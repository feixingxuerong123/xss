# -*- coding: utf-8 -*-
"""A captured credential must not survive into a deliverable or a stored row.

`attach_replay_ctx` copies the request's OTHER form fields into
`finding["csrf_fields"]` so PoCs can replay CSRF-protected endpoints.  That was
name-blind: point the scanner at a login form and the submitted password landed
verbatim in `csrf_fields`, in the curl PoC, in the HTML report a client forwards
around, and in the SQLite job row that outlives the scan.

Both write paths now mask credential-shaped VALUES and keep the KEYS, so the
redaction stays auditable and the operator can see a field was dropped.  The
companion rule is what keeps this from being a regression in disguise: a CSRF
nonce must still ride along in full, or every authenticated PoC stops replaying
and we have traded a leak for a broken tool.

Run:  pytest tests/test_credential_leak.py
"""
from __future__ import annotations

import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.findings import (Finding, REDACTED,  # noqa: E402
                                      _is_credential_field, attach_replay_ctx)
from xssentinel.core.poc import build_poc  # noqa: E402

SECRET = "Sup3rS3cr3t!hunter2"


def _ctx(url, method, data):
    tl = types.SimpleNamespace()
    tl.reqctx = {"url": url, "method": method, "data": data}
    return tl


def _posting(url="http://t/login", param="username"):
    return Finding(url=url, method="POST", param=param, type="reflected",
                   context="html_attr", payload="<img src=x onerror=1>",
                   severity="high", confidence="high", detail="d")


# --- the field-name classifier ------------------------------------------------

@pytest.mark.parametrize("name", [
    "password", "Password", "user_password", "password_confirmation",
    "passwd", "pwd", "pin", "otp", "cvv", "secret", "client_secret",
    "private_key", "authorization", "cookie", "pass", "cc_number",
])
def test_credential_shaped_names_are_caught(name):
    assert _is_credential_field(name), f"{name} would have been stored verbatim"


@pytest.mark.parametrize("name", [
    # substring traps: these contain a short credential name but are not one
    "compass", "typing", "mapping", "passenger", "otp_required_note",
    # the thing replay actually needs
    "csrf_token", "authenticity_token", "_token", "return_to", "remember",
])
def test_ordinary_and_csrf_names_are_not_caught(name):
    assert not _is_credential_field(name), f"{name} must keep its value"


# --- the finding / PoC path ---------------------------------------------------

def test_captured_password_never_reaches_the_finding_or_the_curl():
    f = _posting()
    attach_replay_ctx(f, _ctx("http://t/login", "POST", {
        "username": "alice", "password": SECRET,
        "csrf_token": "abc123", "remember": "1"}))
    d = f.data
    assert d["csrf_fields"]["password"] == REDACTED
    assert SECRET not in repr(d), "the secret is still sitting in the finding"
    poc = build_poc(d)
    joined = " ".join(str(v) for v in poc.values())
    assert SECRET not in joined, "the PoC shipped the password"
    assert REDACTED in joined or "password" in joined


def test_csrf_token_still_rides_along_in_full():
    """The reverse assertion: masking everything would quietly break replays."""
    f = _posting()
    attach_replay_ctx(f, _ctx("http://t/login", "POST", {
        "username": "alice", "password": SECRET, "csrf_token": "abc123"}))
    assert f.data["csrf_fields"]["csrf_token"] == "abc123"
    assert "csrf_token=abc123" in build_poc(f.data)["curl"], (
        "a PoC that drops the CSRF token 403s and is worth nothing to a client")


def test_the_injected_parameter_is_still_the_injected_parameter():
    """`param` itself is excluded from the copy -- masking must not change that."""
    f = _posting(param="username")
    attach_replay_ctx(f, _ctx("http://t/login", "POST", {
        "username": "alice", "password": SECRET}))
    assert "username" not in f.data["csrf_fields"]
    assert f.data["csrf_fields"]["password"] == REDACTED


def test_a_non_post_finding_attaches_nothing():
    f = Finding(url="http://t/x", method="GET", param="q", type="reflected",
                context="html_element", payload="p", severity="high",
                confidence="high", detail="d")
    attach_replay_ctx(f, _ctx("http://t/x", "GET", {"password": SECRET}))
    assert "csrf_fields" not in f.data


# --- the stored-job path ------------------------------------------------------

def test_stored_rows_keep_shape_but_not_secrets(tmp_path):
    from xssentinel.api.persistence import SqliteJobStore
    store = SqliteJobStore(str(tmp_path / "jobs.db"))
    try:
        store.save({"scan_id": "s1", "target_url": "http://t/login",
                    "method": "POST",
                    "params": {"q": "x"},
                    "data": {"username": "alice", "password": SECRET},
                    "options": {"headers": {"Authorization": "Bearer " + SECRET,
                                            "X-Trace": "keep-me"},
                                "timeout": 15}})
        row = store.load("s1")
        blob = repr(row)
        assert SECRET not in blob, "a stored row outlives the scan and gets shared"
        assert row["data"]["password"] == REDACTED
        assert row["options"]["headers"]["Authorization"] == REDACTED
        # shape preserved: the operator can still see what the request carried
        assert "password" in row["data"]
        assert row["options"]["headers"]["X-Trace"] == "keep-me"
        assert row["options"]["timeout"] == 15
    finally:
        store.close()
