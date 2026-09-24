# -*- coding: utf-8 -*-
"""Phase 176l: an imported host is not an authorized host.

`--har` / `--openapi` turn one file into one target per captured operation.  A
HAR saved from a browser contains the site's CDN, analytics and SSO endpoints
next to the application, and until `xssentinel/core/scoping.py` the only test
applied to those was "does it parse as a URL" -- so

    xssentinel -u https://app.example.com --har out.har

sent payload-bearing probes, carrying the scan's session headers, to hosts the
operator never named.  In a client engagement that is not a false positive, it
is traffic to a third party.

These tests cover the host algebra (exact, `.domain`, userinfo/port noise) and
one CLI integration: a two-host HAR where only the operator's host may be
probed, and `--allow-host` as the deliberate way to widen it.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.scoping import (baseline_hosts, distinct_hosts,  # noqa: E402
                                     host_of, partition_by_scope)


# --- host algebra -----------------------------------------------------------

@pytest.mark.parametrize("url,want", [
    ("http://App.Example.com/x?q=1", "app.example.com"),
    ("https://app.example.com:8443/x", "app.example.com"),
    ("https://user:pass@app.example.com/x", "app.example.com"),
    ("http://[::1]:9000/x", "::1"),
    ("not a url", ""),
    ("", ""),
])
def test_host_of_extracts_only_the_host(url, want):
    # authorization is about the host: userinfo, port and case must not create a
    # way to slip a probe past the check
    assert host_of(url) == want


def test_baseline_keeps_operator_hosts_and_allow_list():
    pats = baseline_hosts(["https://app.example.com/x", "http://127.0.0.1:8080/y"],
                          [".cdn.example.com"])
    assert pats == ["app.example.com", "127.0.0.1", ".cdn.example.com"]
    # dedup, and `-u app.example.com` (no scheme) still counts
    assert baseline_hosts(["app.example.com", "https://app.example.com"]) == \
        ["app.example.com"]


def test_allow_host_accepts_a_url_and_keeps_a_leading_dot():
    """Operators type what they see in the address bar. A pattern stored as
    `https://cdn.example.com/analytics.js` would match no host and the refusal
    would then look like a bug in the gate rather than a typo in the flag."""
    assert baseline_hosts([], ["https://cdn.example.com/analytics.js"]) == \
        ["cdn.example.com"]
    assert baseline_hosts([], [".example.com", "*.example.org"]) == \
        [".example.com", "*.example.org"], "glob patterns must survive normalization"
    keep, dropped = partition_by_scope(
        [{"url": "https://cdn.example.com/a.js"}, {"url": "https://other.test/b"}],
        baseline_hosts([], ["https://cdn.example.com/analytics.js"]))
    assert [t["url"] for t in keep] == ["https://cdn.example.com/a.js"]
    assert len(dropped) == 1


def test_partition_is_host_exact_not_suffix_guessing():
    targets = [{"url": "https://app.example.com/a", "method": "GET"},
               {"url": "https://cdn.example.com/b.js", "method": "GET"},
               {"url": "https://api.example.com/p", "method": "POST"}]
    keep, dropped = partition_by_scope(targets, ["app.example.com"])
    assert [t["url"] for t in keep] == ["https://app.example.com/a"]
    assert sorted(d["host"] for d in dropped) == \
        ["api.example.com", "cdn.example.com"], (
        "api.example.com is a different asset from app.example.com: host-exact "
        "matching is the point, not a convenience suffix rule")
    # the dropped entries keep their URL so the report can name them
    assert all(d.get("url") for d in dropped)


def test_leading_dot_is_the_way_to_say_whole_domain():
    targets = [{"url": "https://a.example.com/x"}, {"url": "https://evil.co/y"}]
    keep, dropped = partition_by_scope(targets, [".example.com"])
    assert [t["url"] for t in keep] == ["https://a.example.com/x"]
    assert len(dropped) == 1
    # and the bare host does NOT match its subdomains
    keep2, dropped2 = partition_by_scope(targets, ["example.com"])
    assert keep2 == [] and len(dropped2) == 2


def test_empty_patterns_allow_all_but_still_report_the_hosts():
    """An import-only run has no baseline; the file defines scope, and the host
    set is printed before anything is probed."""
    targets = [{"url": "https://x.test/a"}, {"url": "https://y.test/b"}]
    keep, dropped = partition_by_scope(targets, [])
    assert len(keep) == 2 and dropped == []
    assert distinct_hosts(targets) == ["x.test", "y.test"]


# --- CLI integration -------------------------------------------------------

def _har(entries):
    return {"log": {"version": "1.2", "entries": [
        {"request": {"method": m, "url": u, "headers": [], "cookies": [],
                     "postData": None},
         "response": {"status": 200, "statusText": "ok"}}
        for m, u in entries]}}


def _write_har(tmp_path, entries):
    p = tmp_path / "out.har"
    p.write_text(json.dumps(_har(entries)), encoding="utf-8")
    return str(p)


def _fake_main(tmp_path, capsys, extra_args, scanned):
    """Run the real CLI with `_run_scan` mocked, and return (rc, scanned urls)."""
    from xssentinel import __main__ as cli

    def fake_scan(args, url, requester, oob, progress, checkpoint,
                  auth_state=None):
        scanned.append(url)
        ms = MagicMock()
        ms.findings = []
        ms.waf_name = None
        ms.req.attempted_requests = 3
        ms.req.failed_requests = 0
        return ms

    argv = ["-u", "https://app.example.com/", "-f", "json",
            "-o", str(tmp_path / "r.json"), "--progress", "none",
            "--log-level", "error"] + extra_args
    with patch.object(cli, "_run_scan", side_effect=fake_scan), \
         patch.object(cli, "_write_report",
                      side_effect=lambda *a, **k: "r.json"):
        return cli.main(argv)


def _har_args(tmp_path):
    return ["--har", _write_har(tmp_path, [
        ("GET", "https://app.example.com/page?q=1"),
        ("GET", "https://cdn.example.com/analytics.js"),
        ("POST", "https://sso.vendor.test/login")])]


def test_har_hosts_outside_the_named_target_are_not_probed(tmp_path, capsys):
    scanned: list[str] = []
    rc = _fake_main(tmp_path, capsys, _har_args(tmp_path), scanned)
    cap = capsys.readouterr()
    hosts = {u.split("/")[2] for u in scanned}
    assert hosts == {"app.example.com"}, (
        f"probed hosts {hosts}: the HAR also named a CDN and a third-party SSO")
    assert "OUTSIDE the scan scope" in cap.err
    assert "sso.vendor.test" in cap.err and "cdn.example.com" in cap.err, \
        "the refused hosts must be named, not just counted"
    assert rc == 0, cap.err


def test_allow_host_admits_a_named_third_party(tmp_path, capsys):
    scanned: list[str] = []
    _fake_main(tmp_path, capsys,
               _har_args(tmp_path) + ["--allow-host", ".example.com"], scanned)
    hosts = {u.split("/")[2] for u in scanned}
    assert hosts == {"app.example.com", "cdn.example.com"}, \
        "the wildcard entry means the whole domain, and nothing more"
    assert "sso.vendor.test" not in "".join(scanned)


def test_allow_any_host_probes_them_all_with_a_warning(tmp_path, capsys):
    scanned: list[str] = []
    _fake_main(tmp_path, capsys, _har_args(tmp_path) + ["--allow-any-host"],
               scanned)
    cap = capsys.readouterr()
    assert len({u.split("/")[2] for u in scanned}) == 3
    assert "--allow-any-host" in cap.err


def test_dropped_import_is_recorded_in_the_report(tmp_path, capsys):
    """The count has to survive into the artifact: a report that says
    `0 findings` after refusing to probe two hosts is only honest if it also
    says which hosts it did not touch."""
    from xssentinel.core import report as reportmod
    meta = {"scope_dropped": [{"url": "https://sso.vendor.test/login",
                               "host": "sso.vendor.test", "method": "POST"}],
            "scope_dropped_count": 1,
            "requests_attempted": 5, "requests_failed": 0}
    out = json.loads(reportmod.build_json([], "https://app.example.com/", meta))
    assert out["scope_dropped_count"] == 1
    assert out["scope_dropped"][0]["host"] == "sso.vendor.test"


def test_every_import_out_of_scope_is_a_hard_error(tmp_path, capsys):
    """Not a silent zero-target scan: the operator has to be told to name them."""
    scanned: list[str] = []
    argv = ["--har", _write_har(tmp_path, [("GET", "https://x.test/a")])]
    from xssentinel import __main__ as cli

    def fake_scan(args, url, requester, oob, progress, checkpoint,
                  auth_state=None):
        scanned.append(url)
        ms = MagicMock()
        ms.findings = []
        ms.waf_name = None
        ms.req.attempted_requests = 1
        ms.req.failed_requests = 0
        return ms

    # `-u` names a host the import never mentions -> nothing survives, and the
    # run must say so rather than exit quietly having probed zero endpoints.
    with patch.object(cli, "_run_scan", side_effect=fake_scan), \
         patch.object(cli, "_write_report", side_effect=lambda *a, **k: "r.json"):
        rc = cli.main(["-u", "https://app.example.com/", "-f", "json",
                       "-o", str(tmp_path / "r.json"), "--progress", "none",
                       "--log-level", "error"] + argv)
    assert rc == 2, f"an all-out-of-scope import must be an error, got {rc}"
    assert scanned == []
    assert "out of scope" in capsys.readouterr().err
