# -*- coding: utf-8 -*-
"""Phase 139: reproducible PoCs must be DELIVERABLE, not just in-memory.

`poc.build_poc()` has produced curl/URL/HTML PoCs for ages (and Phase 135
even runs them for verification), but nothing ever wrote them to disk --
`replay.write_poc_file()` existed with **zero callers**.  These tests lock
the missing half: `--poc-dir` artifacts.

The security-relevant assertion is the shell one: a PoC whose curl command
is broken by the very payload it carries (an unescaped quote) is worse than
no PoC -- it either fails to reproduce or, worse, executes something else.
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import poc as pocmod
from xssentinel.core import report as reportmod

# A payload that has broken plenty of generated shell commands: it closes a
# single-quoted argument AND appends another command.
NASTY = "'; touch /tmp/pwned; echo '"


def _finding(param="q", method="GET", ftype="reflected", payload=None):
    d = {"type": ftype, "severity": "high", "param": param,
         "method": method, "url": "http://127.0.0.1:8877/r/echo01?q=up",
         "payload": payload or "<script>alert(1)</script>",
         "poc_payload": payload or "<script>alert(1)</script>",
         "context": "html_element"}
    d["poc"] = pocmod.build_poc(d)
    return {"data": d}


def test_poc_dir_writes_html_curl_and_index(tmp_path):
    out = str(tmp_path / "poc")
    written = reportmod.write_poc_dir([_finding()], "http://t/", {}, out)
    names = sorted(os.path.basename(p) for p in written)
    assert any(n.endswith(".html") for n in names), names
    assert any(n.endswith(".sh") for n in names), names
    assert "INDEX.md" in names, names
    for p in written:
        assert os.path.getsize(p) > 0, p


def test_curl_poc_survives_a_payload_that_closes_the_quote(tmp_path):
    out = str(tmp_path / "poc")
    f = _finding(payload=NASTY)
    reportmod.write_poc_dir([f], "http://t/", {}, out)
    sh = [p for p in os.listdir(out) if p.endswith(".sh")]
    assert sh, os.listdir(out)
    body = open(os.path.join(out, sh[0]), encoding="utf-8").read()
    line = [l for l in body.splitlines()
            if l.startswith("curl")][0]
    # The payload must not terminate the quoted argument.  It is
    # URL-encoded here (`%27` for the quote), so the check is: the line
    # contains exactly the two wrapping quotes and nothing raw inside.
    assert line.count("'") == 2, (
        f"payload broke out of the shell quoting: {line}")
    assert "%27" in line, f"payload not encoded as expected: {line}"


def test_post_poc_html_auto_submits(tmp_path):
    out = str(tmp_path / "poc")
    f = _finding(method="POST", ftype="stored_xss")
    reportmod.write_poc_dir([f], "http://t/", {}, out)
    htmls = [p for p in os.listdir(out) if p.endswith(".html")]
    assert htmls, os.listdir(out)
    body = open(os.path.join(out, htmls[0]), encoding="utf-8").read()
    assert "<form" in body, body[:200]
    assert "submit()" in body or 'type="submit"' in body, body[:200]


def test_index_counts_findings_without_a_poc(tmp_path):
    """Audit-style findings (a missing header) carry no PoC -- the index
    must say so instead of silently dropping them."""
    out = str(tmp_path / "poc")
    bare = {"data": {"type": "csp_missing_header", "severity": "low"}}
    reportmod.write_poc_dir([_finding(), bare], "http://t/", {}, out)
    idx = open(os.path.join(out, "INDEX.md"), encoding="utf-8").read()
    assert "with PoC: 1" in idx, idx
    assert "without: 1" in idx, idx


def test_poc_dir_flag_is_parsed():
    from xssentinel.__main__ import build_parser
    args = build_parser().parse_args(
        ["-u", "http://t/", "--poc-dir", "out/poc"])
    assert args.poc_dir == "out/poc"


def test_poc_dir_never_writes_without_the_flag():
    """Default behaviour must not litter the filesystem with live attack
    strings."""
    from xssentinel.__main__ import build_parser
    args = build_parser().parse_args(["-u", "http://t/"])
    assert getattr(args, "poc_dir", None) is None
