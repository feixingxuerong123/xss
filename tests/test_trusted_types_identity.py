# -*- coding: utf-8 -*-
"""Phase 116b: Trusted Types identity bypass regression.

_IDENTITY_ARROW_RE matched ``(s) => s`` with a trailing ``\\b``; in
``(s) => s.replace(/</g, '&lt;')`` the identifier is also followed by a
word boundary, so a policy that clearly sanitised was reported as an
identity bypass -- found by the benchmark's safe twin neg-tt-01.

Only a policy that hands the value back UNCHANGED is a bypass.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.trusted_types import analyze_page

_TPL = "<script>trustedTypes.createPolicy('p', {createHTML: %s});</script>"


def _is_identity(expr):
    res = analyze_page(_TPL % expr, None)
    return any(p["is_identity"] for p in (res.get("policies") or []))


def test_passthrough_forms_are_identity():
    for expr in ("(s) => s", "s => s", "function(s){ return s; }"):
        assert _is_identity(expr), f"passthrough {expr!r} must be a bypass"


def test_sanitising_forms_are_not_identity():
    for expr in ("(s) => s.replace(/</g, '&lt;')",
                 "(s) => DOMPurify.sanitize(s)",
                 "(s) => escapeHtml(s)"):
        assert not _is_identity(expr), (
            f"{expr!r} sanitises -- it is not an identity bypass")


def test_only_the_passthrough_policy_reports_bypass():
    res = analyze_page(_TPL % "(s) => s.replace(/</g, '&lt;')", None)
    types = [v.get("type") for v in res.get("violations")]
    assert "tt_policy_bypass" not in types, (
        f"a sanitising policy must not be reported as a bypass: {types}")
