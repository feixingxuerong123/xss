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


# --- Phase 160: a no-op policy is only a bypass if a sink can consume it ---
#
# neg-dom-08 is the safe twin of pos-dom-08: the very same identity policy,
# but the value lands in textContent.  The layer reported a high-severity
# bypass anyway, and the benchmark never saw it -- its scorer only counts
# the finding types a case declares.  A no-op policy with no HTML sink is
# not an XSS.

_TT_PAGE = """<div id="out"></div>
<script>
var POL = trustedTypes.createPolicy('probePolicy',
          { createHTML: function(s){ return s; } });
function render(){
  var q = new URLSearchParams(location.hash.split('?')[1] || '').get('q');
  var val = POL ? POL.createHTML(q) : q;
  document.getElementById('out').%s = val;
}
render();
</script>"""


def test_identity_policy_written_to_textcontent_is_not_a_bypass():
    res = analyze_page(_TT_PAGE % "textContent", None)
    types = [v.get("type") for v in res.get("violations")]
    assert "tt_policy_bypass" not in types, (
        "textContent is not a sink -- an identity policy nowhere near an "
        f"HTML sink is not a bypass: {types}")


def test_identity_policy_written_to_innerhtml_is_still_a_bypass():
    """Guard against over-fixing: the vulnerable twin must still fire."""
    res = analyze_page(_TT_PAGE % "innerHTML", None)
    types = [v.get("type") for v in res.get("violations")]
    assert "tt_policy_bypass" in types, (
        f"identity policy feeding innerHTML is a real bypass: {types}")


def test_uninspectable_bundle_keeps_the_bypass():
    """The sink may live in a bundle we cannot see -- never skip those."""
    html = (_TT_PAGE % "textContent") + '<script src="/app.js"></script>'
    res = analyze_page(html, None)
    types = [v.get("type") for v in res.get("violations")]
    assert "tt_policy_bypass" in types, (
        "an external script may hold the sink -- prove-dead, not "
        f"prove-alive: {types}")
