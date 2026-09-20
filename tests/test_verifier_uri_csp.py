"""Phase 91: CSP gate and URI-sink ownership in the verifier.

Two benchmark-derived defects, both of which made a *safe* case score as
exploitable:

1. ``_structural_confirm``'s css_context branch ignored CSP while every
   other branch honoured it, so
   ``<svg><style><iframe src=javascript:alert(TOK)></style></svg>`` was
   confirmed even under ``script-src 'self'`` (neg-csp-01 / neg-csp-03 in
   the async matrix).  A javascript: sink reached through CSS is still
   script execution.

2. The url_javascript fallback rejected only *entity-encoded* breakouts.
   UTF-7-style transforms carry no entity at all, so
   ``value='+ADw-iframe src=javascript:...'`` slipped through: the
   ``src=`` in it is text belonging to ``value``.  The guard now asks
   which attribute's value actually contains the sink and requires it to
   be a URI-carrying attribute.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import (  # noqa: E402
    _value_owner_attr,
    verify_semantic,
)

TOK = "xssv_c17f0a2e"

CSP_STRICT = {"Content-Security-Policy": "script-src 'self'; object-src 'none'"}
CSP_NONE = {"Content-Security-Policy": "default-src 'none'; script-src 'none'"}
CSP_NONCE = {"Content-Security-Policy": "script-src 'nonce-k8Fj3x9Qm2Rw7Yp4'"}


def _conf(body: str, headers: dict | None = None) -> bool:
    return verify_semantic(body, TOK, headers)["confirmed"]


# --------------------------------------------------------------------------
# _value_owner_attr -- which attribute owns the text at this offset
# --------------------------------------------------------------------------

def test_owner_none_between_attributes() -> None:
    tag = "<svg/onload=alert(1)>"
    assert _value_owner_attr(tag, tag.find("onload")) is None


def test_owner_quoted_value_keeps_ownership() -> None:
    tag = "<input type='text' value='&#x27; src=javascript:x'>"
    assert _value_owner_attr(tag, tag.find("src=")) == "value"


def test_owner_unquoted_value_keeps_ownership() -> None:
    tag = "<img src=x/onerror=alert(1)>"
    assert _value_owner_attr(tag, tag.find("onerror")) == "src"


def test_owner_closed_value_releases_ownership() -> None:
    tag = '<a href="#" onmouseover=alert(1)>'
    assert _value_owner_attr(tag, tag.find("onmouseover")) is None


def test_owner_name_is_lowercased() -> None:
    tag = '<A HREF="javascript:alert(1)">x</A>'
    assert _value_owner_attr(tag, tag.find("javascript") + 2) == "href"


# --------------------------------------------------------------------------
# 1. CSP must gate the css_context branch
# --------------------------------------------------------------------------

def _style_payload() -> str:
    return ("<div><svg><style><iframe src=javascript:alert('" + TOK
            + "')></style></svg></div>")


def test_css_sink_blocked_by_strict_csp() -> None:
    assert _conf(_style_payload(), CSP_STRICT) is False


def test_css_sink_blocked_by_nonce_csp() -> None:
    assert _conf(_style_payload(), CSP_NONCE) is False


def test_css_sink_blocked_by_default_src_none() -> None:
    assert _conf(_style_payload(), CSP_NONE) is False


def test_css_sink_still_confirms_without_csp() -> None:
    """mXSS via <svg><style> is real -- only CSP makes it safe."""
    assert _conf(_style_payload()) is True


def test_style_attr_sink_blocked_by_csp() -> None:
    body = ("<div style=\"background:url(javascript:alert('" + TOK + "'))\">"
            "x</div>")
    assert _conf(body, CSP_STRICT) is False


def test_style_attr_expression_not_gated_by_script_src() -> None:
    """expression() is CSS, not script: script-src must not mask it."""
    body = "<div style=\"x:expression(alert('" + TOK + "'))\">x</div>"
    assert _conf(body, CSP_STRICT) is True


# --------------------------------------------------------------------------
# 2. javascript: sinks must belong to a URI-carrying attribute
# --------------------------------------------------------------------------

def test_utf7_style_sink_inside_value_is_inert() -> None:
    body = ("<input type='text' value='+ADw-iframe src=javascript:alert+ADs-"
            "+ACY-" + TOK + "+ACY-+AD0-+AD4-'>")
    assert _conf(body) is False


def test_entity_escaped_sink_inside_value_is_inert() -> None:
    body = ("<input value='&lt;iframe src=javascript:alert(&#x27;" + TOK
            + "&#x27;)&gt;'>")
    assert _conf(body) is False


def test_real_href_javascript_uri_confirms() -> None:
    body = '<a href="javascript:alert(\'' + TOK + '\')">x</a>'
    assert _conf(body) is True


def test_real_unquoted_href_javascript_uri_confirms() -> None:
    body = "<a href=javascript:alert('" + TOK + "')>x</a>"
    assert _conf(body) is True


def test_real_meta_refresh_is_not_a_sink() -> None:
    """Phase 168: ``javascript:`` in a meta refresh does not execute.

    Measured in Chromium over a real HTTP origin (``probe_meta_refresh_scheme.py``),
    with the controls that make the negative meaningful: an inline ``<script>``
    and an ``iframe.src=javascript:`` both run in the same session (so the
    harness sees execution and sees this scheme), and
    ``meta refresh -> about:blank`` does navigate (so the refresh does follow a
    non-http scheme).  Only ``javascript:`` is refused.

    The assertion here used to be the opposite, and it held only while
    confirmation was text-position based rather than element-aware.
    """
    body = ('<meta http-equiv="refresh" content="0;url=javascript:alert(\''
            + TOK + '\')">')
    assert _conf(body) is False


def test_ampersand_after_scheme_does_not_mask_real_uri() -> None:
    """&amp; after the scheme must not be read as an escaped boundary."""
    body = '<a href="javascript:alert(\'' + TOK + '&amp;b\')">x</a>'
    assert _conf(body) is True


def test_javascript_text_in_body_is_not_a_sink() -> None:
    body = "<div>see javascript:alert('" + TOK + "') docs</div>"
    assert _conf(body) is False


# ---------------------------------------------------------------------------
# Phase 98: a nonce/hash source makes 'unsafe-inline' inert (CSP Level 2+)
# ---------------------------------------------------------------------------
#
# Pentest-shape finding: modern CSP headers carry BOTH a nonce (current
# browsers) and 'unsafe-inline' (legacy-UA fallback).  Per spec the
# browser IGNORES 'unsafe-inline' when a nonce/hash source is present, so
# a bare inline <script> does NOT execute.  The pre-Phase-98 rule
# ("'unsafe-inline' present -> inline works") turned every such target
# into a high/high false positive whose PoC never fires.
#
# Verified on a live shape: before the fix the confirming payload was a
# bare <script>; after it the engine escalates to the Phase 36 nonce-leak
# exploit (script carrying the page's real nonce) -- i.e. the false
# positive became a genuine finding.

_NONCE = "r4Nd0mV4lu3AbCdEf12"   # >=8 chars: the extractor's minimum
_CSP_NONCE_UI = ("default-src 'self'; script-src 'strict-dynamic' "
                 f"'nonce-{_NONCE}' 'unsafe-inline'")
_CSP_UI_ONLY = "script-src 'self' 'unsafe-inline'"
_CSP_NONCE_ONLY = f"script-src 'self' 'nonce-{_NONCE}'"


def test_unsafe_inline_overridden_matrix() -> None:
    from xssentinel.core import csp as csp_mod
    assert csp_mod.unsafe_inline_overridden(_CSP_NONCE_UI) is True
    assert csp_mod.unsafe_inline_overridden(_CSP_UI_ONLY) is False
    assert csp_mod.unsafe_inline_overridden(
        "script-src 'self' 'sha256-abc12345678' 'unsafe-inline'") is True
    assert csp_mod.unsafe_inline_overridden("") is False
    # strict-dynamic alone does NOT override 'unsafe-inline'
    assert csp_mod.unsafe_inline_overridden(
        "script-src 'strict-dynamic' 'unsafe-inline'") is False


def test_csp_blocks_inline_when_nonce_overrides_unsafe_inline() -> None:
    from xssentinel.core.verifier import _csp_blocks_inline as _blocks
    h = lambda c: {"Content-Security-Policy": c}
    assert _blocks(h(_CSP_NONCE_UI)) is True        # nonce wins over ui
    assert _blocks(h(_CSP_UI_ONLY)) is False        # ui really works
    assert _blocks(h(_CSP_NONCE_ONLY)) is True      # inline needs the nonce


def test_bare_inline_script_not_confirmed_under_nonce_csp() -> None:
    body = "<script>alert('" + TOK + "')</script>"
    v = verify_semantic(body, TOK,
                        {"Content-Security-Policy": _CSP_NONCE_UI})
    assert v["confirmed"] is False, (
        "bare inline script must not be confirmed under a nonce CSP "
        "(the browser ignores 'unsafe-inline')")


def test_inline_script_still_confirmed_under_unsafe_inline_only_csp() -> None:
    """No false-negative: without a nonce, 'unsafe-inline' really works."""
    body = "<script>alert('" + TOK + "')</script>"
    v = verify_semantic(body, TOK,
                        {"Content-Security-Policy": _CSP_UI_ONLY})
    assert v["confirmed"] is True


def test_nonce_leak_exploit_survives_the_tighter_gate() -> None:
    """Phase 36 must not be collateral damage: a script carrying a nonce
    the policy itself declares is allowed to execute."""
    body = (f'<script nonce="{_NONCE}">alert(\'{TOK}\')</script>'
            f'<div>leak</div>')
    v = verify_semantic(body, TOK,
                        {"Content-Security-Policy": _CSP_NONCE_UI})
    assert v["confirmed"] is True, (
        "script with a policy-declared nonce must still confirm "
        "(nonce-leak exploitation path)")
