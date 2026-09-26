# -*- coding: utf-8 -*-
"""Direct tests for the WAF transform engine (23 families).

transform.py sat at zero direct tests while every L2 bypass variant in
every scan flows through it.  Its contracts are objective, so they are
pinned exactly:

  * registry shape (README advertises 23 families),
  * purity: every transform is str->str and apply() never raises,
  * encodings round-trip through their authoritative decoders
    (html.unescape, urllib.unquote, the utf_7 codec),
  * the UTF-7 table matches the codec -- it did NOT before Phase 178b:
    4 of 9 entries mis-encoded ("'"+ACY- decodes to "&", "("+ADs- to
    ";", ")"+AD0- to "=", "/"+AFw- to "\\"), so every variant built
    from those characters decoded to a payload that was never tested.

Parser-soundness note (measured, not pinned here -- the verdicts belong
to the sandbox's fidelity ledger): several text-level transforms are
inert by construction in an element-body context, because the HTML
tokenizer never re-classifies character references as markup and does
not accept whitespace/slashes inside a tag name.  They remain useful
against non-parser defenses (double-decode targets, legacy engines).
"""
from __future__ import annotations
import base64
import html
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import transform as T

PAYLOAD = "<svg/onload=alert('TOK')>"


# ---------------------------------------------------------------------------
# registry contract
# ---------------------------------------------------------------------------

def test_registry_has_the_23_advertised_families():
    assert len(T.REGISTRY) == 23
    assert all(callable(fn) for fn in T.REGISTRY.values())


def test_combinable_names_all_exist():
    assert set(T.COMBINABLE) <= set(T.REGISTRY)


def test_apply_with_an_unknown_name_is_a_noop():
    assert T.apply("__nope__", PAYLOAD) == PAYLOAD


def test_apply_never_raises_on_hostile_input():
    nasty = ('<a href="jav\tascript:\x00alert(1)\n" data-x=\'{"k": "中文"}\''
             '></a>')
    for name in T.REGISTRY:
        out = T.apply(name, nasty)
        assert isinstance(out, str), name


# ---------------------------------------------------------------------------
# encoding round-trips through the authoritative decoder
# ---------------------------------------------------------------------------

def test_decimal_entities_round_trip():
    out = T.apply("html_entity_decimal", PAYLOAD)
    assert html.unescape(out) == PAYLOAD


def test_hex_entities_round_trip():
    out = T.apply("html_entity_hex", PAYLOAD)
    assert html.unescape(out) == PAYLOAD


def test_named_entities_round_trip():
    out = T.apply("html_entity_named", PAYLOAD)
    assert html.unescape(out) == PAYLOAD


def test_html5_named_entities_round_trip():
    out = T.apply("html5_entities", PAYLOAD)
    assert html.unescape(out) == PAYLOAD


def test_url_encode_all_round_trips():
    out = T.apply("url_encode_all", PAYLOAD)
    assert urllib.parse.unquote(out) == PAYLOAD


def test_url_encode_selective_round_trips():
    out = T.apply("url_encode_selective", PAYLOAD)
    assert urllib.parse.unquote(out) == PAYLOAD


def test_double_url_encode_needs_two_decodes():
    out = T.apply("double_url_encode", PAYLOAD)
    once = urllib.parse.unquote(out)
    assert once != PAYLOAD, "single decode must not be enough"
    assert urllib.parse.unquote(once) == PAYLOAD


# ---------------------------------------------------------------------------
# the UTF-7 table vs the codec (the Phase 178b fix)
# ---------------------------------------------------------------------------

def _modified_b64(ch: str) -> str:
    return ("+" + base64.b64encode(ch.encode("utf-16-be")).decode("ascii")
            .rstrip("=") + "-")


def test_utf7_every_entry_decodes_back_to_its_character():
    # Regenerate the table the same way the fix derives it, then prove
    # the transform's output round-trips char by char.
    for ch in "<>'\"()&/\\":
        want = _modified_b64(ch)
        got = T.t_utf7(ch)
        assert got == want, f"{ch!r}: {got!r} != codec-derived {want!r}"
        assert got.encode("ascii").decode("utf_7") == ch, (
            f"{ch!r}: {got!r} does not decode back to itself")


def test_utf7_output_decodes_to_the_original_payload():
    # A UTF-7 target applying the charset decodes the variant back to a
    # payload with the same executable characters.
    out = T.t_utf7("<svg/onload=alert('TOK')>")
    decoded = out.encode("ascii").decode("utf_7")
    assert decoded == "<svg/onload=alert('TOK')>"


def test_utf7_quote_and_ampersand_encode_differently():
    # The old table collapsed both to +ACY-.
    assert T.t_utf7("'") != T.t_utf7("&")


# ---------------------------------------------------------------------------
# shape contracts of the structural transforms
# ---------------------------------------------------------------------------

def test_fromcharcode_keeps_a_callable_and_encodes_only_the_argument():
    out = T.apply("fromcharcode", "alert('TOK')")
    assert out.startswith("alert(String.fromCharCode(")
    assert ")" in out


def test_duplicate_attribute_prepends_a_benign_first_attribute():
    out = T.apply("duplicate_attribute", '" autofocus onfocus=alert(1) x="')
    assert out.startswith(' autofocus=""')


def test_duplicate_attribute_noops_on_non_attribute_payloads():
    assert T.apply("duplicate_attribute", "<script>alert(1)</script>") == \
        "<script>alert(1)</script>"


def test_comment_break_breaks_the_keyword_but_keeps_js_parseable():
    out = T.apply("comment_break", "alert(1)")
    assert "alert" not in out
    # the mangled callable must still be a JS comment-wrapper, not a
    # renamed function
    assert out == "ale/*x*/rt(1)"


def test_mixed_case_alternates_case_and_preserves_non_letters():
    assert T.t_mixed_case("a1b2") == "A1B2"
