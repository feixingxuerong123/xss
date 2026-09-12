# -*- coding: utf-8 -*-
"""Phase 119: the strict WAF target must block the CLASS of tag injection.

neg-waf-01 exists to be a target a scanner CANNOT get through.  It was
implemented by enumerating a few blocked patterns, and the async engine
walked through with `<details open ontoggle=alert(...)>` (ontoggle was
not on the list).  The echo was real, the engine's finding was correct,
and my manifest scored it as a false positive -- the FP was mine.

Two things are pinned here:
  * the strict ruleset blocks tag injection generally (any tag, any event
    handler, script URIs, common encodings), not a hand-written list;
  * the naive ruleset still only blocks the plain shapes, so the bypass
    case can still land.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.server import (_WAF_NAIVE_BLOCKS, _WAF_STRICT_PATTERNS,
                              _waf_blocked)

_STRICT = tuple("re:" + p for p in _WAF_STRICT_PATTERNS)


def test_strict_blocks_any_tag_and_handler():
    for value in ("<details open ontoggle=alert(1)>",
                  "<svg/onload=alert(1)>",
                  "<img src=x onerror=alert(1)>",
                  "<ScRiPt>x</ScRiPt>",
                  "%3Cscript%3Ealert(1)%3C/script%3E",
                  "'-alert(1)-'",  # no tag: allowed, see below
                  ):
        blocked = _waf_blocked(value, _STRICT)
        if value.startswith("'-alert"):
            assert not blocked, "a quote-only payload is not tag injection"
        else:
            assert blocked, f"strict WAF must block {value!r}"


def test_strict_allows_plain_text():
    assert not _waf_blocked("plain", _STRICT)
    assert not _waf_blocked("hello world", _STRICT)


def test_naive_waf_only_blocks_the_plain_shapes():
    """The vulnerable twin must stay bypassable."""
    assert _waf_blocked("<script>alert(1)</script>", _WAF_NAIVE_BLOCKS)
    assert _waf_blocked("<svg onload=alert(1)>", _WAF_NAIVE_BLOCKS)
    for escalation in ("<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>",
                       "<details open ontoggle=alert(1)>"):
        assert not _waf_blocked(escalation, _WAF_NAIVE_BLOCKS), (
            f"{escalation!r} must slip past the naive ruleset")


def test_helpers_are_defined_once():
    """The duplicate-definition bug that caused the FP: Python takes the
    LAST definition, so a re-inserted block silently shadowed the fixed
    one."""
    import benchmark.server as srv
    src = open(srv.__file__, "r", encoding="utf-8").read()
    for name in ("_waf_blocked", "_waf_respond", "m_waf_naive", "m_waf_strict"):
        assert src.count(f"def {name}(") == 1, (
            f"{name} is defined {src.count(f'def {name}(')} times -- a "
            "duplicated block will shadow the fixed definition")
