"""Phase 154: page_can_run_sink -- skip provably dead browser sessions.

A browser pass costs ~5.6s (9 probes x ~700ms settle).  41 of the 57 slow
benchmark cases had client-side JS but no code path that could reach an
XSS sink, so they paid it for nothing (~25% of the run's wall clock).

The contract that matters most is the CONSERVATIVE direction: the filter
may only SKIP a browser session, never silently drop coverage.  An
external script must always pass, because real SPAs keep their sinks in a
bundle we cannot see inside (Juice Shop's Angular bundle).
"""
from __future__ import annotations

import pytest

from xssentinel.core.dom_engine import page_can_run_sink


def test_plain_html_without_script_is_skipped():
    assert page_can_run_sink(
        "<html><body><div>hello</div></body></html>") is False


def test_inline_script_without_any_sink_is_skipped():
    # the classic false-positive for "has client JS": data assignment only.
    html = ("<html><body><script>var user = 'bob'; "
            "var cfg = {a: 1};</script></body></html>")
    assert page_can_run_sink(html) is False


def test_inline_sink_lets_the_browser_run():
    for body in ("el.innerHTML = x;", "document.write(x);",
                 "eval(x);", "setTimeout(x, 1);", "$('#a').html(x);",
                 "img.src = x;", "location = x;",
                 "e.setAttribute('onclick', x);"):
        html = f"<html><body><script>{body}</script></body></html>"
        assert page_can_run_sink(html) is True, body


def test_external_script_always_runs_the_browser():
    """The one rule that protects real SPAs: a bundle we cannot inspect
    may hold every sink the page has, so never skip it."""
    assert page_can_run_sink(
        "<html><head><script src=\"/main.js\"></script></head></html>") \
        is True
    # even with no inline script at all
    assert page_can_run_sink(
        "<html><head><script src='https://cdn/x.js'></script></head>"
        "</html>") is True


def test_empty_or_none_is_skipped():
    assert page_can_run_sink("") is False
    assert page_can_run_sink(None) is False


def test_mixed_page_with_sink_in_second_script():
    html = ("<html><body>"
            "<script>var a = 1;</script>"
            "<script>document.getElementById('x').innerHTML = v;</script>"
            "</body></html>")
    assert page_can_run_sink(html) is True


def test_src_attribute_lookup_is_not_a_script_tag():
    # an <img src=...> must NOT be read as "external script"
    html = "<html><body><img src=\"/a.png\"></body></html>"
    assert page_can_run_sink(html) is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
