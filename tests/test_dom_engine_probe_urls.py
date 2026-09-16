"""Regression lock for the DOM-dynamic source probes.

Background (audit 2026-09-14): ``_probes()`` derived the query separator
from the *original* URL but appended it to a base that had already been
stripped of the query.  For every URL carrying a query string -- i.e.
every URL a real scan visits -- it produced ``http://h/p&__xss__=MK``,
a path with no query at all, so the ``location.search`` and
``location.href`` probes never delivered the marker.  A second gap: the
probe only ever used the literal name ``__xss__``, while real pages read
a specific parameter (``?q=``).

The first test below is pure and always runs; it is the actual lock.
The second drives a real browser against a throwaway server.
"""
from __future__ import annotations

import http.server
import os
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from urllib.parse import unquote, urlsplit  # noqa: E402

from xssentinel.core import dom_engine  # noqa: E402
from xssentinel.core.dom_engine import DynamicDomAnalyzer  # noqa: E402

from tests.conftest import SOCKETPAIR_OK, loopback_healthy  # noqa: E402

_HAS_PW = DynamicDomAnalyzer.available()

# The live browser tests below launch Chromium against a throwaway server.
# On machines with a system HTTP proxy (or an over-eager local security
# agent) those runs intermittently hang inside Playwright's greenlet, and
# pytest-timeout cannot interrupt it.  They are therefore opt-in:
#
#     XSS_DOM_LIVE=1 python -m pytest tests/test_dom_engine_probe_urls.py
#
# The pure tests above need no browser and always run -- they are the real
# regression lock for this bug.
_LIVE = os.environ.get("XSS_DOM_LIVE") == "1"


def _probe_urls(url: str, marker: str = "MK") -> dict:
    """``{source: [urls...]}`` for the goto-style probes."""
    analyzer = DynamicDomAnalyzer.__new__(DynamicDomAnalyzer)
    out: dict = {}
    for probe in analyzer._probes(url, marker):
        source = probe.get("source")
        if source in ("location.search", "location.href"):
            out.setdefault(source, []).append(probe.get("url"))
    return out


# --------------------------------------------------------------------------
# 1. pure: probe URLs must be well formed
# --------------------------------------------------------------------------

def test_search_probe_keeps_query_separator_when_url_has_query():
    """``?q=1`` must not collapse into ``path&__xss__=`` (no query at all)."""
    urls = _probe_urls("http://h/p?q=1")["location.search"]
    assert urls, "no location.search probe emitted"
    generic = [u for u in urls if "__xss__" in u]
    assert generic, f"generic __xss__ probe missing: {urls}"
    for u in generic:
        assert "&__xss__" not in u.split("?")[0], (
            f"query separator lost, probe URL is malformed: {u}")


def test_search_probe_url_is_well_formed_without_query():
    urls = _probe_urls("http://h/p")["location.search"]
    assert any(u == "http://h/p?__xss__=MK" for u in urls), urls


def test_href_probe_keeps_query_separator_when_url_has_query():
    urls = _probe_urls("http://h/p?q=1")["location.href"]
    assert urls
    for u in urls:
        assert "&__xss__" not in u.split("?")[0], f"malformed href probe: {u}"


@pytest.mark.parametrize("url", [
    "http://h/p?q=1",
    "http://h/p?q=1&r=2",
    "http://h/p",
    "http://h/p?q=1#frag",
    "http://h/p#frag",
])
def test_every_search_probe_carries_marker_in_query(url):
    """Every location.search/href probe must put the marker in a real query
    string -- never in the path, which is what the old bug did."""
    for source, urls in _probe_urls(url).items():
        assert urls, f"{source} emitted no probe for {url!r}"
        for u in urls:
            query = urlsplit(u).query
            assert query, f"{source} probe has no query string: {u}"
            assert "MK" in unquote(query), (
                f"{source} probe lost the marker: {u}")


def test_real_parameter_names_are_probed():
    """A page reading ``?q=`` must be reachable -- the generic ``__xss__``
    name alone can never reach it."""
    urls = _probe_urls("http://h/p?q=1&r=2")["location.search"]
    assert any("q=MK" in u for u in urls), urls
    assert any("r=MK" in u for u in urls), urls


def test_param_swap_preserves_sibling_parameters():
    """Other parameters keep their values so the page reaches the same path."""
    swapped = dom_engine._with_param_value("http://h/p?q=1&r=2", "q", "MK")
    assert "q=MK" in swapped, swapped
    assert "r=2" in swapped, swapped


def test_param_swap_adds_missing_parameter():
    swapped = dom_engine._with_param_value("http://h/p", "q", "MK")
    assert swapped.endswith("?q=MK"), swapped


# --------------------------------------------------------------------------
# 2. live: a real browser must confirm DOM XSS through a query parameter
# --------------------------------------------------------------------------

_PAGE_READS_Q = b"""<!doctype html><html><body><div id="o"></div><script>
var u = new URLSearchParams(location.search).get("q");
if (u) { document.getElementById("o").innerHTML = u; }
</script></body></html>"""

_SAFE_PAGE = b"""<!doctype html><html><body><div id="o"></div><script>
var u = new URLSearchParams(location.search).get("q");
if (u) { document.getElementById("o").textContent = u; }
</script></body></html>"""


def _serve(pages: dict, port: int):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path.split("?")[0], b"<html>404</html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class TS(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = TS(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _live_analyze(pages: dict, path: str, marker: str) -> list:
    srv = _serve(pages, 8973)
    try:
        return DynamicDomAnalyzer().analyze(
            f"http://127.0.0.1:8973{path}", marker=marker)
    finally:
        srv.shutdown()


@pytest.mark.skipif(not _LIVE, reason="set XSS_DOM_LIVE=1 to run live browser tests")
@pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair degraded")
@pytest.mark.skipif(not _HAS_PW, reason="Playwright not installed")
def test_live_browser_confirms_dom_xss_via_real_query_param():
    """The end-to-end shape the pure tests lock: ``?q=`` reaching innerHTML."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    hits = _live_analyze({"/vuln": _PAGE_READS_Q}, "/vuln?q=1", "LIVEMK1")
    assert hits, "real browser missed a DOM XSS delivered via ?q="
    assert any(h.get("sink") == "Element.innerHTML" for h in hits), hits


@pytest.mark.skipif(not _LIVE, reason="set XSS_DOM_LIVE=1 to run live browser tests")
@pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair degraded")
@pytest.mark.skipif(not _HAS_PW, reason="Playwright not installed")
def test_live_browser_stays_quiet_on_textcontent_sink():
    """Same source, non-executing sink -- must not be reported."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    hits = _live_analyze({"/safe": _SAFE_PAGE}, "/safe?q=1", "LIVEMK2")
    assert hits == [], hits


# --------------------------------------------------------------------------
# 3. Phase 141: SPA hash routing -- the query lives inside the fragment
#
# ``http://h/#/search?q=1`` has an EMPTY ``urlparse().query``; the parameter
# is in ``.fragment`` as ``/search?q=1``.  Every parameter-discovery path in
# the project used to miss these, so hash-routed DOM XSS was invisible.
# Confirmed on OWASP Juice Shop, where both official XSS challenges sit
# behind ``#/`` routes and neither was detected.
# --------------------------------------------------------------------------

def _hash_probe_urls(url: str, marker: str = "MK") -> list:
    analyzer = DynamicDomAnalyzer.__new__(DynamicDomAnalyzer)
    return [p.get("url") for p in analyzer._probes(url, marker)
            if p.get("source") == "location.hash"]


def test_hash_route_query_is_extracted():
    assert dom_engine._hash_route_query("http://h/#/search?q=1") == "q=1"
    assert dom_engine._hash_route_query("http://h/#/search") == ""
    assert dom_engine._hash_route_query("http://h/p?a=1") == ""


def test_hash_param_names():
    assert dom_engine._hash_param_names("http://h/#/search?q=1") == ["q"]
    assert dom_engine._hash_param_names("http://h/p?a=1") == []
    assert dom_engine._hash_param_names("http://h/#/a?x=1&y=2&x=3") == ["x", "y"]


def test_hash_param_swap_keeps_route():
    """The route must survive the swap -- otherwise the SPA renders a
    different view (usually its 404) and the sink is never reached, which
    makes the probe silently prove nothing."""
    out = dom_engine._with_hash_param_value("http://h/#/search?q=1", "q", "MK")
    assert out == "http://h/#/search?q=MK", out


def test_hash_param_swap_preserves_siblings_and_outer_query():
    out = dom_engine._with_hash_param_value("http://h/p?a=1#/x?q=1&r=2",
                                            "q", "MK")
    assert out == "http://h/p?a=1#/x?q=MK&r=2", out


def test_hash_route_parameter_is_probed():
    """A hash-routed parameter must yield a probe carrying the marker into
    the fragment, with the route intact."""
    urls = _hash_probe_urls("http://h/#/search?q=1")
    assert any(u == "http://h/#/search?q=MK" for u in urls), urls


def test_plain_query_url_gains_no_fragment_probe():
    """Regression guard: ordinary query URLs must not accumulate fragment
    junk (the existing probes already cover them)."""
    urls = _hash_probe_urls("http://h/p?q=1")
    assert not any("#/search" in u for u in urls), urls


_HASH_PAGE = b"""<!doctype html><html><body><div id="o"></div><script>
function render() {
  var qs = (location.hash.split("?")[1] || "");
  var m = qs.match(/(?:^|&)q=([^&]*)/);
  if (m) { document.getElementById("o").innerHTML = decodeURIComponent(m[1]); }
}
window.addEventListener("hashchange", render);
render();
</script></body></html>"""


@pytest.mark.skipif(not _LIVE, reason="set XSS_DOM_LIVE=1 to run live browser tests")
@pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair degraded")
@pytest.mark.skipif(not _HAS_PW, reason="Playwright not installed")
def test_live_browser_confirms_dom_xss_via_hash_route():
    """The end-to-end shape the pure tests lock: ``#/route?q=`` -> innerHTML."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    hits = _live_analyze({"/app": _HASH_PAGE}, "/app#/search?q=1", "HASHMK1")
    assert hits, "real browser missed a DOM XSS delivered via #/route?q="
    assert any(h.get("sink") == "Element.innerHTML" for h in hits), hits
