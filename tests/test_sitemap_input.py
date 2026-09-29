"""Phase 184: --sitemap URL-source import (DalFox parity).

Mostly fetch-injected (no network): the expansion logic -- urlset,
sitemap-index recursion with a dead child, plain-text sitemaps, dedup and
caps -- is driven through the ``fetch`` hook.  One loopback test covers the
real HTTP path end to end.
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.sitemap_import import sitemap_to_urls

URLSET = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://t/s/a?x=1</loc></url>
  <url><loc>http://t/s/b</loc></url>
  <url><loc>http://t/s/a?x=1</loc></url>
  <url><loc>http://t/s/c</loc></url>
</urlset>"""

INDEX = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://t/smap/child1.xml</loc></sitemap>
  <sitemap><loc>http://t/smap/child2.xml</loc></sitemap>
  <sitemap><loc>http://t/smap/dead.xml</loc></sitemap>
</sitemapindex>"""

CHILD1 = URLSET
CHILD2 = """<?xml version="1.0"?>
<urlset><url><loc>http://t/s/d</loc></url></urlset>"""

TXT = """http://t/t/one
# comment
http://t/t/two
not-a-url-junk
http://t/t/one
"""


def _fetch_map(doc):
    def fetch(url):
        if url.endswith("dead.xml"):
            raise ConnectionError("dead child")
        return doc[url]
    return fetch


class TestUrlset:
    def test_expansion_dedup_and_order(self):
        urls = sitemap_to_urls("http://t/smap.xml", fetch=_fetch_map(
            {"http://t/smap.xml": URLSET}))
        assert urls == ["http://t/s/a?x=1", "http://t/s/b", "http://t/s/c"]

    def test_max_urls_cap(self):
        urls = sitemap_to_urls("http://t/smap.xml", max_urls=2, fetch=(
            _fetch_map({"http://t/smap.xml": URLSET})))
        assert len(urls) == 2


class TestIndex:
    def test_children_fetched_dead_child_survives(self):
        docs = {"http://t/smap.xml": INDEX,
                "http://t/smap/child1.xml": CHILD1,
                "http://t/smap/child2.xml": CHILD2}
        urls = sitemap_to_urls("http://t/smap.xml", fetch=_fetch_map(docs))
        # child2's locs come after child1's; the dead child contributes
        # nothing but does not abort the walk.
        assert urls[0] == "http://t/s/a?x=1"
        assert "http://t/s/d" in urls
        assert len(urls) == 4

    def test_max_children_cap(self):
        docs = {"http://t/smap.xml": INDEX,
                "http://t/smap/child1.xml": CHILD1,
                "http://t/smap/child2.xml": CHILD2}
        urls = sitemap_to_urls("http://t/smap.xml", max_children=1,
                               fetch=_fetch_map(docs))
        assert urls == ["http://t/s/a?x=1", "http://t/s/b", "http://t/s/c"]


class TestPlainText:
    def test_lines_filtered_to_real_urls(self):
        urls = sitemap_to_urls("http://t/sitemap.txt", fetch=_fetch_map(
            {"http://t/sitemap.txt": TXT}))
        # junk line dropped, comment dropped, dup collapsed
        assert urls == ["http://t/t/one", "http://t/t/two"]

    def test_html_error_page_yields_nothing(self):
        html = "<html><body><a href='/x'>404</a></body></html>"
        urls = sitemap_to_urls("http://t/sitemap.xml", fetch=_fetch_map(
            {"http://t/sitemap.xml": html}))
        # An HTML page is not a sitemap: nothing becomes a target.
        assert urls == []


class TestFileSource:
    def test_local_file_wins(self, tmp_path):
        p = tmp_path / "sitemap.xml"
        p.write_text(URLSET, encoding="utf-8")
        urls = sitemap_to_urls(str(p))
        assert len(urls) == 3

    def test_missing_scheme_raises(self):
        import pytest
        with pytest.raises(ValueError):
            sitemap_to_urls("ftp://not/supported")


def test_real_http_path(tmp_path):
    """One loopback test: the actual requests.get path (no injection).

    Child locs must name the REAL loopback host:port (an index that points
    at an unresolvable host would exercise only the tolerate path).  One
    intentionally dead child rides along to prove a failed fetch does not
    abort the walk.
    """
    served = {"/sitemap.xml": None,   # filled in below (needs the port)
              "/child1.xml": (CHILD1, "application/xml")}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            item = served.get(self.path)
            body, ctype = item if item else (b"", "text/plain")
            if isinstance(body, str):
                body = body.encode()
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    host = f"http://127.0.0.1:{port}"
    served["/sitemap.xml"] = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <sitemap><loc>{host}/child1.xml</loc></sitemap>\n"
        "  <sitemap><loc>http://dead.invalid/child2.xml</loc></sitemap>\n"
        "</sitemapindex>", "application/xml")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        urls = sitemap_to_urls(f"{host}/sitemap.xml", timeout=5)
    finally:
        srv.shutdown()
    # child1 expands; the dead child contributes nothing but is tolerated.
    assert urls == ["http://t/s/a?x=1", "http://t/s/b", "http://t/s/c"]
