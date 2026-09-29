"""Sitemap URL-source import (Phase 184, absorbed from DalFox --sitemap).

``--sitemap`` joins the input family (--batch / --batch-stdin / --har /
--openapi): point it at a sitemap and every ``<loc>`` becomes a scan
target.  Handles the three shapes seen in the wild:

  * sitemap **index** (``<sitemapindex>`` of ``<sitemap><loc>`` entries) --
    child sitemaps are fetched recursively, bounded by ``max_children``;
  * a normal **URL set** (``<urlset>`` of ``<url><loc>`` entries);
  * a **plain-text** sitemap (some sites serve ``sitemap.txt``) -- one URL
    per line, ``#`` comments.

The source may be an http(s) URL (fetched with the core ``requests``
dependency) or a local file path (``os.path.isfile`` wins first, so
fetching a URL that happens to name an existing file is not a thing that
can happen).

Scope policy follows the Phase 176l import philosophy: the sitemap the
operator named defines the authorized host set; ``<loc>`` entries on other
hosts are reported and dropped unless --allow-host / --allow-any-host say
otherwise (partitioning itself lives in ``cli_runner``, mirroring the HAR
path, so the behavior is identical across imports).

Security note: the XML is untrusted input.  Parsing uses ``xml.etree``
(external entities are never resolved by the stdlib parser) and the text
is never interpolated into anything but URL strings; caps bound both the
number of child sitemaps and total URLs so a hostile 10GB sitemap cannot
turn into a memory event.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

__all__ = ["sitemap_to_urls"]

_MAX_BYTES = 8 * 1024 * 1024      # per-document cap


def _local_tag(elem) -> str:
    """``{namespace}loc`` -> ``loc`` (sitemap namespaces vary)."""
    return elem.tag.rsplit("}", 1)[-1].lower()


def _iter_locs(xml_text: str) -> tuple[list[str], bool]:
    """Parse one sitemap document -> (loc urls, is_index)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], False
    urls: list[str] = []
    child_sitemaps: list[str] = []
    for elem in root.iter():
        tag = _local_tag(elem)
        if tag == "loc" and elem.text and elem.text.strip():
            urls.append(elem.text.strip())
    # A document is an index when its DIRECT children include <sitemap>
    # entries; <url> children mark a URL set.  Iterate once more, cheaply.
    is_index = any(_local_tag(c) == "sitemap" for c in root)
    if is_index:
        child_sitemaps = urls
        return child_sitemaps, True
    return urls, False


def _load(source: str, timeout: int, fetch=None) -> str:
    """Fetch or read the sitemap document as text."""
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            return f.read(_MAX_BYTES)
    if not (source.lower().startswith("http://")
            or source.lower().startswith("https://")):
        raise ValueError(
            f"sitemap source is neither a file nor an http(s) URL: {source}")
    if fetch is not None:                     # injectable for tests
        return fetch(source)
    import requests
    r = requests.get(source, timeout=timeout,
                     headers={"User-Agent": "xssentinel-sitemap/1.0"},
                     stream=True)
    r.raise_for_status()
    return r.raw.read(_MAX_BYTES + 1, decode_content=True).decode(
        "utf-8", errors="replace")[:_MAX_BYTES]


def sitemap_to_urls(source: str, timeout: int = 15, max_urls: int = 500,
                    max_children: int = 20,
                    fetch=None) -> list[str]:
    """Expand a sitemap (index, URL set, or plain text) into scan targets.

    Returns deduplicated URLs in document order, capped at ``max_urls``.
    Raises on unreachable sources; callers surface the error like the HAR
    importer does.
    """
    text = _load(source, timeout, fetch)

    # Plain-text sitemap: not XML at all -> one URL per line.  Only lines
    # that actually parse as http(s) URLs survive: a misconfigured server
    # handing us an HTML error page must not become 200 junk scan targets.
    if "<" not in text.split("\n", 1)[0] and not text.lstrip().startswith("<?"):
        urls = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            p = urlparse(ln)
            if p.scheme in ("http", "https") and p.netloc:
                urls.append(ln)
        return list(dict.fromkeys(urls))[:max_urls]

    root_urls, is_index = _iter_locs(text)
    if not is_index:
        return list(dict.fromkeys(root_urls))[:max_urls]

    # Sitemap index: fetch each child (bounded), collecting their <loc>s.
    out: list[str] = []
    for child in root_urls[:max_children]:
        try:
            ctext = _load(child, timeout, fetch)
        except Exception:
            continue                    # a dead child must not kill the rest
        try:
            croot = ET.fromstring(ctext)
            for elem in croot.iter():
                if _local_tag(elem) == "loc" and elem.text \
                        and elem.text.strip():
                    out.append(elem.text.strip())
        except ET.ParseError:
            continue
        if len(out) >= max_urls:
            break
    return list(dict.fromkeys(out))[:max_urls]
