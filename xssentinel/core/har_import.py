"""HAR (HTTP Archive) import for batch scanning (Phase 88 / P1).

XSpear, Burp, and browser devtools all export ``.har`` files.  The scan
pipeline's most valuable entry point is the ENDPOINT LIST captured in the
archive: every request the browser/app actually made is a real parameter
surface worth probing.

``har_to_scan_targets()`` flattens a HAR into per-entry scan targets:

  * method + URL (+ query) map onto the existing single-target pipeline;
  * POST bodies are parsed form-encoded (or kept raw for JSON/text) and
    become the scan's ``-d`` data;
  * cookies present on the entry become the scan's cookie jar;
  * only entries with a 2xx/3xx/4xx HTTP response are kept (failed DNS /
    aborted requests carry no server behaviour to probe);
  * duplicates (same method + URL + body) are collapsed.

Design notes
------------
This module does NOT know about Scanner internals.  It returns plain
``dict`` targets that ``cli_runner``/``__main__`` can feed through the
existing ``load_target_urls``-style flow.  Keeping the parser pure makes
it directly unit-testable without a live server.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

#: HAR mime types that carry request parameters worth scanning.
_FORM_TYPES = ("application/x-www-form-urlencoded",)
_JSON_TYPES = ("application/json", "text/json", "application/*+json")


class HarImportError(ValueError):
    """Raised when a HAR file cannot be parsed into scan targets."""


def _entry_target(entry: dict, idx: int) -> dict | None:
    """Convert one HAR ``entry`` into a scan-target dict.

    Returns None when the entry is not scannable (missing request/URL,
    non-HTTP response, or a request that already failed at the network
    layer -- no server behaviour to probe).
    """
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    if not url or method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        return None
    status = resp.get("status") or 0
    # 0 = aborted / no response; keep only real server answers.
    if not (200 <= status < 600):
        return None

    # Cookies the request carried -> scan with the same session context.
    cookies: list[str] = []
    for c in req.get("cookies") or []:
        name = c.get("name")
        value = c.get("value")
        if name is not None and value is not None:
            cookies.append(f"{name}={value}")

    # Extra headers worth preserving (auth, custom, X-*).  Host/Content-
    # Length/Cookie are transport details the pipeline re-derives.
    skip = {"host", "content-length", "cookie", "connection",
            "accept-encoding", "pragma", "cache-control"}
    headers: list[str] = []
    for h in req.get("headers") or []:
        n = (h.get("name") or "").strip()
        v = (h.get("value") or "").strip()
        if n.lower() in skip or not n:
            continue
        headers.append(f"{n}: {v}")

    body = (req.get("postData") or {}).get("text") or ""
    content_type = ""
    for h in req.get("headers") or []:
        if (h.get("name") or "").lower() == "content-type":
            content_type = (h.get("value") or "").split(";")[0].strip()
            break
    if body and content_type in _FORM_TYPES:
        try:
            params = parse_qsl(body, keep_blank_values=True)
        except Exception:
            params = []
        data = urlencode(params)
    elif body:
        # JSON / text / xml bodies are scanned as one carrier value.
        data = body
    else:
        data = ""

    return {
        "idx": idx,
        "method": method,
        "url": url,
        "data": data,
        "content_type": content_type or "application/x-www-form-urlencoded",
        "cookies": cookies,
        "headers": headers,
    }


def har_to_scan_targets(har_path: str, max_entries: int = 0) -> list[dict]:
    """Load a HAR file and return a deduplicated list of scan targets.

    ``max_entries`` caps how many entries are imported (0 = unlimited);
    the cap applies AFTER dedup so the first N unique endpoints win.

    Raises :class:`HarImportError` when the file is missing, is not valid
    JSON, lacks the ``log.entries`` array, or yields no scannable
    entries.
    """
    try:
        with open(har_path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except OSError as e:
        raise HarImportError(f"cannot read HAR file: {e}") from e
    except json.JSONDecodeError as e:
        raise HarImportError(f"HAR is not valid JSON: {e}") from e

    entries = ((doc.get("log") or {}).get("entries")) or []
    if not isinstance(entries, list) or not entries:
        raise HarImportError(
            f"HAR has no log.entries array ({har_path})")

    seen: set[str] = set()
    targets: list[dict] = []
    for idx, entry in enumerate(entries):
        tgt = _entry_target(entry, idx)
        if tgt is None:
            continue
        key = (f"{tgt['method']} {tgt['url']} "
               f"{tgt['data']} {';'.join(tgt['cookies'])}")
        if key in seen:
            continue
        seen.add(key)
        targets.append(tgt)
        if max_entries and len(targets) >= max_entries:
            break

    if not targets:
        raise HarImportError(
            f"HAR contains no scannable HTTP endpoints ({har_path})")
    return targets


def target_to_scan_args(tgt: dict) -> dict:
    """Map a HAR target dict onto CLI-style scan arguments.

    Query-string parameters on GET URLs are already part of ``url``
    (the scanner extracts them); POST/PUT/PATCH/DELETE bodies become the
    ``data`` carrier.  Returns a dict that mirrors what ``--batch``
    would parse for one line, so a HAR import can reuse the batch loop.
    """
    parsed = urlparse(tgt["url"])
    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "",
                      parsed.query, ""))
    return {
        "url": url,
        "method": tgt["method"],
        "data": tgt["data"],
        "cookies": "; ".join(tgt["cookies"]),
        "headers": list(tgt["headers"]),
        "content_type": tgt["content_type"],
    }
