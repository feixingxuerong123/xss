"""Shared finding dataclass + the default transform ladder.

Extracted from scanner.py (Phase 40) so scanner mixins can import them
without a circular import (scanner imports the mixins; mixins import
this module).
"""
from __future__ import annotations

_DEFAULT_TRANSFORMS = [
    [],  # base
    ["mixed_case"],
    ["html_entity_named"],
    ["url_encode_selective"],
    ["comment_break"],
    ["null_byte"],
    ["mixed_case", "comment_break"],
    ["fullwidth"],
    ["constructor_escape"],
    ["interleave_nulls"],
    ["utf7"],
    ["js_unicode"],
    ["css_unicode"],
    ["html5_entities"],
    ["duplicate_attribute"],
]



class Finding:
    def __init__(self, **kw):
        self.data = kw

    def to_dict(self):
        return self.data


def _norm(url: str) -> str:
    """Normalize a URL for comparison/dedup: drop fragment, default port, and
    lowercase scheme+host.  Query string is kept (so /p?a=1 vs /p?b=2 differ)
    but NOT sorted (param order rarely matters for dedup grouping)."""
    from urllib.parse import urlparse, urlunparse
    p = urlparse(url)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    # strip default ports so http://h:80/p == http://h/p
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, p.params, p.query, ""))


def _proof(resp, method, param, payload):
    return {
        "status": resp.status_code,
        "method": method,
        "param": param,
        "payload": payload,
        "snippet": _safe_snippet(resp.text, payload),
    }


def _safe_snippet(text, payload, width=120):
    i = text.find(payload[:30] if payload else "")
    if i == -1:
        return ""
    return text[max(0, i - 40): i + width].replace("\n", " ")


def attach_replay_ctx(finding, tl) -> None:
    """Phase 48: attach the OTHER (non-target) form fields of the request
    that produced ``finding`` -- typically CSRF/hidden tokens -- so PoC
    generators can emit a replay that passes CSRF checks.

    ``tl`` is the scanner's per-thread context holder (threading.local)
    whose ``reqctx`` was set by _scan_param for the endpoint currently
    being probed.  Guards: only POST-ish findings whose url+method match
    the live context, and only when the endpoint actually had extra body
    fields besides the injected parameter.
    """
    d = finding.data if hasattr(finding, "data") else finding
    if d.get("method") in (None, "GET") or "csrf_fields" in d:
        return
    rc = getattr(tl, "reqctx", None) if tl is not None else None
    if not (rc and rc.get("url") == d.get("url")
            and rc.get("method") == d.get("method")):
        return
    param = d.get("param")
    extra = {k: v for k, v in (rc.get("data") or {}).items()
             if v is not None and k != param}
    if extra:
        d["csrf_fields"] = extra

