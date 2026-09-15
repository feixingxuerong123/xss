"""Payload corpus loader."""
from __future__ import annotations

import json
import os
import threading

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_PAYLOADS_FILE = os.path.join(_DATA_DIR, "payloads.json")

_cache: dict | None = None
_cache_lock = threading.Lock()


def _load() -> dict:
    global _cache
    if _cache is None:
        with _cache_lock:
            # Double-checked locking: avoid double-load when multiple threads
            # race on the first call.
            if _cache is None:
                with open(_PAYLOADS_FILE, "r", encoding="utf-8") as f:
                    _cache = json.load(f)
    return _cache


def all_payloads() -> list[dict]:
    return _load()["payloads"]


def all_polyglots() -> list[dict]:
    return _load().get("polyglots", [])


def by_context(context: str) -> list[dict]:
    return [p for p in all_payloads() if p.get("context") == context]


# ---------------------------------------------------------------------------
# Phase 43: multi-corpus cross-context sampling matrix — parity with the
# sync scanner's _scan_param (_sample + cross-context expansion).  Maps a
# reflection context to the SIBLING corpora whose shapes also fire there;
# without it the async path only sees one corpus slice and misses payloads
# like the recursive <sscriptcript> strip (observed as neg-filter-01 FN).
# ---------------------------------------------------------------------------
_CROSS_CONTEXT: dict[str, list[tuple[str, int]]] = {
    "url_href": [("url_javascript", 4), ("data_uri", 3)],
    "meta_refresh": [("url_javascript", 4), ("data_uri", 3)],
    "svg_context": [("html_element", 4)],
    "math_context": [("html_element", 4)],
    "template_angular": [("template_vue", 2), ("framework_angular", 3),
                         ("framework_vue", 3), ("framework_mustache", 2)],
    "template_vue": [("template_vue", 2), ("framework_angular", 3),
                     ("framework_vue", 3), ("framework_mustache", 2)],
    "cdata": [("script_block", 4)],
    "css_context": [("css_exfil", 3)],
    # Phase 137: `url_javascript` was only ever a sibling of url_href /
    # meta_refresh, so in a plain element context the engine never sent a
    # javascript:-URI payload -- yet `<a href="javascript:...">x</a>` is
    # perfectly live there.  Found by benchmark/fuzz_context_matrix.py
    # (text + strip-a-<script>-filter: the payload keeps no script tag, so
    # the filter does not touch it and the verifier confirms it).
    # Kept at n=2: the Phase 43 note above -- cross-context samples reorder
    # the budget window, so they go in small.
    "html_element": [("dom_clobber", 2), ("html5_new", 2),
                     ("dangling_markup", 1), ("script_gadget", 2),
                     ("markdown", 2), ("framework_react", 1),
                     ("framework_svelte", 1), ("url_javascript", 2)],
    "script_block": [("service_worker", 2), ("postmessage_source", 2),
                     ("prototype_gadget", 2)],
}


def _stride_sample(items: list[dict], n: int) -> list[dict]:
    """Even-stride sampling so the budget spreads across corpus shapes
    (mirrors the sync scanner's _sample)."""
    if n <= 0 or not items:
        return []
    if len(items) <= n:
        return items
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def cross_context_candidates(context: str, budget: int) -> list[str]:
    """Payload STRINGS for a context: even-stride sample of the primary
    corpus + the cross-context sibling corpora, capped at ``budget``.
    Order: primary first (biggest slice), then siblings — dedup preserves
    first-seen order.

    NOTE: polyglots are deliberately NOT included here — the async probe
    loop already appends a ``build_polyglot(marker)`` variant per payload
    (matching the pre-Phase-43 behavior).  Adding the full polyglot corpus
    here reordered multi-context gadget payloads into the budget window on
    strictly-escaped endpoints and caused jQuery-gadget false positives
    (their execution depends on page-level conditions the verifier cannot
    see: jQuery presence, ``.html()`` entity decoding).

    The primary corpus is taken from the HEAD, not stride-sampled: the
    corpus is ordered by real-world yield, and stride sampling with small
    budgets was observed to skip the basic confirmation payloads (async L1
    tests with budget=3 regressed to zero findings).
    """
    primary = by_context(context)[:max(6, budget // 2)]
    out: list[str] = [p["payload"] for p in primary if p.get("payload")]
    seen = set(out)
    for extra_ctx, n in _CROSS_CONTEXT.get(context, []):
        for p in _stride_sample(by_context(extra_ctx), n):
            s = p.get("payload", "")
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out[:budget]


def for_context(context: str) -> list[str]:
    """Payload STRINGS for a context (async scanner convenience).

    The async scanner iterates raw strings; this shim also documents the
    contract that was silently missing before Phase 37 (its absence made
    the async L1 layer raise AttributeError inside a swallowed except).
    """
    return [p.get("payload", "") for p in by_context(context)
            if p.get("payload")]


def polyglots_for(context: str) -> list[dict]:
    return [p for p in all_polyglots() if context in p.get("contexts", [])]


def contexts() -> list[str]:
    return _load()["_meta"]["contexts"]


def reload(path: str | None = None) -> None:
    """Reload corpus from a custom JSON file (extensibility hook)."""
    global _cache
    with _cache_lock:
        if path:
            with open(path, "r", encoding="utf-8") as f:
                _cache = json.load(f)
        else:
            _cache = None
    _load()
