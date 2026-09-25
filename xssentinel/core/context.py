"""Reflection-context analyzer.

Given an HTTP response body and the unique marker that was reflected back,
classify the context the input landed in. The scanner uses this to pick
context-appropriate payloads. Heuristic but dependency-free.

Contexts covered:
  html_element, html_attribute_dq/sq/noquote, script_block,
  script_string_dq/sq, script_template, event_handler, url_href,
  url_javascript, css_context (style attr / <style>), svg_context,
  math_context, html_comment.
"""
from __future__ import annotations

import re

_TAGNAME_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")


def _rfind_ci(body: str, sub: str, end: int) -> int:
    lower = body[:end].lower()
    return lower.rfind(sub.lower())


def _script_content(body: str, tag_start: int, tag_gt: int, idx: int) -> dict:
    content = body[tag_gt + 1:idx]
    in_dq = content.count('"') % 2 == 1
    in_sq = content.count("'") % 2 == 1
    in_bt = content.count("`") % 2 == 1   # template literal
    if in_bt:
        return {"context": "script_template", "index": idx,
                "inside_tag": False, "tag": "script"}
    if in_dq:
        return {"context": "script_string_dq", "index": idx,
                "inside_tag": False, "tag": "script"}
    if in_sq:
        return {"context": "script_string_sq", "index": idx,
                "inside_tag": False, "tag": "script"}
    return {"context": "script_block", "index": idx,
            "inside_tag": False, "tag": "script"}


def _enclosing_tags(body: str, idx: int) -> list[str]:
    """Return the open tag stack before idx (lightweight nesting check)."""
    stack = []
    for m in re.finditer(r"</?([a-zA-Z][a-zA-Z0-9]*)\b", body[:idx]):
        raw = m.group(0)
        name = m.group(1).lower()
        if raw.startswith("</"):
            if stack and stack[-1] == name:
                stack.pop()
        else:
            # self-closing tags don't push
            if not raw.rstrip(">").endswith("/"):
                stack.append(name)
    return stack


def _analyze_at(body: str, idx: int, marker: str) -> dict | None:
    # 1) Inside <script>...</script> content? (most reliable)
    s_open = _rfind_ci(body, "<script", idx)
    if s_open != -1:
        s_gt = body.find(">", s_open)
        s_close = _rfind_ci(body, "</script", idx)
        if s_gt != -1 and s_gt < idx and (s_close == -1 or s_close < s_open):
            return _script_content(body, s_open, s_gt, idx)

    # 2) Inside <style>...</style> content?
    st_open = _rfind_ci(body, "<style", idx)
    if st_open != -1:
        st_gt = body.find(">", st_open)
        st_close = _rfind_ci(body, "</style", idx)
        if st_gt != -1 and st_gt < idx and (st_close == -1 or st_close < st_open):
            return {"context": "css_context", "index": idx,
                    "inside_tag": False, "tag": "style"}

    # 2.5) Inside a CDATA section? (XHTML/SVG <style>/<script> raw text, or
    #      raw XML). Content here is not entity-decoded, so a `</script>` inside
    #      CDATA does NOT close the script — breakout needs a CDATA-closing trick.
    cdata_open = body.rfind("<![CDATA[", 0, idx)
    if cdata_open != -1 and body.find("]]>", cdata_open, idx) == -1:
        return {"context": "cdata", "index": idx,
                "inside_tag": False, "tag": "cdata"}

    # 3) Inside an open HTML comment? (must precede the tag branch, because a
    #    reflection like `<!-- ... MARKER -->` otherwise looks like a tag).
    cmt_open = body.rfind("<!--", 0, idx)
    if cmt_open != -1 and body.find("-->", cmt_open, idx) == -1:
        return {"context": "html_comment", "index": idx,
                "inside_tag": False, "tag": "comment"}

    # 4) Inside a tag (attribute / event-handler / svg / math)?
    last_lt = body.rfind("<", 0, idx)
    last_gt = body.rfind(">", 0, idx)
    if last_lt > last_gt:
        tag_segment = body[last_lt:idx]
        m = _TAGNAME_RE.search(tag_segment)
        tagname = m.group(1).lower() if m else ""
        if tagname == "script":
            return _script_content(body, last_lt, last_gt, idx)
        attr = _attribute_context(tag_segment)
        if attr:
            return attr
        if tagname in ("svg", "math"):
            return {"context": f"{tagname}_context", "index": idx,
                    "inside_tag": True, "tag": tagname}
        return {"context": "html_element", "index": idx,
                "inside_tag": True, "tag": tagname}

    # 5) Between tags (or no tags): svg/math nesting / element body.
    stack = _enclosing_tags(body, idx)
    if "svg" in stack:
        return {"context": "svg_context", "index": idx,
                "inside_tag": False, "tag": "svg"}
    if "math" in stack:
        return {"context": "math_context", "index": idx,
                "inside_tag": False, "tag": "math"}

    # 6) Reflected inside a template-expression delimiter {{ ... }}? (Angular /
    #    Vue / Handlebars interpolation — a reflected template-injection sink).
    pre = body[max(0, idx - 40): idx]
    post = body[idx: idx + 40]
    if "{{" in pre and "}}" in post and "{{" in body[max(0, idx - 60):idx + 60]:
        return {"context": "template_angular", "index": idx,
                "inside_tag": False, "tag": "template"}

    return {"context": "html_element", "index": idx, "inside_tag": False}


def analyze(body: str, marker: str) -> dict | None:
    idx = body.find(marker)
    if idx == -1:
        return None
    return _analyze_at(body, idx, marker)


# Entities that prove the server encoded the input around the marker.
_ESCAPED_HINT_ENTITIES = (
    "&lt;", "&gt;", "&quot;", "&#39;", "&#x27;", "&amp;lt;", "&amp;gt;",
)


def is_marker_escaped(text: str, marker: str) -> bool:
    """True when the marker reflected but the input around it was encoded.

    Phase 27-1.  A server that applies context-aware output encoding shows
    the plain alphanumeric marker verbatim while any ``<``/``>``/``"``
    around it comes back as ``&lt;``/``&gt;``/``&quot;``.  That means the
    overwhelming majority of payload variants will be encoded too and
    cannot execute, so both engines shrink their budget for that param
    (sync: 3 payloads x 2 transforms instead of 14 x 12).

    Canonical implementation -- it used to be copy-pasted into scanner.py
    and scanner_layers.py, and the async engine had no copy at all, which
    is why async paid the full 168-request budget on escaped endpoints
    (neg-escape-03: 23s async vs 2s sync).

    Returns True when the marker sits inside an escaped context (early
    convergence is safe), False otherwise.
    """
    if not text or not marker:
        return False
    idx = text.find(marker)
    if idx < 0:
        return False
    before = text[max(0, idx - 8):idx]
    after = text[idx + len(marker):idx + len(marker) + 8]
    for entity in _ESCAPED_HINT_ENTITIES:
        if before.endswith(entity) or after.startswith(entity):
            return True
    # Double-encoded entities (&amp;lt; -> &lt;).
    return "&amp;" in before[-5:] or "&amp;" in after[:5]


_ATTR_RE = re.compile(
    r"""(?P<name>[a-zA-Z_:][\w:\.-]*)\s*=\s*"""
    r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<nq>[^\s>]*))""",
    re.S,
)


def _attribute_context(segment: str) -> dict | None:
    # The reflection sits *inside* the value, possibly before the closing
    # quote, so extend the segment to let quoted values match correctly.
    #
    # Phase 130: the tail must be able to close BOTH quote styles.  The old
    # `">` only terminated a double-quoted value; an unterminated
    # SINGLE-quoted value fell through to the unquoted branch and the whole
    # attribute was classified `html_attribute_noquote` -- so the scanner
    # picked the space-break-out corpus for `<input value='...'>`, could not
    # break out of the quotes, and reported a live single-quote break-out as
    # nothing (or diluted it to a medium polyglot note).  Appending `'">`
    # closes a single-quoted value while still closing a double-quoted one
    # and leaving genuinely unquoted values unquoted.
    seg = segment + "'\">"
    matches = list(_ATTR_RE.finditer(seg))
    if not matches:
        return None
    m = matches[-1]  # last attribute == the one containing the reflection
    name = m.group("name").lower()
    if name == "content" and "refresh" in seg.lower() and "http-equiv" in seg.lower():
        # Reflection inside <meta http-equiv="refresh" content="...">:
        # a `url=javascript:...` value executes on refresh.
        return {"context": "meta_refresh", "index": -1,
                "inside_tag": True, "tag": "meta", "attr": name}
    if m.group("dq") is not None:
        q = '"'
    elif m.group("sq") is not None:
        q = "'"
    else:
        q = ""
    val = m.group("dq")
    if val is None:
        val = m.group("sq")
    if val is None:
        val = m.group("nq") or ""
    val_l = val.lower()
    if name.startswith("on"):
        return {"context": "event_handler", "index": -1,
                "inside_tag": True, "tag": "attr", "attr": name}
    if name == "style":
        # CSS context: expression()/url(javascript:) sinks (legacy IE etc.)
        return {"context": "css_context", "index": -1,
                "inside_tag": True, "tag": "attr", "attr": name}
    if name in ("href", "src"):
        if "javascript:" in val_l:
            return {"context": "url_javascript", "index": -1,
                    "inside_tag": True, "tag": "attr", "attr": name}
        return {"context": "url_href", "index": -1,
                "inside_tag": True, "tag": "attr", "attr": name}
    if q == '"':
        return {"context": "html_attribute_dq", "index": -1,
                "inside_tag": True, "tag": "attr", "attr": name}
    if q == "'":
        return {"context": "html_attribute_sq", "index": -1,
                "inside_tag": True, "tag": "attr", "attr": name}
    return {"context": "html_attribute_noquote", "index": -1,
            "inside_tag": True, "tag": "attr", "attr": name}


def rank_contexts(body: str, marker: str) -> list[str]:
    seen = []
    start = 0
    while True:
        i = body.find(marker, start)
        if i == -1:
            break
        c = _analyze_at(body, i, marker)
        if c and c["context"] not in seen:
            seen.append(c["context"])
        start = i + len(marker)
    return seen


# Contexts ordered by how directly an unescaped payload there executes.
# The marker often reflects at SEVERAL points in one page (a nav
# highlight, an HTML comment, and the actual sink); classifying only the
# first byte-stream occurrence made both engines pick payloads for
# whatever came first -- typically an inert comment -- while the
# executable context was never tested at all.  This list is the
# tiebreaker `analyze_all` uses to choose the primary context among ALL
# reflection points.  Single-reflection pages keep exactly the old
# behaviour: one occurrence -> its own context, whatever it is.
_CONTEXT_PRIORITY = [
    "script_block", "script_string_dq", "script_string_sq",
    "script_template", "event_handler", "url_javascript",
    "url_href", "meta_refresh",
    "html_attribute_dq", "html_attribute_sq", "html_attribute_noquote",
    "svg_context", "math_context", "html_element",
    "css_context", "template_angular", "html_comment", "cdata",
]


def analyze_all(body: str, marker: str) -> dict:
    """Classify every reflection of ``marker`` and choose a primary context.

    Returns ``{"context": <primary>, "contexts": [<distinct contexts in
    reflection order>]}``.  The primary is the highest-priority context
    from ``_CONTEXT_PRIORITY`` (executable contexts beat inert ones);
    when the marker reflects only once this is exactly ``analyze()``'s
    answer.  The full list lets the scanners queue a small candidate set
    for each additional context without growing the request budget.
    """
    contexts = rank_contexts(body, marker)
    if not contexts:
        return {"context": "html_element", "contexts": []}

    def _prio(c: str) -> int:
        try:
            return _CONTEXT_PRIORITY.index(c)
        except ValueError:
            return len(_CONTEXT_PRIORITY)

    return {"context": min(contexts, key=_prio), "contexts": contexts}
