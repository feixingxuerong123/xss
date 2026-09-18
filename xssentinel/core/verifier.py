"""Verification: confirm a reflected payload actually executes (not just echoes).

Two layers:
  1. Semantic confirmation (always on, zero deps): inject a unique token into
     the payload's alert() call; if the token reflects back *inside an
     executable context* (script block/string, event handler, javascript: URI),
     the reflection is exploitable, not escaped.
  2. Headless confirmation (optional): if Playwright is installed, actually
     render the response in a real browser and capture the dialog event. This
     is the strongest proof and also catches DOM/event-trigger XSS.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

from . import context as ctx
from .parser_utils import bs_parser as _bs_parser

_TOKEN_RE = re.compile(r"alert\((?:1|0|)\)")
# Match alert(<anything-not-paren>) so we can token-mark ALL alert variants,
# not just alert(1)/alert(0)/alert().  This covers alert(document.domain),
# alert(document.cookie), alert('xss'), etc.  The second alternative marks
# the tagged-template call alert`...` (Phase 32): it executes WITHOUT
# parentheses, so the generator uses it when ( ) are stripped/encoded.
_ALERT_CALL_RE = re.compile(r"alert\s*\(([^()]*)\)|alert\s*`([^`]*)`")

# RCDATA elements: content is treated as text by browsers, HTML tags inside
# are NOT parsed/executed.  A <script> or <img onerror> inside these is inert.
_RCDATA_TAGS = frozenset(["textarea", "title", "xmp", "iframe", "noembed",
                          "noframes", "noscript"])

# CSP patterns that block inline script execution.
_CSP_BLOCK_RE = re.compile(
    r"script-src\s+[^;]*(?:'none'|'self'|'nonce-[A-Za-z0-9+/=]+')",
    re.I)


# Phase 166: the concatenated callable.  A keyword filter typically rewrites a
# LITERAL callable -- benchmark filter_keywords rewrites
# alert|prompt|confirm|eval|function|setTimeout|setInterval|fetch|XMLHttpRequest
# followed by "(" into "blocked(" -- while letting this form through, which is
# exactly why the payloads that survived such a filter could never carry the
# marker: stamping required a literal callable.
_CONCAT_CALL = "window['ale'+'rt']"
# An on*= attribute value / a javascript: URI code section, so an unarmed
# payload's own execution point can be armed with the concat stamp.
_ON_HANDLER_RE = re.compile(
    r"(\son[a-z]+\s*=\s*)(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_JS_URI_RE = re.compile(r"javascript\s*:[^\s\"'>]*", re.I)


def mark(payload: str, token: str, style: str = "plain") -> str:
    """Inject `token` into the payload's alert() call so we can track it.

    Replaces the first alert(...) call's argument with the token so the
    verifier can confirm the payload executed (not just echoed).  Handles
    alert(1), alert(document.domain), alert('msg'), and the paren-free
    tagged-template form alert`1` (Phase 32).

    ``style="concat"`` stamps with ``window['ale'+'rt']('token')`` instead: a
    keyword filter cannot rewrite that (there is no literal callable followed
    by a paren), so it is the only way to confirm a target that neuters
    literal callables.  When the payload carries no callable at all, the
    stamp is appended to its own execution point (an on*= handler value or a
    javascript: URI) -- the structural gate only needs the token INSIDE the
    handler/URI value, not inside a call.
    """
    if style == "concat":
        if _ALERT_CALL_RE.search(payload):
            return _ALERT_CALL_RE.sub(
                lambda m: (f"{_CONCAT_CALL}('{token}')"
                           if m.group(1) is not None
                           else f"{_CONCAT_CALL}`{token}`"),
                payload, count=1)
        stamp = f";{_CONCAT_CALL}('{token}')"

        def _arm_handler(m):
            # Append INSIDE a quoted value: appending after the closing quote
            # leaves a stray statement in the tag, so the token would sit
            # outside the handler value and prove nothing.
            val = m.group(2) or m.group(3) or m.group(4) or ""
            if val[:1] in ("'", '"') and val[-1:] == val[:1]:
                return f"{m.group(1)}{val[:-1]}{stamp}{val[-1]}"
            return f"{m.group(1)}{val}{stamp}"

        out, n_on = _ON_HANDLER_RE.subn(_arm_handler, payload, count=1)
        if n_on:
            return out
        out, n_js = _JS_URI_RE.subn(
            lambda m: m.group(0).rstrip() + stamp, payload, count=1)
        if n_js:
            return out
        return payload

    def _sub(m):
        if m.group(1) is not None:
            return f"alert('{token}')"
        return f"alert`{token}`"
    return _ALERT_CALL_RE.sub(_sub, payload, count=1)


def _is_in_rcdata(tag) -> bool:
    """Check if a BeautifulSoup tag is inside an RCDATA ancestor."""
    parent = tag.parent
    while parent:
        if parent.name and parent.name.lower() in _RCDATA_TAGS:
            return True
        parent = parent.parent
    return False


def _in_rcdata_raw(html_text: str, token_idx: int) -> bool:
    """Raw-text check: is the token position inside an RCDATA element?

    Scans backwards from token_idx for an unclosed <textarea>/<title>/<xmp>
    opening tag.  This catches cases where BeautifulSoup's structural check
    was bypassed but the token is still in an inert RCDATA context.
    """
    before = html_text[:token_idx].lower()
    for tag_name in ("textarea", "title", "xmp"):
        open_tag = f"<{tag_name}"
        close_tag = f"</{tag_name}>"
        last_open = before.rfind(open_tag)
        if last_open == -1:
            continue
        # Check if there's a closing tag between the open and the token
        close_between = before.find(close_tag, last_open)
        if close_between == -1:
            # No closing tag found → token is inside this RCDATA element
            return True
    return False


def _csp_blocks_inline(headers: dict | None) -> bool:
    """Return True if the CSP header blocks inline script execution."""
    if not headers:
        return False
    csp = headers.get("Content-Security-Policy", "") or \
          headers.get("content-security-policy", "")
    if not csp:
        return False
    # script-src 'none', 'self' (without 'unsafe-inline'), or nonce-only
    if _CSP_BLOCK_RE.search(csp):
        # Ensure 'unsafe-inline' is NOT present (which would re-allow
        # inline) -- with one Phase 98 exception: when the policy ALSO
        # carries a nonce/hash source the browser IGNORES 'unsafe-inline'
        # (CSP Level 2+), so inline execution still requires the nonce and
        # bare inline reflection is blocked.  The nonce-leak path stays
        # alive: a script carrying a nonce the policy declares is
        # re-allowed by _script_nonce_allowed() further down, so this
        # cannot turn into a false negative on the nonce-reuse layer.
        if "'unsafe-inline'" not in csp.lower():
            return True
        try:
            from .csp import unsafe_inline_overridden
            if unsafe_inline_overridden(csp):
                return True
        except Exception:
            pass
    # default-src 'none' without explicit script-src also blocks
    if re.search(r"default-src\s+[^;]*'none'", csp, re.I) and \
            "script-src" not in csp.lower():
        return True
    return False


def _csp_blocks_js_uri(headers: dict | None) -> bool:
    """Return True if CSP blocks javascript: URI execution.

    In modern browsers (CSP Level 2+), javascript: URIs are governed by
    script-src.  If script-src lacks 'unsafe-inline', javascript: URIs
    are blocked — same policy that blocks inline <script> and on* handlers.
    """
    # javascript: URIs are treated as inline scripts by CSP.
    # If inline scripts are blocked, javascript: URIs are also blocked.
    return _csp_blocks_inline(headers)


def _token_in_js_string(script_text: str, token: str) -> bool:
    """Heuristic: is the token trapped inside a JS string literal in a
    non-executable position?

    Returns True only when the token is inside a string that is part of a
    variable/property ASSIGNMENT (var x = "...token...") meaning the payload
    failed to break out.  Returns False when the token is inside a function
    call argument like alert("token") which IS the executable payload.
    """
    idx = script_text.find(token)
    if idx == -1:
        return False

    # First: if there's a dangerous function call containing the token that
    # is NOT itself inside a string, the payload IS executable.
    # Check for alert/prompt/confirm/eval calls with the token as argument.
    dangerous_call = re.search(
        r"(?:alert|prompt|confirm|eval|setTimeout|setInterval|Function)\s*\([^)]*"
        + re.escape(token), script_text, re.I)
    if dangerous_call:
        # Verify the function call itself is not inside a string.
        call_start = dangerous_call.start()
        before_call = script_text[:call_start]
        # Count unescaped quotes before the function call
        dq = _count_unescaped_quotes(before_call, '"')
        sq = _count_unescaped_quotes(before_call, "'")
        if dq % 2 == 0 and sq % 2 == 0:
            # Function call is in code position → executable
            return False

    # Check if token is inside a string literal (between quotes)
    before = script_text[:idx]
    in_dq_string = (_count_unescaped_quotes(before, '"') % 2 == 1)
    in_sq_string = (_count_unescaped_quotes(before, "'") % 2 == 1)

    if in_dq_string or in_sq_string:
        quote_char = '"' if in_dq_string else "'"
        # Check what precedes the opening quote: if it's an assignment (= "
        # or : ") then the token is trapped in a data string.
        # Find the opening quote position
        open_pos = _find_opening_quote(before, quote_char)
        if open_pos >= 0:
            # Look at what's before the opening quote
            pre_quote = before[:open_pos].rstrip()
            # Assignment patterns: = "...", : "...", ("..." as function arg
            if pre_quote.endswith('=') or pre_quote.endswith(':'):
                # Verify string is properly closed after token
                after = script_text[idx + len(token):]
                if _has_closing_quote(after, quote_char):
                    return True
            # If preceded by ( it's likely a function argument - could be
            # alert("token") which is executable, so don't trap it.
        # Fallback: if in string and string is closed, consider trapped
        after = script_text[idx + len(token):]
        if _has_closing_quote(after, quote_char):
            # But only if there's no unescaped </script> after the token
            # (which would indicate a successful breakout)
            if "</script>" not in after.split(quote_char)[0].lower():
                return True

    return False


def _count_unescaped_quotes(text: str, quote: str) -> int:
    """Count unescaped occurrences of quote char in text."""
    count = 0
    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text):
            i += 2
            continue
        if text[i] == quote:
            count += 1
        i += 1
    return count


def _find_opening_quote(before: str, quote: str) -> int:
    """Find the position of the last unescaped opening quote in before."""
    positions = []
    i = 0
    while i < len(before):
        if before[i] == '\\' and i + 1 < len(before):
            i += 2
            continue
        if before[i] == quote:
            positions.append(i)
        i += 1
    # The opening quote is the last one that makes the count odd
    # (i.e., the one that opened the current string)
    if len(positions) % 2 == 1:
        return positions[-1]
    return -1


def _has_closing_quote(after: str, quote: str) -> bool:
    """Check if there's an unescaped closing quote in the text after token."""
    i = 0
    while i < len(after):
        if after[i] == '\\' and i + 1 < len(after):
            i += 2
            continue
        if after[i] == quote:
            return True
        i += 1
    return False


def _extract_script_block(html_text: str, token_idx: int) -> str | None:
    """Extract the text content of the <script> block containing token_idx.

    Uses HTML parsing semantics: <script> opens a raw-text element that
    extends until the FIRST </script> (inner <script> tags are just text).
    Returns the text between the opening tag and closing tag, or None.
    """
    lower = html_text.lower()
    # Find all <script> opening tags before the token
    search_start = 0
    best_start = -1
    best_tag_end = -1
    while True:
        pos = lower.find("<script", search_start)
        if pos == -1 or pos > token_idx:
            break
        # Find end of this opening tag
        tag_end = html_text.find(">", pos)
        if tag_end == -1:
            break
        # Find the closing </script> for THIS script element
        close_pos = lower.find("</script>", tag_end)
        if close_pos == -1:
            # No closing tag; this script extends to end of document
            best_start = pos
            best_tag_end = tag_end
            break
        if close_pos >= token_idx:
            # Token is between this script's open and close → this is our block
            best_start = pos
            best_tag_end = tag_end
            break
        # Token is after this script's close → try next script tag
        search_start = close_pos + 9  # len("</script>")

    if best_tag_end == -1:
        return None
    # Extract text between opening tag end and closing tag (or end of text)
    close_pos = lower.find("</script>", best_tag_end)
    if close_pos == -1:
        return html_text[best_tag_end + 1:]
    return html_text[best_tag_end + 1: close_pos]


def _script_nonce_allowed(script_tag, headers) -> bool:
    """Phase 36: a script whose nonce is declared by the page's own CSP
    header is ALLOWED to execute (the nonce-leak exploitation path).

    If the server rotates nonces per request, the injected script's nonce
    will NOT match the fresh response header and this returns False --
    which is exactly the real-browser behavior we want to mirror.
    """
    if not headers:
        return False
    sn = (script_tag.get("nonce") or "").strip("'\" ")
    if not sn:
        return False
    csp = (headers.get("Content-Security-Policy")
           or headers.get("content-security-policy") or "")
    if not csp:
        return False
    try:
        from . import csp as csp_mod
        return sn in [n.strip("'\" ")
                      for n in csp_mod.extract_nonces_from_csp(csp)]
    except Exception:
        return False


_TOKEN_IN_PAYLOAD_RE = re.compile(r"xssv_[0-9a-f]{8}")


def payload_survived(response_text: str, payload: str) -> bool:
    """Did the payload survive the round trip, or only its token?

    Phase 165.  ``verify_semantic`` confirms on the token plus a structural
    context, which is the right question for "did this land somewhere
    executable" -- but it is blind to a server that REWRITES the payload while
    leaving the token alone.  Measured on two benchmark cases:

      * ``filter_keywords`` rewrites ``alert(`` into ``blocked(``: the finding
        was credited, and a human replaying the shipped PoC saw
        ``javascript:blocked(...)`` -- no alert, nothing to reproduce;
      * ``filter_javascript_uri`` strips a ``data:text/html,`` prefix: the
        claimed URL carrier is gone from the response.

    Neither is provable XSS.  This answers the narrower question so callers can
    keep looking for a payload that DOES survive instead of reporting one that
    does not.  The token is wildcarded: benign re-encodings of the token must
    not read as mangling, while a rewritten callable or a dropped scheme must.
    """
    if not response_text or not payload:
        return False
    for cand in _survival_candidates(payload):
        pat = _TOKEN_IN_PAYLOAD_RE.sub("xssv_[0-9a-f]{8}", re.escape(cand))
        try:
            if re.search(pat, response_text):
                return True
        except re.error:                                  # pragma: no cover
            return True
    return False


def _survival_candidates(payload: str) -> list:
    """The forms a payload may legitimately come back in.

    The TRANSPORT encoding is not the reflected form: a transform that
    percent-encodes the payload to slip past a naive filter is decoded by the
    app and reflected DECODED (measured: tests/test_async_budget.py's
    "naivewaf" fixture), and a pre-encoded base64 container is decoded and
    reflected as its inner payload (tests/test_async_pipeline.py).  Comparing
    only the sent form rejected both -- the gate was too strict, not the
    targets safe.
    """
    out = {payload,
           urllib.parse.quote(payload, safe=""),
           urllib.parse.quote_plus(payload, safe="")}
    try:
        once = urllib.parse.unquote(payload)
        out.add(once)
        out.add(urllib.parse.unquote(once))
    except Exception:
        pass
    # base64 containers, in BOTH alphabets and up to two rounds: the
    # pre-encoded layer and its fixtures use the URL-safe alphabet without
    # padding (see tests/test_async_pipeline.py's decode fixture), which the
    # standard alphabet cannot read.
    for cur in (payload, payload.replace("-", "+").replace("_", "/")):
        dec = cur
        for _ in range(2):
            try:
                pad = dec + "=" * (-len(dec) % 4)
                nxt = base64.b64decode(pad, validate=True).decode(
                    "utf-8", "replace")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                # Narrow on purpose: a broad except here swallowed a NameError
                # (this module only imported base64 locally back then) and the
                # helper silently produced no base64 candidates at all --
                # measured as test_async_pipeline's pre-encode failure.
                break
            if not nxt or nxt == dec or not nxt.isprintable():
                break
            dec = nxt
            out.add(dec)
            for part in re.findall(r'"[^"]*?<[^"]*?"', dec):
                out.add(part.strip('"'))
    return [c for c in out if c]
    return False


def verify_semantic(response_text: str, token: str,
                    response_headers: dict | None = None) -> dict:
    """Return confirmation based on where the token reflected.

    Uses a real HTML parser (not naive regex) so a transform that merely
    *breaks the tag name* to slip past a string-WAF is NOT counted as a real
    execution: e.g. `<\\tscript>` is parsed as text, not a script element, so
    it is reported as non-executable. This keeps confirmation meaningful.

    Args:
        response_text: The HTTP response body.
        token: The unique verification token injected into the payload.
        response_headers: Optional dict of HTTP response headers. Used to
            detect CSP policies that block inline script execution.
    """
    idx = response_text.find(token)
    if idx == -1:
        return {"confirmed": False, "context": None,
                "detail": "token not reflected"}

    # -- CSP gate: if a strict Content-Security-Policy blocks inline scripts,
    #    reflected <script>/on* handlers won't execute in a real browser. --
    csp_blocks = _csp_blocks_inline(response_headers)

    # -- Raw RCDATA gate BEFORE structural parsing (Phase 35 hardening). --
    #    lxml's HTML tree fixup can hoist a tag written inside
    #    <title>/<textarea>/<xmp> up to the document top, losing the RCDATA
    #    ancestor in the bs4 tree -- the structural checks below would then
    #    confirm an inert reflection (observed as a rare polyglot_reflection
    #    false positive on RCDATA endpoints).  The raw scan is immune to
    #    that; a genuine breakout AFTER the closing tag still confirms.
    if _in_rcdata_raw(response_text, idx):
        return {"confirmed": False, "context": "html_element",
                "detail": "token reflected inside RCDATA element (inert text)"}

    # -- Structural confirmation (authoritative) -------------------------
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response_text, _bs_parser())
        verdict = _structural_confirm(soup, token, csp_blocks,
                                      response_headers)
        if verdict is not None:
            return verdict
    except Exception:
        pass

    # -- Template-expression reflection ({{ ... token ... }}): a reflected
    #    Angular/Vue/Handlebars expression is itself the sink. --
    if re.search(r"\{\{[^}]*" + re.escape(token) + r"[^}]*\}\}", response_text):
        return {"confirmed": True, "context": "template_angular",
                "detail": "token reflected inside {{ }} template expression"}

    # -- Conservative fallback: is an executable sink genuinely adjacent? ---
    # CSP gate applies to the fallback too.
    if csp_blocks:
        return {"confirmed": False, "context": "script_block",
                "detail": "token reflected but CSP blocks inline execution"}

    # RCDATA gate (raw text): if the token is inside <textarea>/<title>/<xmp>
    # in the raw HTML, browsers treat it as text regardless of what it looks like.
    if _in_rcdata_raw(response_text, idx):
        return {"confirmed": False, "context": "html_element",
                "detail": "token reflected inside RCDATA element (inert text)"}

    info = ctx._analyze_at(response_text, idx, token)
    c = info["context"] if info else None
    executable = c in (
        "script_block", "script_string_dq", "script_string_sq",
        "event_handler", "url_javascript", "svg_context",
        "meta_refresh", "template_angular", "cdata",
    ) and _fallback_executable(response_text, idx, token, c)

    # -- mXSS mutation check (Phase 16) ---------------------------------
    # If the single-pass parse did not confirm, check whether the page
    # contains a *mutating sink* (e.g. ``<svg><style>``, ``<noscript>``,
    # ``<math><mtext>``) that would cause a browser's HTML parser to
    # re-interpret the reflected token as executable code on a second
    # parse pass.  This is the core mXSS mechanism -- a single-pass
    # parser (like the one above) cannot see it, so without this check
    # all mXSS payloads are falsely reported as non-executable.
    if not executable:
        verdict = _mxss_confirm(response_text, token, idx)
        if verdict is not None:
            return verdict

    return {
        "confirmed": executable,
        "context": c,
        "detail": f"token reflected in context '{c}'"
                  + ("" if executable else " (escaped / non-executable)"),
    }


def _structural_confirm(soup, token: str, csp_blocks: bool,
                        response_headers: dict | None) -> dict | None:
    """Authoritative BeautifulSoup-based confirmation (verify_semantic
    steps 1-4).  Returns a verdict dict or None when no structural sink
    matched and parsing should fall through to the raw-text fallback."""
    # 1) token inside a real <script> element's text
    for s in soup.find_all("script"):
        if token in (s.get_text() or ""):
            # RCDATA guard: <script> inside textarea/title/xmp is inert
            if _is_in_rcdata(s):
                continue
            # CSP guard: strict CSP blocks inline script execution.
            # Phase 36 exception: a script carrying a nonce declared in
            # the CSP header itself is allowed (nonce-leak exploit).
            if csp_blocks and not _script_nonce_allowed(s,
                                                         response_headers):
                return {"confirmed": False, "context": "script_block",
                        "detail": "token in <script> but CSP blocks inline execution"}
            # JS string trapping: token inside a properly escaped string
            # literal is NOT executable code (e.g. var x = "...token...")
            script_text = s.get_text() or ""
            if _token_in_js_string(script_text, token):
                continue
            return {"confirmed": True, "context": "script_block",
                    "detail": "token reflected inside <script> element text"}

    # 2) token inside an event-handler attr, or a javascript: URI
    for tag in soup.find_all(True):
        # RCDATA guard: tags inside textarea/title/xmp are inert text
        if _is_in_rcdata(tag):
            continue
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = " ".join(val)
            if not isinstance(val, str):
                continue
            if attr.lower().startswith("on") and token in val:
                if csp_blocks:
                    return {"confirmed": False, "context": "event_handler",
                            "detail": f"token in {attr} but CSP blocks inline execution"}
                return {"confirmed": True, "context": "event_handler",
                        "detail": f"token reflected in {attr} handler"}
            if attr.lower() in ("href", "src") and "javascript:" in val.lower() \
                    and token in val:
                # CSP script-src 'none' also blocks javascript: URIs
                if csp_blocks and _csp_blocks_js_uri(response_headers):
                    return {"confirmed": False, "context": "url_javascript",
                            "detail": "token in javascript: URI but CSP blocks script execution"}
                return {"confirmed": True, "context": "url_javascript",
                        "detail": f"token reflected in {attr}=javascript: URI"}
            # meta refresh content="...url=javascript:..." executes on refresh
            if attr.lower() == "content" and "javascript:" in val.lower() \
                    and token in val:
                return {"confirmed": True, "context": "meta_refresh",
                        "detail": "token reflected in meta refresh "
                                  "content=javascript: URI"}

    # 3) SVG/MathML on* handlers (bs4 may store as `/onload` after a slash)
    for tag in soup.find_all(True):
        if _is_in_rcdata(tag):
            continue
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = " ".join(val)
            if not isinstance(val, str):
                continue
            if attr.lower().lstrip("/").startswith("on") and token in val and attr.lower() != "on":
                if csp_blocks:
                    return {"confirmed": False, "context": "event_handler",
                            "detail": f"token in {attr} but CSP blocks inline execution"}
                return {"confirmed": True, "context": "event_handler",
                        "detail": f"token reflected in {attr} handler (svg/math)"}

    # 4) CSS context: token inside <style> text or a style= attribute that
    #    actually carries an executable CSS sink (expression()/javascript:/@import).
    #
    #    Phase 91: this branch used to ignore CSP entirely while the
    #    script_block / event_handler / url_javascript branches all honour
    #    it, so <svg><style><iframe src=javascript:alert(TOK)></style></svg>
    #    was confirmed even under script-src 'self'.  A ``javascript:`` sink
    #    reached through CSS is still script execution, so it is gated too.
    for s in soup.find_all("style"):
        txt = s.get_text() or ""
        if token in txt and re.search(
                r"expression\s*\(|javascript:|@import", txt, re.I):
            if "javascript:" in txt.lower() and _csp_blocks_js_uri(
                    response_headers):
                return {"confirmed": False, "context": "css_context",
                        "detail": "token in <style> javascript: sink but CSP "
                                  "blocks script execution"}
            return {"confirmed": True, "context": "css_context",
                    "detail": "token in <style> with expression()/javascript:/@import"}
    for tag in soup.find_all(True):
        style = tag.get("style")
        if isinstance(style, str) and token in style and re.search(
                r"expression\s*\(|javascript:|@import", style, re.I):
            if "javascript:" in style.lower() and _csp_blocks_js_uri(
                    response_headers):
                return {"confirmed": False, "context": "css_context",
                        "detail": "token in style= javascript: sink but CSP "
                                  "blocks script execution"}
            return {"confirmed": True, "context": "css_context",
                    "detail": "token in style= attr with expression()/javascript:/@import"}
    return None


# An on* attribute name.  \b keeps ``on`` from matching inside ``button``.
_ON_ATTR_RE = re.compile(r"\bon\w+\s*=", re.I)


_WS_CHARS = " \t\r\n\f\v"


def _value_owner_attr(tag: str, pos: int) -> str | None:
    """Name the attribute whose VALUE contains ``pos``; None between attrs.

    A tiny HTML tokenizer over one tag's text, because a browser's own
    rules decide what is an attribute and what is merely text:

    * ``value='&#x27; onmouseover=...'`` -- a QUOTED value is still open,
      so the handler belongs to ``value`` (html.escape'd breakout).
    * ``<img src=x/onerror=...>`` -- an UNQUOTED value is still open; ``/``
      does not terminate one, only whitespace does.  lxml agrees:
      ``src='x/onerror=alert(1)'`` and there is no onerror attribute.
    * ``<svg/onload=...>`` -- no value is open, so this returns None.
      lxml drops that attribute outright, which is exactly why the
      raw-text fallback exists.
    """
    i = 0
    n = len(tag)
    state = 0  # 0 = between attributes, 1 = quoted value, 2 = unquoted value
    quote = ""
    owner: str | None = None
    name_start: int | None = None
    while i < pos:
        ch = tag[i]
        if state == 1:
            if ch == quote:
                state, owner = 0, None
            i += 1
        elif state == 2:
            if ch in _WS_CHARS:
                state, owner = 0, None
            i += 1
        elif ch in _WS_CHARS:
            name_start = None
            i += 1
        elif ch == "=":
            owner = (tag[name_start:i].strip().lower()
                     if name_start is not None else "")
            j = i + 1
            while j < n and tag[j] in _WS_CHARS:
                j += 1
            if j < n and tag[j] in "\"'":
                quote, state, i = tag[j], 1, j + 1
            else:
                state, i = 2, j
        else:
            if name_start is None:
                name_start = i
            i += 1
    return owner if state else None


def _on_attr_is_real(tag: str, pos: int) -> bool:
    """True when the ``on*`` at ``pos`` sits at a genuine attribute boundary.

    ``&amp;`` in an earlier value opens nothing, so a real breakout such as
    ``<img src="a&amp;b" alt=x onmouseover=...>`` is still confirmed.
    """
    return _value_owner_attr(tag, pos) is None


# Attributes that carry a URI -- the only ones in which a javascript: sink
# is actually reached.  Anything else (``value``, ``alt``, ``title``) means
# the "src=javascript:" text is inert content of that attribute.
_URI_ATTRS = frozenset([
    "href", "src", "action", "formaction", "data", "poster", "background",
    "content", "cite", "longdesc", "usemap", "manifest", "srcdoc", "ping",
    "codebase", "profile", "icon", "xlink:href",
])

# Phase 128: attribute tokenizer for the mXSS exec-context check.  Quoted
# values are consumed atomically, so handler/URI text sitting inside ANOTHER
# attribute's value cannot masquerade as a live attribute.
_MXSS_ATTR_RE = re.compile(
    r'([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')


def _marker_in_exec_context(response_text: str, token: str) -> bool:
    """True when the token sits where a browser would actually EXECUTE it.

    Phase 128: `_mxss_confirm` used to accept "the token appears somewhere
    AND the page carries a mutating sink".  ``mutation.analyze()``'s
    ``reflected`` flag is a bare substring test over the whole response, so
    an HTML-ESCAPED token sitting in a text node counted as reflected -- and
    any page with innerHTML/DOMParser in a script then produced a
    high-severity finding the moment the token showed up.  Execution needs
    one of:
      * a live ``<script>`` block containing the token, or
      * a REAL element attribute whose tokenised value carries the token --
        an ``on*`` handler, or a ``javascript:`` URI in a URI attribute.
    Escaped text is inert: ``&lt;img src=x onerror=alert(&#x27;TOK&#x27;)&gt;``
    starts no tag, and ``onerror=`` inside another attribute's quoted value
    is text, not an attribute.  (Same discipline as
    ``dom_clobber._real_tag_attr``.)
    """
    if not response_text or not token:
        return False
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", response_text,
                         re.IGNORECASE | re.DOTALL):
        if token in m.group(1):
            return True
    for tag in re.finditer(r"<\s*[a-zA-Z][^>]*>", response_text):
        for m in _MXSS_ATTR_RE.finditer(tag.group(0)):
            name = m.group(1).lower()
            value = next((g for g in m.groups()[1:] if g is not None), "")
            if token not in value:
                continue
            if name.startswith("on"):
                return True
            if name in _URI_ATTRS and value.strip().lower().startswith(
                    "javascript:"):
                return True
    return False


def _event_handler_raw_confirmed(response_text: str, idx: int,
                                 token: str) -> bool:
    """Raw-text confirmation for the ``event_handler`` context.

    Used only when the structural (BeautifulSoup) pass found no real ``on*``
    attribute holding the token -- typically slash-form tags lxml drops
    (``<svg/onload=...>``).  Confirms when, *inside the tag that contains
    the token*, some ``on\\w+=`` is reachable from the tag opener without
    crossing a quote/angle entity, and the token sits after that handler.
    """
    start = response_text.rfind("<", 0, idx)
    if start == -1:
        return False
    end = response_text.find(">", idx)
    if end == -1:
        end = min(len(response_text), idx + 400)
    tag = response_text[start:end]
    if token not in tag:
        return False
    for m in _ON_ATTR_RE.finditer(tag):
        if not _on_attr_is_real(tag, m.start()):
            continue  # still inside a quoted value -- inert text
        if token in tag[m.end():]:
            return True
    return False


def _fallback_executable(response_text: str, idx: int, token: str,
                         c: str | None) -> bool:
    """Refine the raw-text classifier verdict with per-context guards.

    The regex classifier can be fooled by entity-encoded or trapped
    reflections; each guard here refuses to confirm when the reflection is
    provably inert.  Unknown contexts keep the classifier's verdict.
    """
    if c in ("script_string_dq", "script_string_sq", "script_block"):
        # Extra verification: ensure the token actually broke out of the JS
        # string and is in executable code position.  If it's still trapped
        # inside a properly escaped string assignment, don't confirm.
        # Extract the surrounding <script> block text for analysis.
        script_match = _extract_script_block(response_text, idx)
        if script_match and _token_in_js_string(script_match, token):
            return False
        return True
    if c == "html_element":
        # require an unbroken, unescaped <script>/<svg>/<tag on*= sink next to
        # the token. An escaped string like &lt;svg/onload= is text, not a tag,
        # so it must NOT confirm (prevents false positives on html.escape'd input).
        snippet = response_text[max(0, idx - 40): idx + 40]
        return bool(re.search(
            r"<script|<svg|<[a-zA-Z][^>]*\bon\w+\s*=", snippet, re.I))
    if c == "event_handler":
        # The structural parse (BeautifulSoup) did NOT find a real on* attr
        # with the token.  The regex fallback sees on*= text in the raw HTML,
        # but it might be inside an attribute VALUE (e.g. value="...onfocus=...").
        # Require that the on* pattern looks like a real attribute boundary:
        # preceded by whitespace or a tag opener, not by = or a quote char.
        #
        # Phase 84 relaxed this to let the token sit anywhere inside the on*
        # attribute VALUE (lxml drops attributes on slash-form tags such as
        # <svg/onload=...>).  That relaxation also re-admitted escaped
        # reflections: html.escape(quote=True) turns the breakout quote into
        # &#x27;, so  value='&#x27; onmouseover=alert(&#x27;TOK&#x27;)  is
        # inert attribute TEXT -- the quote never terminated anything -- yet
        # it matched.  Phase 91 therefore requires the handler to sit at a
        # real attribute boundary: see _on_attr_is_real(), which walks the
        # tag's quote state instead of pattern-matching, so it also rejects
        # UTF-7-style variants (+ACY- onmouseover=...) that carry no entity
        # at all.  A genuine breakout (<img src="a&amp;b" alt=
        # onmouseover=...>) is still confirmed -- &amp; does not open a value.
        return _event_handler_raw_confirmed(response_text, idx, token)
    if c in ("url_javascript", "meta_refresh"):
        # Phase 43 (async-benchmark FP): a literal ``javascript:`` substring
        # SURVIVES html.escape (letters are not encoded), so an
        # attribute-escaped reflection like
        #     value='&lt;iframe src=javascript:alert(&#x27;tok&#x27;)&gt;'
        # is inert attribute TEXT yet still trips the raw-text classifier
        # (it sees ``javascript:...token``).  A live href=javascript: URI
        # never carries entity-encoded boundaries, so confirming via the
        # raw-text fallback requires the preceding window to be free of
        # entities (the structural parse above has already validated real
        # href/src/content attributes with decoded values).
        return _uri_sink_raw_confirmed(response_text, idx, token)
    return True


def _uri_sink_raw_confirmed(response_text: str, idx: int, token: str) -> bool:
    """Raw-text confirmation for ``javascript:`` URI sinks.

    Phase 43 fixed the entity-encoded case -- a literal ``javascript:``
    survives html.escape, so

        value='&lt;iframe src=javascript:alert(&#x27;TOK&#x27;)&gt;'

    is inert attribute TEXT that still trips the raw-text classifier.
    Requiring "no entity in the preceding window" was not enough though:
    UTF-7-style transforms carry no entity at all, so

        value='+ADw-iframe src=javascript:alert+ADs-+ACY-TOK+ACY-+AD0-+AD4-'

    slipped straight through (observed as neg-escape-03 in the async
    matrix).  Both are the same mistake: the ``src=``/``href=`` in them is
    text belonging to some *other* attribute.  So the guard now asks which
    attribute's VALUE actually contains the sink and requires it to be a
    URI-carrying one (href/src/content/...).  The entity check is kept as
    defence in depth but narrowed to the enclosing tag, so a legitimate
    ``href="javascript:alert('a&amp;b')"`` is no longer rejected for the
    ``&amp;`` that appears *after* the scheme.
    """
    start = response_text.rfind("<", 0, idx)
    if start == -1:
        return False
    end = response_text.find(">", idx)
    if end == -1:
        end = min(len(response_text), idx + 400)
    tag = response_text[start:end]
    if token not in tag:
        return False
    for m in re.finditer(r"javascript\s*:", tag, re.I):
        if _value_owner_attr(tag, m.start()) not in _URI_ATTRS:
            continue  # text inside some non-URI attribute -- inert
        if re.search(r"&(?:lt|gt|quot|apos|#\d+|#x[0-9a-f]+|[a-z]+);",
                     tag[:m.start()], re.I):
            continue  # entity-encoded boundary -- the value never closed
        if token in tag[m.end():]:
            return True
    return False


def _mxss_confirm(response_text: str, token: str, idx: int) -> dict | None:
    """Phase 16 mXSS check: return a confirmed verdict when the page has a
    *mutating sink* that a browser's parse-serialize-reparse round-trip
    would turn into executable code, or None when not applicable."""
    try:
        from . import mutation as mxss_mod
        mxss_result = mxss_mod.analyze(response_text, token)
        if mxss_result.get("exploitable"):
            # Phase 128: "the token appears somewhere AND the page carries a
            # sink" is NOT mutation evidence.  analyze()'s `reflected` is a
            # bare substring test over the whole response, so an
            # HTML-ESCAPED token sitting in a text node counted as
            # "reflected" -- and then any page with innerHTML/DOMParser in a
            # script produced a high-severity `reflected` finding the moment
            # the token showed up.  That is the escaping-blind family again
            # (Phase 123), and it fired on the benchmark's escaping twin,
            # i.e. on every ordinary app that escapes its output.
            # Require the token to have actually landed in an EXECUTABLE
            # context in the served bytes: a live <script>, an on*= handler
            # value, or a javascript: URI.  The helper lives in this module
            # on purpose -- it must not depend on a module that is not part
            # of the repository.
            if not _marker_in_exec_context(response_text, token):
                return None
            # Phase 43 (async-benchmark FP): a polyglot payload carries
            # its OWN tag structure (<div id=x><script>...), so the
            # "mutating sink" the analyzer sees may be payload-internal
            # text, not page structure.  If the token is still trapped
            # inside a properly escaped JS string in the response, the
            # whole construction is inert — refuse to confirm.
            sm = _extract_script_block(response_text, idx)
            trapped = bool(sm and _token_in_js_string(sm, token))
            if not trapped:
                sinks = mxss_result.get("sinks", [])
                return {
                    "confirmed": True,
                    "context": "mutation_xss",
                    "detail": (
                        "token reflected near a mutating sink "
                        f"({', '.join(sinks[:2]) if sinks else 'unknown'}); "
                        "browser HTML parser would reinterpret as executable "
                        "on the parse-serialize-reparse round-trip"
                    ),
                }
    except Exception:
        pass  # mXSS analysis must not break the verifier
    return None


def verify_headless(url: str, method: str, params: dict | None,
                    data: dict | None, headers: dict | None,
                    token: str, timeout: int = 20) -> dict:
    """Best-effort headless confirmation via Playwright. Returns status dict.

    For GET: encode params into the URL, set extra HTTP headers, then navigate.
    For POST: fetch the response via the request API and render it with
    ``page.set_content`` so the dialog handler can fire on the resulting page.

    Phase 38 (P1-6): reuses a thread-bound shared Chromium instead of
    launching a fresh browser for every confirmation (~1-2s saved each).
    """
    try:
        from .dom_engine import get_shared_browser
    except Exception:
        return {"available": False, "confirmed": False,
                "detail": "playwright not installed; skipped"}

    from urllib.parse import urlencode
    page = None
    try:
        browser = get_shared_browser()
        page = browser.new_page()
        fired: list[str] = []

        def on_dialog(dialog):
            fired.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", on_dialog)
        if headers:
            try:
                page.set_extra_http_headers(headers)
            except Exception:
                pass
        if method.upper() == "POST":
            # Fetch the POST response via the request API, then render the
            # body in the page so scripts execute and dialogs fire.
            try:
                resp = page.context.request.post(
                    url, data=data or {}, params=params or {},
                    headers=headers or {}, timeout=timeout * 1000)
                body = resp.text() if hasattr(resp, "text") else ""
                page.set_content(body, timeout=timeout * 1000)
            except Exception as e:
                return {"available": True, "confirmed": False,
                        "detail": f"headless POST error: {e}"}
        else:
            full_url = url
            if params:
                sep = "&" if "?" in url else "?"
                full_url = url + sep + urlencode(params)
            page.goto(full_url, timeout=timeout * 1000)
        # Give scripts a moment to fire dialogs before closing.
        try:
            page.wait_for_load_state("domcontentloaded",
                                     timeout=timeout * 1000)
        except Exception:
            pass
        # Phase 46 (pentest-readiness): the previous rule
        # ``any(token in m) or len(fired) > 0`` confirmed ANY dialog as
        # execution -- a page that pops its own alert() (cookie banners,
        # debug hooks, anti-bot warnings) turned into a false "confirmed"
        # finding in the client report.  Confirmation now REQUIRES the
        # dialog message to carry the unique probe token.
        token_hit = [m for m in fired if token in m]
        confirmed = bool(token_hit)
        # Evidence screenshot: captures the executing page (dialogs are
        # dismissed by the handler, so this is the page state right after
        # execution).  Returned as base64 PNG so the HTML report can embed
        # it self-contained.
        screenshot_b64 = None
        try:
            raw = page.screenshot(type="png")
            if raw and len(raw) <= 2 * 1024 * 1024:   # 2 MB guard
                import base64 as _b64
                screenshot_b64 = _b64.b64encode(raw).decode("ascii")
        except Exception:
            screenshot_b64 = None
        if confirmed:
            detail = f"dialogs fired carrying the probe token: {token_hit}"
        elif fired:
            detail = (f"dialogs fired but NONE carried the probe token "
                      f"({fired}) -- the dialog came from the page itself, "
                      f"NOT the payload; not confirmed")
        else:
            detail = "no dialog"
        result = {"available": True, "confirmed": confirmed, "detail": detail}
        if screenshot_b64:
            result["screenshot_b64"] = screenshot_b64
        return result
    except Exception as e:  # pragma: no cover
        return {"available": True, "confirmed": False,
                "detail": f"headless run error: {e}"}
    finally:
        # Pages are disposable; the shared browser is NOT closed.
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
