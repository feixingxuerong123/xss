"""Pure-Python HTML sandbox: decide whether reflected markup is LIVE, no browser.

Why this exists
---------------
`verifier.verify_semantic` answers "is the token inside an executable context"
from a BeautifulSoup tree plus hand-maintained sink tables.  `dom_engine` answers
the same question by launching Chromium at ~5.6 s per probe page, and
`mxss_verify` needs a browser for the parse->serialise->re-parse round-trip that
defines mutation XSS.  On an engagement that ordering is backwards twice over:
the browser is the slow, fragile, sometimes-unavailable path, and the question
"does `<img src=x onerror=...>` inside a `class="..."` value fire?" does not
need one -- it needs a parser that agrees with the browser about tokenisation
and serialisation.

This module is that parser.  It never *executes* a payload -- no JS engine runs,
and the only thing JavaScript is used for is reading a script body's lexical
states and syntax tree, so an XSS verdict becomes a structural fact about a DOM.
Three states, deliberately:

    LIVE      a node the browser would run is present, with the reason attached
    INERT     the token is present but cannot run (raw text, attribute value,
              dropped tag, ...).  Safe to report as a non-finding, and safe to
              skip the browser for.
    UNKNOWN   the sandbox does not model what it met.  Callers MUST fall back
              to the browser.  A sandbox that never says UNKNOWN is not
              conservative, it is wrong with more confidence.

Fidelity is measured, not assumed: `benchmark/sandbox_fidelity.py` scores every
row of `benchmark/results/browser_dom_oracle.json` (Chromium ground truth,
payload x context x sink) against this module, and every disagreement is a test.
`tests/test_sandbox_fidelity.py` replays that corpus in CI so a rule changed for
one payload cannot silently flip another.

What it models
--------------
* Tokeniser states the XSS decisions actually depend on: tag/attribute
  quote-state recovery, RAWTEXT (script/style/xmp/iframe/noembed/noframes),
  RCDATA (title/textarea), PLAINTEXT, <noscript> under scripting, bogus
  comments, CDATA in foreign content, character references consumed per state.
  U+0000 is per-context too, and the two halves point opposite ways: it becomes
  U+FFFD in tag names, attribute names, attribute values, comments, RCDATA and
  RAWTEXT, and is *dropped* in document text (benchmark/probe_nul.py).  Getting
  either half backwards manufactures a live <script> or a live javascript: URI
  out of a payload that cannot run.
* Foreign content: <svg>/<math> subtrees, MathML text integration points
  (mtext/mi/mn/mo/ms...) and SVG HTML integration points (foreignObject,
  desc, title), and the *measured* break-out set (benchmark/probe_breakout.py:
  40 names, identical for both namespaces).  Two consequences worth stating
  because they contradict the folklore: <style> inside <svg> is NOT raw text, so
  `<svg><style><img onerror=...>` is live on the FIRST parse rather than a
  mutation vector; and HTML void-ness does not cross the foreign boundary, so a
  `<base>` in SVG takes children.
* Insertion modes that move nodes: implicit <p> closing, the implied
  <tbody>/<tr>, **foster parenting** out of table scope, <select>/<option>
  scoping (measured name by name, 105 names x 3 contexts,
  benchmark/probe_option.py -- and it is *not* the spec's list: only `input`
  leaves an open select, 12 names are discarded outright, everything else stays
  where it sits), <template> content, the <body> attribute merge, stray end tags.
  Foster parenting matters beyond tidiness: moving an empty <table> is what
  re-orders a serialisation, and the re-order is what flips a namespace on the
  next parse (see `judge_roundtrip` and tests/test_sandbox.py's mutation test).
* Event semantics per element and per sink: which handler can fire without user
  interaction (`onerror` needs a src that can fail, `ontoggle` is a <details>
  event, `onload` on <svg>/<body> is a document event that does not re-fire for
  an innerHTML-inserted node), and whether the element's namespace gives it the
  HTML behaviour at all.
* The serialiser, because the round-trip is what mutation is judged on: text is
  escaped for & < > and nbsp everywhere *including* foreign content (measured --
  `<svg>` text is not an &-only zone), except inside the HTML no-escaping
  elements, which write verbatim; attribute values escape & " < > and controls.
* JavaScript, read but not run: whether a script body or an inline handler
  compiles at all, and whether the token sits in code, in a data string, or in
  the argument of the alert-family call the marker was stamped into.

Usage
-----
    from xssentinel.core import sandbox
    v = sandbox.judge(document_html, token)        # -> Verdict(state, reason)
    sandbox.roundtrip(html)                        # -> [ser1, ser2, ...]

    python -m xssentinel.core.sandbox --payload '<img src=x onerror=alert(1)>' \\
            --host attr_dq --token alert
"""
from __future__ import annotations

import json
import re
from typing import Iterable, Optional

try:                          # optional extra; js validity gating degrades to
    import esprima as _esprima  # type: ignore[import-untyped]  # "cannot decide" without it
except ImportError:           # noqa: E402
    _esprima = None

# ---------------------------------------------------------------------------
# Element classification tables
# ---------------------------------------------------------------------------

#: <script> and <style> contents are tokenised as raw text: no entities, and
#: only the matching close tag ends them.
RAWTEXT = frozenset({"style", "xmp", "iframe", "noembed", "noframes"})
#: Like RAWTEXT but character references ARE consumed.
RCDATA = frozenset({"title", "textarea"})
#: Everything to end-of-input is text.
PLAINTEXT = frozenset({"plaintext"})
#: Scripting is enabled in every browser we care about, so <noscript> is
#: raw text -- the vector family that depends on it only bites after a
#: serialise/re-parse into a *scripting-disabled* context.
NOSCRIPT_RAWTEXT = frozenset({"noscript"})

#: Elements whose serialised text children are written verbatim (no escaping).
#: Taken from the HTML parsing spec's "serialise an HTML fragment" step; this is
#: the exact set that lets text turn back into markup on re-parse.
NO_ESCAPE_TEXT = frozenset(
    {"script", "style", "xmp", "iframe", "noembed", "noframes", "plaintext",
     "noscript"})

#: MathML integration points: children are parsed as HTML, not MathML.
MATHML_TEXT_INTEGRATION = frozenset(
    {"mtext", "mi", "mo", "mn", "ms", "mmultiscripts", "mprescripts",
     "none", "annotation-xml"})
#: SVG integration points: children are parsed as HTML.
SVG_HTML_INTEGRATION = frozenset({"foreignobject", "desc", "title"})
#: Start tags that BREAK OUT of foreign content: the parser leaves the svg/math
#: subtree and the element becomes HTML beside it.
#:
#: MEASURED, not recalled from the spec.  Every name in a 120-element candidate
#: list was opened inside `<svg>` and inside `<math>` and the element's own
#: position in the resulting tree decided the answer
#: (benchmark/probe_breakout.py -> results/foreign_breakout.json).  Both
#: namespaces returned the identical 40 names.
#:
#: Getting this wrong costs in both directions, which is why it is measured
#: rather than guessed.  `<select>`, `<template>`, `<style>`, `<script>`,
#: `<iframe>`, `<form>`, `<input>`, `<button>`, `<option>`, `<td>`/`<tr>`,
#: `<a>`, `<title>` and `<noscript>` do NOT break out -- listing them as
#: breakers collapses the foreign subtree into HTML and manufactures liveness
#: (that was the bug behind the `mxss-select-style x svg_style` miss).  And
#: `<span>`, `<s>`, `<tt>`, `<var>`, `<em>`, `<ruby>`, `<small>`, `<dd>` DO --
#: leaving them out loses the real `<svg><span><img onerror>` breakout.
#: `code`/`nobr` are in the spec's list and unprobed here; `body`/`head` are in
#: the spec's list but create no element inside a div, so this harness cannot
#: observe them -- both are included because the break-out *decision* is what
#: the tree builder acts on.
FOREIGN_BREAK = frozenset({
    "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div",
    "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head",
    "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p",
    "pre", "ruby", "s", "small", "span", "strike", "strong", "sub", "sup",
    "table", "tt", "u", "ul", "var",
})

#: Void elements never take children and swallow no close tag.
VOID = frozenset({
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame",
    "hr", "img", "input", "keygen", "link", "meta", "param", "source",
    "track", "wbr", "image", "menuitem", "command", "!--",
})

#: Elements that auto-dismiss the next <p>.
P_CLOSERS = frozenset({
    "address", "article", "aside", "blockquote", "center", "details",
    "dialog", "dir", "div", "dl", "fieldset", "figcaption", "figure",
    "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
    "hgroup", "main", "menu", "nav", "ol", "p", "pre", "section",
    "summary", "ul", "table", "span", "hr", "iframe", "noscript",
    "button", "input", "select", "textarea", "li", "dd", "dt",
})

#: End tags that close a <p> even though they are not themselves <p>.
AUTO_CLOSE = {
    "li": {"li"},
    "dd": {"dd", "dt"},
    "dt": {"dd", "dt"},
    "tr": {"td", "th", "tr"},
    "td": {"td", "th"},
    "th": {"td", "th"},
    "p": {"p"},
    "option": {"option"},
    "optgroup": {"option", "optgroup"},
}

# ---------------------------------------------------------------------------
# Sink semantics -- which attribute/element pairs can actually RUN.
#
# Every entry below is traceable to a measurement, not to memory:
#   benchmark/sink_execution.py  (2026-09-18, headless Chromium, per-shape)
#   benchmark/results/browser_dom_oracle.json (payload x context x sink)
# An unmeasured shape is UNKNOWN and the caller is told so; that is the whole
# reason the three-state Verdict exists.
# ---------------------------------------------------------------------------

#: javascript: URI sinks that execute with no user activation.
JS_URI_EXECUTES = {("iframe", "src"), ("frame", "src")}

#: javascript: URI sinks that are real XSS behind a user gesture.  Chromium
#: will not run a javascript: URI from a script-synthesised click at all
#: (measured: `a.href = javascript:CODE (synthetic click)` and even the
#: trusted-click shape both no-exec in that harness), so only a human clicking
#: the link completes the chain -- hence "activation", never "executes".
JS_URI_ACTIVATION = {
    ("a", "href"), ("area", "href"), ("form", "action"),
    ("button", "formaction"), ("input", "formaction"), ("select", "formaction"),
    # An SVG anchor's `xlink:href` is the same sink as its `href`: measured no
    # execution on load, execution on a trusted mouse click, with and without the
    # `xmlns:xlink` declaration (benchmark/probe_svg_ns.py).  The row only means
    # anything once the `<a>` has a box to click, which is why those payloads
    # carry a sized `<svg>` and a `<text>` child.
    ("a", "xlink:href"),
}

#: Measured NOT to execute a javascript: URI.  Listed because the absence of a
#: table entry would be UNKNOWN, and "unknown" is expensive: it sends the
#: scanner back to a 5.6 s browser probe for a shape we have proved inert.
#: `frame.src` is deliberately absent -- it executes (see JS_URI_EXECUTES), and
#: having it in both tables once meant the rule below was reachable only by the
#: order of two dict lookups.
JS_URI_INERT = {
    ("img", "src"), ("link", "href"), ("script", "src"), ("base", "href"),
    ("embed", "src"), ("object", "data"), ("source", "src"),
    ("track", "src"), ("video", "src"), ("audio", "src"),
    ("input", "src"),
    # meta refresh to a javascript: URL: measured no-exec (Chromium dropped
    # javascript: in meta refresh long ago).
    ("meta", "content"),
    # The foreign-content resource sinks: `<svg><image href>`, `<use xlink:href>`
    # and `<feImage href>` all measured no-exec, and none of them has a gesture
    # that could make them run -- a user click cannot re-resolve an image
    # reference the way it can follow an anchor (benchmark/probe_svg_ns.py).  The
    # MathML `<maction xlink:href>` sibling is deliberately NOT here: relocate
    # wants a click on a MathML element that gets no box to click, so the
    # question stayed unasked and the verdict stays UNKNOWN.
    ("image", "href"), ("image", "xlink:href"),
    ("use", "xlink:href"), ("feimage", "href"),
}

#: Events that fire without user interaction, and the elements they can fire on
#: once the node has been inserted by the *parser*.  A handler on anything not
#: listed here is a real vulnerability one click away -> activation, not inert.
AUTO_FIRING_EVENTS = {
    "onerror": {"img", "script", "iframe", "source", "video", "audio", "link",
                "object", "embed", "input", "track"},
    "onload": {"svg", "body", "frameset", "iframe", "frame", "object", "img",
               "script", "link", "vmlframe"},
    "ontoggle": {"details"},
    "onfocus": {"*"},            # only with autofocus; see _handler_state
    "onbrowsersubmit": {"*"},
    "onbeforetoggle": {"details"},
    "onscroll": {"*"},           # fires on restore; treat as auto
}

#: SMIL timing events.  These were listed as auto-firing on `{'*'}` while
#: `judge` simultaneously demanded user interaction -- and both halves were
#: wrong: a SMIL timeline belongs to the animation element, not to any element.
#: Measured element x event x `begin` value in
#: benchmark/results/smil_probe.json (23 shapes, both sinks).
SMIL_TIMING_EVENTS = frozenset({"onbegin", "onend", "onrepeat"})

#: The SMIL elements that really do start a timeline on their own: `<animate
#: onbegin>` fires within 300 ms of the parse with no interaction, in the
#: document parse *and* through innerHTML.
SMIL_TIMING_ELEMENTS = frozenset({"animate", "set", "animatetransform",
                                  "animatemotion"})

#: SMIL-adjacent elements measured NOT to fire their timing handler.  `<discard>`
#: is the instructive one: it is an animation element, and it still does not
#: raise `begin` here, so the set above is a measured list rather than "anything
#: SMIL-looking".
SMIL_TIMING_INERT = frozenset({"discard", "svg", "circle", "rect"})

#: A SMIL clock value: `0s`, `2s`, `1.5s`, or a bare number (seconds implied).
#: Anything else in `begin` is offset/event/syncbase syntax and is not measured.
_SMIL_CLOCK_RE = re.compile(r"^\d+(\.\d+)?(s|ms)?$")

#: `begin="<dom event>"` waits for that event, which is what `activation` means
#: here: not inert, but not something the gate may promote either.
SMIL_GESTURE_TRIGGERS = frozenset({
    "mouseover", "mouseout", "mousedown", "mouseup", "click", "dblclick",
    "focus", "blur", "keypress",
})

#: Media *loading* events, measured on `<audio>` with a loadable src: they fire
#: with no user interaction, in every context that instantiates the element
#: (plain div, `<select><option>`, `<table><td>`, `<svg><foreignObject>`) and in
#: neither a `<template>` nor an unquoted-attribute swallow.  See
#: benchmark/results/media_probe.json -- 19 shapes x 6 reflection contexts.
#:
#: Deliberately only these six.  `onplaying`/`onended`/`ontimeupdate` belong to
#: playback, which autoplay policy gates (`video ontimeupdate` measured no-exec
#: in all six contexts), so they stay in the generic tail rather than being swept
#: in by the family name.  `<video>` uses the same loading machinery but was not
#: measured for these events, so it is not claimed either.
MEDIA_LOAD_EVENTS = frozenset({
    "onloadstart", "ondurationchange", "onloadedmetadata", "onloadeddata",
    "oncanplay", "oncanplaythrough",
})

#: The only elements a media event can be dispatched to.  `<audio>` is the one
#: measured here; the rest keep the sandbox out of claiming a verdict for a
#: loading path it has not watched.
MEDIA_EVENT_TARGETS = frozenset({"audio", "video", "source", "track"})

#: Start tags that the tree builder ignores unless a table is already open.
#: Measured name by name in a bare `<div>`, and again inside `<select>`,
#: `<option>` and `<optgroup>` (152 names x 4 contexts,
#: benchmark/results/option_probe.json): the browser creates no element at all,
#: so a payload reflected as `<td>` is not merely inert, it is absent -- and a
#: model that inserts it sees a node the DOM does not have.
TABLE_ONLY_STARTS = frozenset({
    "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr",
})

#: The tags a `<frameset>` owns.  `frame` measured dropped in all four contexts;
#: `frameset` itself is handled where it is noted as changing the model.
FRAMESET_ONLY_STARTS = frozenset({"frame"})

#: Start tags that switch the parser's `frameset-ok` flag off, so a `<frameset>`
#: after one of them is IGNORED -- no frameset element, no browsing context, and
#: a `<frame src="javascript:CODE">` inside it runs nothing.  Measured name by
#: name in `benchmark/probe_frameset_ok.py`: one served page per element
#: (`<html><NAME>` then a frameset holding `<frame src="javascript:__x()">`), a
#: hit meaning the frameset was still honoured -- 125 names, because a sample of
#: them is how the `<option>` rule was once written wrong.
#:
#: The names *absent* here are the other half of that measurement and the
#: surprising half: `<div>`, `<span>`, `<p>`, `<a>`, `<svg>`, `<math>`, `<menu>`,
#: the head metadata tags and `<caption>`/`<col>` all leave the flag alone, so a
#: frameset that follows one of them really is built.  `<textarea>`, `<xmp>` and
#: `<plaintext>` are listed although their raw text also swallows the payload:
#: `<html><xmp></xmp><frameset><frame src=javascript:CODE>` measured ignored, so
#: the tag clears the flag on its own.
#:
#: Character tokens clear it too (see `add_text`), which is why `<html>x<frameset>`
#: is dead while `<html><!--x--><frameset>` lives: a comment is not a character
#: token, whitespace-only text has its own rule, and text inside a `<template>`
#: is not body text -- measured honoured, unlike text inside `<svg>`.
FRAMESET_OK_KILLERS = frozenset({
    "area", "body", "br", "button", "dd", "dt", "embed", "hr", "iframe", "img",
    "input", "keygen", "li", "listing", "marquee", "object", "plaintext", "pre",
    "select", "table", "textarea", "xmp",
})

#: Elements whose presence means "a table is open" for the rule above.
TABLE_CONTEXT = frozenset({"table", "tbody", "thead", "tfoot", "tr"})

#: CSS animation events.  Both sides measured and they cancel out: an inline
#: `animation:` fires by itself only where the `@keyframes` rule actually exists,
#: and deciding that needs stylesheet resolution, which this module does not do.
#: So `_css_animation_state` declines; the name is kept here as the marker for
#: which it declines.
CSS_ANIMATION_EVENTS = frozenset({"onanimationstart", "onanimationend",
                                  "onanimationiteration"})

#: Elements the HTML spec makes focusable without help.  Anything else becomes
#: focusable with `tabindex`, which is why `_handler_state` has to test both --
#: a form-control-only list called `<span tabindex=1 autofocus onfocus=...>`
#: inert, and that shape fired in Chromium.
FOCUSABLE_CONTROLS = frozenset({
    "input", "button", "select", "textarea", "a", "area", "summary",
    "details", "dialog", "audio", "video", "object", "embed", "label",
    "legend", "option", "optgroup", "slot",
})

#: `on` + letters.  A NUL in a handler name becomes U+FFFD and a `<x one-error>`
#: style name is not a handler at all; both must be rejected before they can be
#: scored as an event.
_HANDLER_NAME_RE = re.compile(r"^on[a-z]+$")


#: What may legally appear inside each table-scope container.  Anything else is
#: **foster-parented**: inserted *before* the table rather than inside it.
#: This is not a cosmetic reordering -- it is the step that turns
#: `<math><mtext><table><mglyph><style><img onerror>` from inert into a live
#: vector, because moving the empty <table> out of the way lets the re-parse hit
#: the mglyph MathML exception (see `html_start`) and flip <style>'s namespace.
TABLE_SCOPE = frozenset({"table", "tbody", "thead", "tfoot", "tr"})
TABLE_OK_IN = {
    "table": {"caption", "col", "colgroup", "tbody", "tfoot", "thead", "tr",
              "td", "th", "form", "style", "script", "template", "slot"},
    "tbody": {"tr", "td", "th", "style", "script", "template", "slot"},
    "thead": {"tr", "td", "th", "style", "script", "template", "slot"},
    "tfoot": {"tr", "td", "th", "style", "script", "template", "slot"},
    "tr": {"td", "th", "caption", "style", "script", "template", "slot"},
}

#: Start tags the tree builder throws away outright while a <select> is open --
#: whether the insertion point is the select itself or an <option>/<optgroup>
#: inside it.  Measured per name (152 names x 4 contexts, both sinks) in
#: benchmark/results/option_probe.json.  This is deliberately NOT the spec's
#: list: the spec *pops the select closed* for caption/col/colgroup/tbody/
#: tfoot/th/thead/tr and re-processes them in body, Chromium discards the token.
SELECT_DROPPED = frozenset({
    "body", "caption", "col", "colgroup", "head", "html", "select", "tbody",
    "tfoot", "th", "thead", "tr",
})

#: The one measured name that leaves an open <select> entirely: it closes the
#: select and is then inserted outside it.
SELECT_EXITS = frozenset({"input"})

#: Names that close an open <option> (and <optgroup> for `optgroup`/`hr`) and
#: land in the select itself.  `option` closes only an open <option>, which is
#: what keeps `<optgroup><option>` an option *inside* the group.
SELECT_END_OPTION = frozenset({"option"})
SELECT_END_SCOPE = frozenset({"optgroup", "hr"})

#: The elements that *are* the option scope, i.e. what `optgroup` and `hr` close
#: down to.  Distinct from SELECT_END_SCOPE, which is the set of names that
#: trigger that close -- conflating the two is what left `<option><hr>` nested
#: in the option instead of landing in the select.
OPTION_SCOPE = frozenset({"option", "optgroup"})


# ---------------------------------------------------------------------------
# DOM
# ---------------------------------------------------------------------------

class Node:
    """Minimal element/document/fragment node."""

    __slots__ = ("kind", "name", "attrs", "parent", "children", "ns", "self_closing")

    def __init__(self, kind: str, name: str = "", ns: str = "html"):
        self.kind = kind                 # document | element | text | comment
        self.name = name
        self.attrs: list[tuple[str, str]] = []
        self.parent: Optional[Node] = None
        self.children: list[Node] = []
        self.ns = ns                     # html | svg | mathml
        self.self_closing = False

    # -- tree helpers ------------------------------------------------------
    def append(self, node: "Node") -> None:
        node.parent = self
        self.children.append(node)

    def get(self, attr: str) -> Optional[str]:
        al = attr.lower()
        for k, v in self.attrs:
            if k.lower() == al:
                return v
        return None

    def has_attr(self, attr: str) -> bool:
        return self.get(attr) is not None

    def walk(self) -> Iterable["Node"]:
        for c in self.children:
            yield c
            yield from c.walk()

    def __repr__(self) -> str:  # debugging aid; the fidelity harness reads it
        if self.kind == "text":
            return f"#text({serialize_text(self)!r})"
        if self.kind == "comment":
            return f"<!--{self.name!r}-->"
        return f"<{self.name}>"


# ---------------------------------------------------------------------------
# Character references
# ---------------------------------------------------------------------------

_NAMED = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
    "nbsp": " ", "tab": "\t", "newline": "\n", "colon": ":",
    "semi": ";", "sol": "/", "lparen": "(", "rparen": ")",
    "num": "#", "commat": "@", "period": ".",
    "excl": "!", "quest": "?", "plus": "+", "equals": "=",
    "lcub": "{", "rcub": "}", "lsqb": "[", "rsqb": "]",
    "bsol": "\\", "hyphen": "-", "lowbar": "_", "dollar": "$",
    "percnt": "%", "ast": "*", "copy": "©", "reg": "®",
    "amp;": "&", "lt;": "<", "gt;": ">",
}


def _decode_ref(s: str, i: int, in_attr: bool) -> tuple[str, int]:
    """Decode one character reference at s[i] ('&').  Returns (text, consumed)."""
    n = len(s)
    if i + 1 >= n or s[i + 1] != "#":
        j = i + 1
        while j < n and (s[j].isalnum()):
            j += 1
            if j - i > 32:
                break
        name = s[i + 1:j]
        if not name:
            return "&", 1
        # The named-reference matcher tries the longest known name first, and a
        # reference without ';' still decodes in text -- which is how
        # `&lt` (no semicolon) becomes '<' and then a live tag start.
        for ln in range(min(len(name), 31), 0, -1):
            cand = name[:ln]
            if cand in _NAMED:
                consumed = 1 + ln
                if j < n and s[i + 1 + ln] == ";":
                    consumed += 1
                return _NAMED[cand], consumed
        return "&", 1
    # numeric
    j = i + 2
    radix = 10
    if j < n and s[j] in "xX":
        radix = 16
        j += 1
    ds = j
    while j < n and (s[j] in "0123456789" if radix == 10
                     else s[j] in "0123456789abcdefABCDEF"):
        j += 1
    if j == ds:
        return "&", 1
    try:
        cp = int(s[ds:j], radix)
    except ValueError:
        return "&", 1
    if j < n and s[j] == ";":
        j += 1
    elif in_attr:
        # In an attribute value a bare `&` followed by alphanumerics is left
        # alone; the whole point is that `&lt` there is NOT '<'.
        pass
    if cp == 0:
        # `&#0;` / `&#x00;` decodes to U+FFFD, NOT to nothing.  Deleting it is
        # what turned `<a href="jav&#x00;ascript:...">` -- which Chromium holds as
        # `jav\ufffdascript:`, an inert relative URL -- into a live `javascript:`
        # URI in the sandbox.  Measured in benchmark/results/nul_probe.json.
        return "\ufffd", j - i
    if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
        return "", j - i
    try:
        return chr(cp), j - i
    except ValueError:
        return "", j - i


def decode_entities(s: str, in_attr: bool = False) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "&":
            t, consumed = _decode_ref(s, i, in_attr)
            out.append(t)
            i += consumed
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

class Token:
    __slots__ = ("kind", "name", "attrs", "data", "self_closing")

    def __init__(self, kind, name="", attrs=None, data="", self_closing=False):
        self.kind = kind          # start | end | text | comment | doctype
        self.name = name
        self.attrs = attrs or []
        self.data = data
        self.self_closing = self_closing

    def __repr__(self) -> str:
        return f"Token({self.kind},{self.name!r},{len(self.attrs)}a)"


def _skip_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] in " \t\n\r\f":
        i += 1
    return i


def _read_name(s: str, i: int, stop: str) -> tuple[str, int]:
    n = len(s)
    j = i
    while j < n and s[j] not in stop:
        j += 1
    return s[i:j], j


def _attr_value_end(s: str, i: int, quote: str) -> int:
    n = len(s)
    if quote:
        j = s.find(quote, i)
        return n if j < 0 else j
    j = i
    while j < n and s[j] not in " \t\n\r\f>":
        j += 1
    return j


def _comment(data: str) -> Node:
    """A comment node, with the NUL adjustment the tokenizer makes for it.

    `<!--a<NUL>b-->` holds `61 fffd 62` (benchmark/results/nul_probe.json).  It
    matters because comment text is re-serialised verbatim, so a raw NUL that
    survives here is fed to the *next* parse as bytes no browser ever produced --
    which is how a `-->`-escaping mXSS vector would be judged on fiction.
    """
    return Node("comment", data.replace("\x00", "\ufffd"))


def _close_rawtext(s: str, i: int, name: str) -> int:
    """Return the index where `</name` appears, tolerating `< / name` and
    `< /name` -- the slash-after-langle variants that bypass naive filters."""
    n = len(s)
    j = i
    low = name.lower()
    while j < n:
        k = s.find("<", j)
        if k < 0:
            return n
        m = k + 1
        # The slash is required.  Treating it as optional makes `<style>` close
        # on `<style`, i.e. on the payload's own nested start tag, and the whole
        # raw-text region collapses to nothing -- which is how `<noscript>` hosts
        # reported every RCDATA-breakout payload as inert.
        if m >= n or s[m] != "/":
            j = k + 1
            continue
        m += 1
        # The name may be any case and must be followed by ws / `>` / `/`.
        ln = 0
        while m + ln < n and ln < len(low) and s[m + ln].lower() == low[ln]:
            ln += 1
        if ln == len(low):
            after = s[m + ln] if m + ln < n else ">"
            if after in " \t\n\r\f/>":
                return k
        j = k + 1
    return n


# ---------------------------------------------------------------------------
# Tree construction
# ---------------------------------------------------------------------------

class Doc:
    """Parse result: the fragment root plus what the parser dropped or moved."""

    __slots__ = ("root", "notes")

    def __init__(self, root: Node, notes: Optional[list] = None):
        self.root = root
        self.notes = notes if notes is not None else []


def _svg_case(name: str) -> tuple[str, str]:
    """Foreign content adjusts a handful of tag names and camel-cases SVG
    elements.  Getting `foreignObject`/`annotation-xml` wrong changes whether a
    subtree is HTML or foreign, i.e. whether a payload is live."""
    low = name.lower()
    if low in ("foreignobject",):
        return "foreignObject", "svg"
    if low in ("desc", "title"):
        return low, "svg"
    return low, "svg"


#: SVG element names carry capitals, and the tree builder restores them from the
#: lowercased tag name it read: `<clippath>` becomes `clipPath`, `<fegaussianblur`
#: becomes `feGaussianBlur`.  Every row was measured by
#: `benchmark/probe_svg_case.py` (68 names, one element per page, compared against
#: Chromium's own `innerHTML` byte for byte), including the two halves that make
#: the table safe to use: `hatchpath`, `mpath`, `tspan` and 27 others really do
#: stay lowercase, and an already-capital input (`<viewBox>`, `<FEgaussianBlur>`)
#: is looked up by its lowercased form -- so the key column is what the tokenizer
#: produces and never the bytes as sent.
#:
#: This is not cosmetic.  A serialiser that prints a name the DOM does not hold
#: yields a second parse of a document that never existed, and mXSS is judged on
#: exactly that second parse.
_SVG_CASE = {
    "animatecolor": "animateColor",
    "animatemotion": "animateMotion",
    "animatetransform": "animateTransform",
    "clippath": "clipPath",
    "feblend": "feBlend",
    "fecolormatrix": "feColorMatrix",
    "fecomponenttransfer": "feComponentTransfer",
    "fecomposite": "feComposite",
    "feconvolvematrix": "feConvolveMatrix",
    "fediffuselighting": "feDiffuseLighting",
    "fedisplacementmap": "feDisplacementMap",
    "fedistantlight": "feDistantLight",
    "fedropshadow": "feDropShadow",
    "feflood": "feFlood",
    "fefunca": "feFuncA",
    "fefuncb": "feFuncB",
    "fefuncg": "feFuncG",
    "fefuncr": "feFuncR",
    "fegaussianblur": "feGaussianBlur",
    "feimage": "feImage",
    "femerge": "feMerge",
    "femergenode": "feMergeNode",
    "femorphology": "feMorphology",
    "feoffset": "feOffset",
    "fepointlight": "fePointLight",
    "fespecularlighting": "feSpecularLighting",
    "fespotlight": "feSpotLight",
    "fetile": "feTile",
    "feturbulence": "feTurbulence",
    "foreignobject": "foreignObject",
    "lineargradient": "linearGradient",
    "radialgradient": "radialGradient",
    "textpath": "textPath",
}

#: SVG attribute names are case-adjusted by the tree builder, not lowercased like
#: HTML ones: `<animate attributename=...>` reaches the DOM as `attributeName`,
#: and `innerHTML` prints the adjusted form.  The sandbox used to print what the
#: tokenizer read, which is why `svg-animate` was the largest remaining
#: serialisation family in `benchmark/sandbox_fidelity.py` (5 of its 6 contexts
#: diverged).  Every row is checked name by name against a real browser by
#: `benchmark/probe_svg_case.py`, so the table is a measurement and not a
#: recollection -- including the one MathML name, which is the only entry the
#: MathML side of the rule contributes.
_SVG_ATTR_CASE = {
    "attributename": "attributeName",
    "attributetype": "attributeType",
    "basefrequency": "baseFrequency",
    "baseprofile": "baseProfile",
    "calcmode": "calcMode",
    "clippathunits": "clipPathUnits",
    "diffuseconstant": "diffuseConstant",
    "edgemode": "edgeMode",
    "filterunits": "filterUnits",
    "glyphref": "glyphRef",
    "gradienttransform": "gradientTransform",
    "gradientunits": "gradientUnits",
    "kernelmatrix": "kernelMatrix",
    "kernelunitlength": "kernelUnitLength",
    "keypoints": "keyPoints",
    "keysplines": "keySplines",
    "keytimes": "keyTimes",
    "lengthadjust": "lengthAdjust",
    "limitingconeangle": "limitingConeAngle",
    "markerheight": "markerHeight",
    "markerunits": "markerUnits",
    "markerwidth": "markerWidth",
    "maskcontentunits": "maskContentUnits",
    "maskunits": "maskUnits",
    "numoctaves": "numOctaves",
    "pathlength": "pathLength",
    "patterncontentunits": "patternContentUnits",
    "patterntransform": "patternTransform",
    "patternunits": "patternUnits",
    "pointsatx": "pointsAtX",
    "pointsaty": "pointsAtY",
    "pointsatz": "pointsAtZ",
    "preservealpha": "preserveAlpha",
    "preserveaspectratio": "preserveAspectRatio",
    "primitiveunits": "primitiveUnits",
    "refx": "refX",
    "refy": "refY",
    "repeatcount": "repeatCount",
    "repeatdur": "repeatDur",
    "requiredextensions": "requiredExtensions",
    "requiredfeatures": "requiredFeatures",
    "specularconstant": "specularConstant",
    "specularexponent": "specularExponent",
    "spreadmethod": "spreadMethod",
    "startoffset": "startOffset",
    "stddeviation": "stdDeviation",
    "stitchtiles": "stitchTiles",
    "surfacescale": "surfaceScale",
    "systemlanguage": "systemLanguage",
    "tablevalues": "tableValues",
    "targetx": "targetX",
    "targety": "targetY",
    "textlength": "textLength",
    "viewbox": "viewBox",
    "viewtarget": "viewTarget",
    "xchannelselector": "xChannelSelector",
    "ychannelselector": "yChannelSelector",
    "zoomandpan": "zoomAndPan",
}

#: The same rule on the MathML side, and `definitionurl` -> `definitionURL` is
#: the only pair with a case difference worth modelling.
_MATHML_ATTR_CASE = {"definitionurl": "definitionURL"}


class _Parser:
    """HTML fragment parser, sized to the XSS question.

    State lives on the instance because the tokenizer's position has to move
    under the tree builder when it enters a raw-text content model -- `</script>`
    is found by the *tokenizer*, and the payload gets to choose where that is.
    """

    def __init__(self, html: str, fragment: bool = True):
        self.s = html
        self.n = len(html)
        self.i = 0
        self.root = Node("document", "#document")
        self.stack: list[Node] = [self.root]
        self.notes: list[str] = []
        # Fragment mode is `div.innerHTML = <a whole document>`, which is what a
        # client-side template sink does.  There, <html>/<head>/<body> are
        # dropped and their children land in the container -- measured, where
        # the browser's serialisation of the same bytes is
        # `<div>...</div>` with no body node at all.  Document mode is the
        # server's response, where a second <body> MERGES its attributes onto
        # the live one, and `<body onload=...>` reflected mid-page really runs.
        self.fragment = fragment
        # The HTML parser's `frameset-ok` flag, and the reason a `<frameset>` is
        # not simply "an element": a served page that already has body content
        # ignores the tag, so a `<frame src="javascript:CODE">` inside it opens
        # nothing.  Modelled from `benchmark/probe_frame.py` (which contexts
        # honour it) and `benchmark/probe_frameset_ok.py` (which tags clear it).
        # A fragment parse never builds one, so this only speaks for documents.
        self.frameset_ok = True

    # -- tree state ---------------------------------------------------------
    def current(self) -> Node:
        return self.stack[-1]

    def integration(self, node: Node) -> bool:
        """True when node is foreign but its CHILDREN parse as HTML."""
        lname = node.name.lower()
        if node.ns == "svg":
            return lname in SVG_HTML_INTEGRATION
        if node.ns == "mathml":
            if lname == "annotation-xml":
                return (node.get("encoding") or "").lower() in (
                    "text/html", "application/xhtml+xml")
            return lname in MATHML_TEXT_INTEGRATION
        return False

    def in_foreign(self) -> bool:
        cur = self.current()
        return cur.ns in ("svg", "mathml") and not self.integration(cur)

    def pop_foreign(self) -> None:
        """The break-out: the svg/math subtree closes and parsing continues in
        HTML.  probe_foreign.py shows the surviving shape -- `<svg></svg><img>`
        -- an empty svg followed by the HTML sibling.

        It stops at an integration point rather than at the nearest HTML element,
        and that difference is itself a vector: for `<math><mtext><mglyph>
        <style><img onerror>` the browser puts the live img **inside `mtext`**,
        as a sibling of `mglyph`.  Popping all the way to the document would
        mis-parent the node and change what is reachable."""
        while len(self.stack) > 1 and self.stack[-1].ns != "html" \
                and not self.integration(self.stack[-1]):
            self.stack.pop()

    def pop_to(self, name: str) -> bool:
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == name:
                del self.stack[k:]
                return True
        return False

    def close_scoped(self, name: str) -> None:
        """li/dd/dt/option/optgroup/td/th/tr close their siblings and a
        block-level start tag closes an open <p>.  Skipping this loses exactly
        the breakout `<noscript><p title="...` payloads rely on."""
        targets = AUTO_CLOSE.get(name)
        if targets:
            for k in range(len(self.stack) - 1, 0, -1):
                if self.stack[k].name in targets and self.stack[k].ns == "html":
                    del self.stack[k:]
                    return
        if name in P_CLOSERS:
            for k in range(len(self.stack) - 1, 0, -1):
                if self.stack[k].name == "p" and self.stack[k].ns == "html":
                    del self.stack[k:]

    def _imply_table_rows(self, name: str) -> None:
        """Create the <tbody>/<tr> the parser implies.  Chromium always shows
        `<table><tbody><tr><td>` in its serialisation even when the bytes said
        `<table><tr><td>`; a serialiser that omits tbody therefore disagrees
        with the browser on every table-shaped response, and the round-trip is
        what mXSS is judged by.  It does not change liveness -- the payload is
        live either way -- but it is 46 of the serialisation diffs."""
        cur = self.current()
        if cur.ns != "html":
            return
        if name == "tr" and cur.name == "table":
            tb = Node("element", "tbody", "html")
            cur.append(tb)
            self.stack.append(tb)
        elif name in ("td", "th"):
            if cur.name in ("table", "tbody", "thead", "tfoot"):
                if cur.name == "table":
                    tb = Node("element", "tbody", "html")
                    cur.append(tb)
                    self.stack.append(tb)
                    cur = self.current()
                tr = Node("element", "tr", "html")
                cur.append(tr)
                self.stack.append(tr)

    def foster_insert(self, node: Node) -> bool:
        """Insert `node` immediately before the open <table>, per foster parenting.

        Returns False when no table-scope element is open, i.e. this is not a
        foster-parenting situation.
        """
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == "table" and self.stack[k].ns == "html":
                tbl = self.stack[k]
                parent = tbl.parent
                if parent is None:
                    return False
                try:
                    at = parent.children.index(tbl)
                except ValueError:
                    at = len(parent.children)
                node.parent = parent
                parent.children.insert(at, node)
                return True
        return False

    def add_text(self, data: str, decode: bool = True) -> None:
        if not data:
            return
        if decode:
            data = decode_entities(data)
            # A NUL in ordinary document text is *dropped* -- `<p>a<NUL>b</p>`
            # holds `61 62`, not `61 fffd 62`.  RCDATA/RAWTEXT do the opposite
            # (see `consume_rawtext`), so the two paths must not share one rule;
            # both read from benchmark/results/nul_probe.json.
            data = data.replace("\x00", "")
        else:
            # Foreign content is not measured for NUL; left exactly as it was so
            # this change cannot move a foreign verdict on an unmeasured corner.
            data = data.replace("\x00", "\ufffd")
        if data.strip() and not any(st.ns == "html" and st.name == "template"
                                    for st in self.stack[1:]):
            # A character token with something in it closes the frameset window:
            # `<html>x<frameset>` measured ignored where
            # `<html><!--x--><frameset>` was honoured, and
            # `<html><svg>text</svg><frameset>` measured ignored too, so text in
            # FOREIGN content counts as well.  The one exemption the measurements
            # give is template contents: a frameset after
            # `<template>t</template>` is still built, because a template's
            # characters never become body text.  Whitespace-only runs do not
            # count, and neither do raw-text contents (style, title) -- those go
            # through `consume_rawtext`, and both measured honoured.
            self.frameset_ok = False
        self.current().append(Node("text", data))

    # -- tokenizer ----------------------------------------------------------
    def read_tag(self, j: int) -> tuple[Token, int]:
        s, n = self.s, self.n
        name, j = _read_name(s, j, " \t\n\r\f/>")
        # NUL becomes U+FFFD in a start-tag name, exactly as it does in an end
        # tag name and in an attribute name.  Dropping it made the OPEN tag the
        # one half of the pair where the bypass worked: `<scr<NUL>ipt>` really
        # creates an unknown element named `scr\ufffdipt` (measured code points
        # `73 63 72 fffd 69 70 74`, contents = plain text, nothing executes),
        # while the sandbox turned it into a live <script> whose `</scr<NUL>ipt>`
        # then failed to close -- a confirmed finding out of a dead payload.
        # See benchmark/results/nul_probe.json.
        name = name.lower().replace("\x00", "\ufffd")
        attrs: list[tuple[str, str]] = []
        self_closing = False
        while j < n:
            j = _skip_ws(s, j)
            if j >= n:
                break
            if s[j] == ">":
                j += 1
                break
            if s[j] == "/":
                if j + 1 < n and s[j + 1] == ">":
                    self_closing = True
                    j += 2
                    break
                j += 1
                continue
            an, j = _read_name(s, j, " \t\n\r\f/=><")
            if not an:
                j += 1
                continue
            # NUL becomes U+FFFD in an attribute name, so `sr<NUL>c=` is NOT
            # `src` -- the payload dies instead of bypassing the filter.
            an = an.replace("\x00", "\ufffd").lower()
            j = _skip_ws(s, j)
            val = ""
            if j < n and s[j] == "=":
                j = _skip_ws(s, j + 1)
                if j < n and s[j] in "\"'":
                    q = s[j]
                    e = _attr_value_end(s, j + 1, q)
                    val = decode_entities(s[j + 1:e], in_attr=True)
                    j = e + 1 if e < n else e
                else:
                    e = _attr_value_end(s, j, "")
                    val = decode_entities(s[j:e], in_attr=True)
                    j = e
            if not any(k == an for k, _ in attrs):
                attrs.append((an, val.replace("\x00", "\ufffd")))
        return Token("start", name, attrs, self_closing=self_closing), j

    def consume_rawtext(self, node: Node, name: str, decode: bool,
                        to_eof: bool = False) -> None:
        """Swallow content up to `</name` (or EOF for <plaintext>).

        The closer is supplied by the PAYLOAD in the RCDATA-breakout vectors,
        so this is the step that decides whether `</title><img ...>` is markup
        or a string of characters.
        """
        if to_eof:
            raw, self.i = self.s[self.i:], self.n
        else:
            end = _close_rawtext(self.s, self.i, name)
            raw = self.s[self.i:end]
            k = self.s.find(">", end)
            self.i = self.n if k < 0 else k + 1
        if decode:
            raw = decode_entities(raw)
        # RCDATA and RAWTEXT both turn a NUL into U+FFFD -- `<title>a<NUL>b</title>`
        # holds `61 fffd 62`, `<style>a<NUL>{...}` holds `61 fffd 7b` -- which is
        # the opposite of document text (see `add_text`).  Deleting it here is
        # what made a NUL-bearing title breakout serialise to different bytes than
        # the browser's, i.e. a round-trip judged on markup no browser ever held.
        raw = raw.replace("\x00", "\ufffd")
        if raw:
            node.append(Node("text", raw))
        if self.stack and self.stack[-1] is node:
            self.stack.pop()

    # -- content models -----------------------------------------------------
    def enter_content_model(self, node: Node, name: str) -> None:
        if name == "script" or name in RAWTEXT or name == "noscript":
            # <noscript> is raw text while scripting is enabled -- every browser
            # a scan runs against.  The vector family that depends on the
            # scripting-disabled form only bites after a round-trip.
            self.consume_rawtext(node, name, decode=False)
        elif name in RCDATA:
            self.consume_rawtext(node, name, decode=True)
        elif name in PLAINTEXT:
            self.consume_rawtext(node, name, decode=False, to_eof=True)

    # -- HTML content -------------------------------------------------------
    def html_start(self, tok: Token) -> None:
        name = tok.name
        if name == "image":
            # In HTML content `image` is renamed to `img` by the tree builder, so
            # `<image src=x onerror=CODE>` is a normal failing image and fires.
            # Left as `image` this element fell outside every onerror table and
            # the payload read as inert -- a missed detection, not a naming
            # quibble.  Inside <svg> the element really is SVG `image` and this
            # branch is not reached.  Measured in all four contexts of
            # benchmark/results/option_probe.json (browser chain `...>img`).
            name = tok.name = "img"
        if name in FRAMESET_OK_KILLERS:
            # Before the `html`/`head`/`body` early returns: `body` is one of
            # these names, and its branch would otherwise swallow the rule.
            self.frameset_ok = False
        if name in ("html", "head"):
            return
        if name == "body":
            if self.fragment:
                # A fragment parser keeps the children and discards the tag.
                return
            if any(st.name == "template" and st.ns == "html" for st in self.stack[1:]):
                # Template contents are parsed by their own rules, where
                # <html>/<head>/<body> are dropped -- so a reflected
                # <body onload> inside a <template> creates no body and fires
                # nothing (measured: the whole template serialises empty).
                return
            existing = None
            for c in self.root.children:
                if c.kind == "element" and c.name == "body":
                    existing = c
                    break
            if existing is None:
                b = Node("element", "body", "html")
                b.attrs = list(tok.attrs)
                self.root.append(b)
                # The body has to become the insertion point, not just a node in
                # the tree.  Without this every element of a served page landed
                # as a SIBLING of <body>, which kept liveness verdicts right by
                # accident (an img fires wherever it sits) while making every
                # ancestor-dependent rule -- select scope, table scope, foreign
                # integration, template -- read a flat tree.
                self.stack.append(b)
                return
            # Document mode: a second <body> merges its attributes onto the one
            # already open, for every name the first body did not carry.  This
            # is why `<body onload=CODE>` reflected into the middle of a page
            # executes -- measured live through the parser, inert through
            # innerHTML, so the two modes must not share this branch.
            have = {k for k, _ in existing.attrs}
            for k, v in tok.attrs:
                if k not in have:
                    existing.attrs.append((k, v))
            return
        if name == "frameset":
            if self.fragment:
                # Inside a fragment (`innerHTML`), a stray `<frameset>` is
                # discarded -- measured as dropped in the div/option/select
                # contexts of benchmark/results/option_probe.json, and as no
                # execution in every fragment arm of benchmark/probe_frame.py.
                return
            # In a *document* parse the frameset really is built, and a
            # `<frame src="javascript:CODE">` inside it executes -- measured, with
            # a positive control (a frame that loads a child document carrying the
            # handler), in benchmark/probe_frame.py.  But only while the page has
            # not committed to body content: `<html><frameset>` opens a browsing
            # context, `<html><body><frameset>` and `<html>x<frameset>` do not,
            # and treating those two alike was an OVER on every served page that
            # reflects below its own markup.  A frameset nested in an open
            # frameset is a different rule -- `in frameset` accepts it -- and a
            # second frameset at document level after one has been honoured is
            # not (`<frameset></frameset><frameset>` measured ignored).
            nested = any(st.ns == "html" and st.name == "frameset"
                         for st in self.stack[1:])
            if not (nested or self.frameset_ok):
                return
            self.frameset_ok = False
            fs = Node("element", "frameset", "html")
            fs.attrs = list(tok.attrs)
            self.current().append(fs)
            self.stack.append(fs)
            return
        if name in TABLE_ONLY_STARTS and not any(
                st.ns == "html" and st.name in TABLE_CONTEXT
                for st in self.stack[1:]):
            # No table open: the token is discarded, and no element of any kind
            # appears.  Doing this before `close_scoped` matters -- the implied
            # close those names do in table context must not happen here either.
            return
        if name in FRAMESET_ONLY_STARTS and not any(
                st.ns == "html" and st.name == "frameset"
                for st in self.stack[1:]):
            return
        self.close_scoped(name)
        # --- <select> scope, measured name by name ---------------------------
        # What follows is what `benchmark/probe_option.py` came back with over
        # 152 names x {div, select, option, optgroup} x both sinks, every shape
        # round-trip stable.  An element reflected into an <option> *stays
        # inside that option* -- 133 of the 152 measured names are not special
        # at all.  The rule this replaces hoisted every non-option name out of the
        # select, which is correct for exactly one name (`input`) and wrong for
        # the rest, and in document mode it also carried the content past
        # <body>, because popping "to select" popped the body with it.
        if any(st.name == "select" and st.ns == "html" for st in self.stack[1:]):
            if name in SELECT_DROPPED:
                return
            if name in SELECT_EXITS:
                # `<select><option><input autofocus onfocus=...>` really does
                # put a firing input beside the select rather than a buried one
                # inside it -- the measurement that started this branch.
                while len(self.stack) > 1:
                    popped = self.stack.pop()
                    if popped.name == "select" and popped.ns == "html":
                        break
            else:
                closers: Iterable[str] = ()
                if name in SELECT_END_OPTION:
                    closers = SELECT_END_OPTION
                elif name in SELECT_END_SCOPE:
                    closers = OPTION_SCOPE
                while self.current().ns == "html" \
                        and self.current().name in closers:
                    self.stack.pop()
        self._imply_table_rows(name)
        # <svg> and <math> are the entry doors to foreign content: everything
        # about break-out, integration points and CDATA depends on this node
        # carrying the right namespace, not on the tag name alone.
        ns = "svg" if name == "svg" else ("mathml" if name == "math" else "html")
        if name in ("mglyph", "malignmark") \
                and self.current().ns == "mathml" \
                and self.current().name in MATHML_TEXT_INTEGRATION:
            # The one exception to "children of a MathML text integration point
            # are HTML": <mglyph> and <malignmark> are created in the MathML
            # namespace even there.  Not cosmetic.  It is what makes a <style>
            # inside them a MathML element rather than an HTML raw-text element,
            # so the `<img>` written in it stops being text and becomes a live
            # tag on the NEXT parse -- the namespace flip that
            # benchmark/sanitizer_probe.py measured as a real mutation vector.
            ns = "mathml"
        node = Node("element", name, ns)
        if ns == "html" and name in TABLE_SCOPE \
                and any(st.ns == "mathml" and st.name in MATHML_TEXT_INTEGRATION
                        for st in self.stack[1:]):
            # Honest limit.  A table container opened inside a MathML text
            # integration point makes the foster-parenting rule interact with the
            # integration-point rule in a way this parser does not model: the
            # browser moves the mglyph subtree out of the table *and* lands it
            # under the integration point, and the payload fires on the FIRST
            # parse.  Measured over benchmark/mxss_family_probe.py (120 of 360
            # combinations), so the shape is recorded and `judge` refuses to call
            # it inert -- it says UNKNOWN and the browser gets asked.
            self.notes.append("table scope inside a MathML integration point "
                              "(foster parenting across that boundary not "
                              "modelled)")
        node.attrs = ([(_adjust_foreign_attr(an, ns), av)
                       for an, av in tok.attrs]
                      if ns != "html" else tok.attrs)
        cur = self.current()
        if cur.ns == "html" and cur.name in TABLE_SCOPE \
                and name not in TABLE_OK_IN.get(cur.name, set()) \
                and self.foster_insert(node):
            # Foster parenting: this element does not belong in the open table
            # container, so it goes *before* the table and the table stays empty.
            if name in VOID or tok.self_closing:
                return
            self.stack.append(node)
            self.enter_content_model(node, name)
            return
        cur.append(node)
        if name in VOID or tok.self_closing:
            return
        self.stack.append(node)
        self.enter_content_model(node, name)

    def html_end(self, name: str) -> None:
        if name in ("html", "body", "head"):
            return
        if name == "br":
            # `</br>` acts as `<br>`; only the serialised shape turns on it.
            self.current().append(Node("element", "br"))
            return
        if name == "p":
            if not self.pop_to("p"):
                # in-body `</p>` with no open <p> inserts one.  Reached by
                # `<svg></p>...` after the break-out (probe_foreign).
                p = Node("element", "p", "html")
                self.current().append(p)
            return
        self.pop_to(name)

    # -- main loop ----------------------------------------------------------
    def run(self) -> Doc:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c != "<":
                j = s.find("<", self.i)
                j = n if j < 0 else j
                data = s[self.i:j]
                # Foreign text does not consume character references: the two
                # `&lt;` payloads in the oracle are inert only because of that.
                if self.in_foreign():
                    self.add_text(data, decode=False)
                else:
                    self.add_text(data, decode=True)
                self.i = j
                continue

            nxt = s[self.i + 1] if self.i + 1 < n else ""

            if nxt == "!":
                if s[self.i:self.i + 4] == "<!--":
                    end = s.find("-->", self.i + 4)
                    if end < 0:
                        self.current().append(_comment(s[self.i + 4:]))
                        self.notes.append(
                            "unterminated comment swallowed the remainder")
                        return Doc(self.root, self.notes)
                    self.current().append(_comment(s[self.i + 4:end]))
                    self.i = end + 3
                    continue
                if s[self.i:self.i + 9].upper() == "<![CDATA[":
                    if self.in_foreign():
                        end = s.find("]]>", self.i + 9)
                        end = n if end < 0 else end
                        self.current().append(Node("text", s[self.i + 9:end]))
                        self.i = end + 3 if end < n else n
                        continue
                    # CDATA in HTML content is a bogus comment up to `>`.
                    end = s.find(">", self.i)
                    end = n if end < 0 else end
                    self.current().append(_comment(s[self.i + 2:end]))
                    self.i = end + 1
                    continue
                end = s.find(">", self.i)
                end = n if end < 0 else end
                self.current().append(_comment(s[self.i + 2:end]))
                self.i = end + 1
                continue

            if nxt == "/":
                nxt2 = s[self.i + 2] if self.i + 2 < n else ""
                if not ("a" <= nxt2.lower() <= "z"):
                    # `</` followed by anything that is not an ASCII letter is
                    # not an end tag at all -- it opens a BOGUS COMMENT that
                    # swallows everything up to the next `>`.  Skipping the
                    # whitespace first (as this used to) made `</ foreignObject>`
                    # look like a harmless close tag, so markup the browser keeps
                    # alive inside a comment vanished here, and `</</</OPTGROUP>`
                    # produced nothing.  Measured with the random differential
                    # fuzzer; the browser's own serialisation is
                    # `<!-- foreignObject-->`, `<!--]]-->`, `<!--</</OPTGROUP-->`.
                    k = s.find(">", self.i + 2)
                    if k < 0:
                        self.current().append(_comment(s[self.i + 2:]))
                        return Doc(self.root, self.notes)
                    self.current().append(_comment(s[self.i + 2:k]))
                    self.i = k + 1
                    continue
                j = _skip_ws(s, self.i + 2)
                name, j = _read_name(s, j, " \t\n\r\f/>")
                # Same rule as attribute names: NUL becomes U+FFFD, so
                # `</scr<NUL>opt>` does not close a <script>.  Dropping it here
                # would make end tags the one place the bypass works.
                name = name.lower().replace("\x00", "\ufffd")
                k = s.find(">", j)
                end_i = n if k < 0 else k + 1
                if not name:
                    # `</>` is a bogus comment.
                    self.i = end_i
                    continue
                if self.in_foreign():
                    cur = self.current()
                    if cur.name == name:
                        self.stack.pop()
                    elif self._pop_foreign_named(name):
                        pass
                    else:
                        # Unmatched end tag in foreign content breaks out and is
                        # reprocessed as HTML -- how `<svg></p><style>` yields
                        # live markup on the FIRST parse.
                        self.pop_foreign()
                        self.i = end_i
                        self.html_end(name)
                        continue
                    self.i = end_i
                    continue
                self.i = end_i
                self.html_end(name)
                continue

            if not nxt.isalpha():
                # `<?php`, a bare `<`, `< 3`: text or a bogus comment.
                k = s.find(">", self.i)
                if k < 0:
                    self.add_text(s[self.i:], decode=not self.in_foreign())
                    return Doc(self.root, self.notes)
                if nxt in ("?", "!"):
                    self.current().append(_comment(s[self.i + 1:k]))
                else:
                    self.current().append(Node("text", s[self.i:k + 1]
                                               .replace("\x00", "\ufffd")))
                self.i = k + 1
                continue

            tok, j = self.read_tag(self.i + 1)
            self.i = j
            if not tok.name:
                continue

            if self.in_foreign():
                if tok.name in FOREIGN_BREAK:
                    self.pop_foreign()
                    self.html_start(tok)
                    continue
                node = Node("element", _adjust_foreign(tok.name,
                                                       self.current().ns),
                            self.current().ns)
                node.attrs = [(_adjust_foreign_attr(an, self.current().ns), av)
                              for an, av in tok.attrs]
                self.current().append(node)
                # HTML void-ness does not cross into foreign content: `<base>`,
                # `<link>`, `<input>` are simply unknown SVG/MathML elements
                # there, they are not void, and they take children.  Measured --
                # Chromium nests the following `<a>` *inside* a foreign `<base>`
                # while the HTML void table would close it immediately.
                if not tok.self_closing:
                    self.stack.append(node)
                continue

            self.html_start(tok)

        return Doc(self.root, self.notes)

    def _pop_foreign_named(self, name: str) -> bool:
        for k in range(len(self.stack) - 1, 0, -1):
            if self.stack[k].name == name and self.stack[k].ns != "html":
                del self.stack[k:]
                return True
        return False


def _adjust_foreign(name: str, ns: str) -> str:
    if ns != "svg":
        return name
    return _SVG_CASE.get(name, name)


def _adjust_foreign_attr(aname: str, ns: str) -> str:
    """The foreign-content case adjustment for ATTRIBUTE names.

    Names arrive here already lowercased by the tokenizer, which is exactly the
    form the adjustment table is keyed on: `<animate ATTRIBUTENAME=...>`,
    `attributename` and `attributeName` all reach the DOM as `attributeName`.  A
    prefixed name (`xlink:href`) has no entry and stays as read.
    """
    if ns == "svg":
        return _SVG_ATTR_CASE.get(aname, aname)
    if ns == "mathml":
        return _MATHML_ATTR_CASE.get(aname, aname)
    return aname


def parse(html: str, fragment: bool = True) -> Doc:
    """Build a DOM from `html` the way a browser parser would.

    `fragment=True` is `div.innerHTML = html` (a client-side template sink);
    `fragment=False` is the document the server sent.  They differ on two
    measured points: the fragment parser throws away <html>/<head>/<body>
    themselves while keeping their children, and the document parser merges a
    second <body>'s attributes onto the live one -- which is the difference
    between inert and a real `<body onload=...>` finding.

    Not a full spec implementation: insertion behaviour is modelled where it
    changes whether markup ends up live (raw-text/RCDATA content models, foreign
    content and its break-out set, implicit <p> closing, <select>/<option>
    scoping, <template>) and skipped where it cannot.  What the parser could not
    decide lands in `notes`, and `judge()` turns that into UNKNOWN instead of a
    guess.
    """
    # Input preprocessing, before the tokenizer sees anything: every CRLF and
    # every lone CR becomes LF.  Measured, and it survives into the DOM -- an
    # attribute value written as `x="\r"` is read back and re-serialised as
    # `x="\n"` (benchmark/results/attr_escape.json), so modelling it here rather
    # than in the serialiser is what keeps the second round-trip honest.
    html = html.replace("\r\n", "\n").replace("\r", "\n")
    return _Parser(html, fragment=fragment).run()


# ---------------------------------------------------------------------------
# Serialisation (innerHTML-compatible)
# ---------------------------------------------------------------------------

def serialize_text(node: Node) -> str:
    data = node.name
    parent = node.parent
    # Only the HTML "no-escaping" elements (script/style/xmp/iframe/noembed/
    # noframes/plaintext/noscript) write their text out verbatim.  Foreign
    # content does NOT get an exemption: `<svg><![CDATA[<img ...>]]></svg>`
    # serialises as `<svg>&lt;img ...&gt;</svg>` (measured), and the &-only
    # shortcut the spec's wording tempts you into is what makes a CDATA payload
    # look like it mutates into a live tag on re-parse.  It does not.
    p = parent
    while p is not None:
        if p.kind == "element" and p.name in NO_ESCAPE_TEXT and p.ns == "html":
            return data
        if p.ns == "html":
            break
        p = p.parent
    return (data.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace(" ", "&nbsp;"))


def _is_integration(node: Node) -> bool:
    lname = node.name.lower()
    if node.ns == "svg" and lname in SVG_HTML_INTEGRATION:
        return True
    if node.ns == "mathml" and lname in MATHML_TEXT_INTEGRATION:
        return True
    return False


def _serialize_attr_value(v: str) -> str:
    # Exactly what Chromium escapes in an attribute value, measured character by
    # character across all three quoting styles
    # (benchmark/results/attr_escape.json): `&`, `"`, `<`, `>` and U+00A0 --
    # and *nothing else*.  Two directions were wrong here before:
    #   * tab / newline / carriage return were being turned into `&#9;` /
    #     `&#10;` / `&#13;`.  Chromium writes them raw, so inventing character
    #     references changes the bytes a round-trip is judged on.
    #   * U+00A0 was written raw, where Chromium emits `&nbsp;`.
    # Every other C0 control (0x01, 0x0C, 0x1F, measured) passes through unharmed,
    # so this is deliberately not "escape all controls".
    return (v.replace("&", "&amp;").replace('"', "&quot;")
             .replace("<", "&lt;").replace(">", "&gt;")
             .replace("\xa0", "&nbsp;"))


def serialize(node: Node) -> str:
    out: list[str] = []
    for c in node.children:
        if c.kind == "text":
            out.append(serialize_text(c))
        elif c.kind == "comment":
            out.append(f"<!--{c.name}-->")
        elif c.kind == "element":
            tag = c.name
            attrs = "".join(f' {k}="{_serialize_attr_value(v)}"'
                            for k, v in c.attrs)
            if c.ns == "html" and tag in VOID:
                out.append(f"<{tag}{attrs}>")
                continue
            out.append(f"<{tag}{attrs}>")
            out.append(serialize(c))
            out.append(f"</{tag}>")
    return "".join(out)


def roundtrip(html: str, times: int = 3) -> list[str]:
    """parse -> serialise -> parse -> ...  Returns each serialisation.

    Two consecutive entries that differ but yield a *different* liveness verdict
    is mutation XSS; the list is what makes that visible rather than guessed.
    """
    cur = html
    out: list[str] = []
    for _ in range(times):
        cur = serialize(parse(cur).root)
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# Liveness / verdict
# ---------------------------------------------------------------------------

class Verdict:
    __slots__ = ("state", "reason", "node", "activation", "evidence")

    def __init__(self, state: str, reason: str, node: Optional[Node] = None,
                 activation: bool = False, evidence: str = ""):
        self.state = state          # live | inert | unknown
        self.reason = reason
        self.node = node
        self.activation = activation
        self.evidence = evidence

    def __bool__(self) -> bool:
        return self.state == "live"

    def to_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason,
                "requires_activation": self.activation,
                "evidence": self.evidence}

    def __repr__(self) -> str:
        return f"Verdict({self.state},{self.reason!r})"


def _smil_state(el: Node, ev: str, nested: bool = False) -> tuple[str, str]:
    """Does a SMIL timing handler (`onbegin`/`onend`/`onrepeat`) ever start?

    The answer belongs to the *element*, its namespace and its `begin` value, not
    to the handler name.  Measured 23 shapes in both sinks, then re-measured
    across 20 reflection hosts (1200-row oracle):
    `<svg><animate onbegin=CODE>` executes within the load itself and again
    through innerHTML; the same attribute on a `<div>`, `<p>`, `<input>`, on the
    `<svg>` root, on the animation's target `<circle>`, or on `<discard>` never
    fires; `begin="indefinite"` never fires, `begin="mouseover"` waits for the
    mouse, and `begin="2s"` needs time rather than a gesture.
    """
    name = el.name.lower()
    # Namespace first, and the reflection hosts are what prove it: an
    # unquoted `class=<svg><animate onbegin=...>` swallows the `<svg>` into the
    # attribute value and leaves `<animate>` as an HTML element.  The browser's
    # own serialisation shows that shape and does not execute it -- an element
    # merely *named* animate has no SMIL timeline.
    if name in SMIL_TIMING_ELEMENTS and el.ns == "svg":
        if nested:
            # Decline, and here is what has been ruled OUT, because the obvious
            # explanations are all false (benchmark/results/smil_probe.json):
            #   * "nested timelines do not run" -- `<iframe srcdoc='...animate
            #     onbegin...attributeName="x"...'` executes, both arms.
            #   * "the quote truncation empties the handler" -- the outer parse
            #     is byte-identical to the browser's here, and the nested value
            #     really is `<svg><animate onbegin=__x() attributeName=`.
            #   * "an empty or absent attributeName kills the timeline" -- the
            #     same truncated markup in a complete document DOES fire:
            #     `attributeName=""`, bare `attributeName`, and no
            #     attributeName at all are all live.
            # What is left is a difference between an unterminated start tag at
            # the end of a nested document and the same markup in a complete one.
            # Nothing here explains it, so nothing claims a verdict either way.
            return "unknown", (f"{name}.{ev} in an attribute-parsed nested "
                               f"document: measured no-exec, unexplained")
        begin = (el.get("begin") or "").strip().lower()
        if not begin or _SMIL_CLOCK_RE.match(begin):
            return "live", (f"{name}.{ev} starts on its own "
                            f"(begin={begin or 'default'}, measured)")
        if begin == "indefinite":
            return "inert", (f'{name}.{ev}: begin="indefinite" only starts when '
                             f"a script calls beginElement()")
        if begin in SMIL_GESTURE_TRIGGERS:
            return "activation", f"{name}.{ev} waits for {begin}"
        return "unknown", f'{name}.{ev} with begin="{begin}" is not measured'
    if name in SMIL_TIMING_INERT or el.ns == "html":
        return "inert", (f"{name}.{ev} has no SMIL timeline of its own "
                         f"(measured no-exec)")
    return "unknown", f"{name}.{ev} is not measured on a {el.ns} element"


def _css_animation_state(el: Node, ev: str) -> tuple[str, str]:
    """`onanimationstart` needs a running animation, which is a CSS answer.

    Measured both sides: `<style>@keyframes k{...}</style>` plus an inline
    `animation:k 1s` fires with no interaction, while reflecting the *same two
    declarations* through an unquoted attribute or a `<style>` host fires nothing,
    because the `@keyframes` rule never comes into existence -- it is text.  An
    inline `animation:` therefore proves nothing by itself, and deciding which
    animation names a page's stylesheets define is outside this module.
    Declining is the only claim both measurements support.
    """
    return "unknown", (f"{el.name}.{ev} needs a running CSS animation whose "
                       f"@keyframes is actually defined; stylesheets are not "
                       f"resolved here")


def _handler_state(el: Node, attr: str, sink: str = "parser",
                   nested: bool = False) -> tuple[str, str]:
    """Can this on* handler fire without the user touching anything?

    Three things gate the answer, and a rule that checks only the handler name
    gets all three wrong:

      * the element.  `ontoggle` is a <details> event; on a div it never fires.
        Attribute-context payloads routinely move a handler onto the wrong
        element (an unquoted `class=` swallows `<details open ontoggle=...>`
        into the div's own attribute list), which is where the over-claims came
        from.
      * the trigger.  `onerror` needs a resource that can fail; `onfocus` needs
        `autofocus` on something focusable.
      * the sink.  `onload` on <svg>/<body> fires when the *document* loads and
        does not re-fire for a node a script inserted via innerHTML -- both
        measured, in benchmark/results/browser_dom_oracle.json.
    """
    ev = attr.lower()
    name = el.name.lower()
    # SMIL and CSS-animation events gate on the element and its own attributes,
    # not on the namespace, so they are settled before the foreign check --
    # `<animate>` is always in the SVG namespace, and the old blanket "not
    # measured" answer there is what left this whole payload family unjudged.
    if ev in SMIL_TIMING_EVENTS:
        return _smil_state(el, ev, nested)
    if ev in CSS_ANIMATION_EVENTS:
        return _css_animation_state(el, ev)
    st, why = _foreign_handler_state(el, ev, sink)
    if st:
        return st, why
    if ev == "onerror":
        if name not in AUTO_FIRING_EVENTS["onerror"]:
            return "activation", f"{name}.{ev} needs an element that can error"
        if name in ("source", "track"):
            # A <source>/<track> is only processed inside a media element (or
            # <picture>); on its own it never attempts a load, so there is no
            # error to fire.  `<track>` is the measured one: an unquoted
            # `class=<video><track onerror=CODE src=...>` leaves the track as a
            # child of the div, and the browser fetches nothing.
            parent = (el.parent.name.lower() if el.parent else "")
            if parent not in ("video", "audio", "picture"):
                return "inert", (f"{name}.onerror needs a <video>/<audio>/"
                                 f"<picture> parent; a bare {name} is never "
                                 f"processed")
            return "live", (f"{name}.onerror fires when the media source fails"
                            if name == "source" else
                            f"{name}.onerror fires when the track file fails")
        # No src/href means no fetch is ever attempted, so there is no error
        # event to fire.  This is what actually kills the `sr<NUL>c=` bypass:
        # the handler survives, but the attribute that would have failed to
        # load no longer exists under that name.
        # For most elements no src means no fetch and therefore no error event.
        # <source> is the exception, and it is the one a media-element payload
        # relies on: a <source> whose src is absent fires `error` anyway.
        src_attr = "href" if name in ("link", "iframe") else "src"
        src = el.get(src_attr)
        if src is None and name != "source":
            return "inert", (f"{name}.{ev} is present but {src_attr} is absent, "
                             f"so nothing is fetched and no error fires")
        if src == "":
            return "inert", (f"{name}.{ev} has an empty {src_attr}: no load is "
                             f"attempted, so no error fires")
        return "live", f"{name}.{ev} fires when the {src_attr} resource fails"
    if ev == "onload":
        resource_load = name in ("img", "iframe", "frame", "link", "script",
                                 "object", "embed")
        if name in ("svg", "body"):
            # Measured: live through the parser, inert through innerHTML.  A
            # document-load event has already happened by the time a template
            # sink inserts the node.
            if sink == "parser":
                return "live", f"{name}.{ev} fires when the document loads"
            return "inert", (f"{name}.{ev} is a document-load event and does not "
                             f"re-fire for a node inserted via innerHTML")
        if resource_load:
            return "live", f"{name}.{ev} fires when the resource loads"
        return "activation", f"{name}.{ev} may not fire on an injected node"
    if ev == "onfocus":
        # What makes an element focusable is `autofocus` plus focusability, and
        # focusability is NOT limited to form controls: `tabindex` makes any
        # element focusable.  Measured over benchmark/results/autofocus_probe.json
        # -- span / a / img / li / button / textarea / video / input all fire with
        # `tabindex=1 autofocus`, so restricting this list to form controls was a
        # false negative waiting for the first `<div tabindex=1 autofocus
        # onfocus=...>` payload (a staple) to come through.
        attrs = dict(el.attrs)
        focusable = name in FOCUSABLE_CONTROLS or "tabindex" in attrs
        if not focusable:
            return "inert", (f"{name}.onfocus cannot fire: no tabindex and "
                             f"{name} is not a focusable control")
        if "autofocus" not in attrs:
            return "activation", "onfocus needs focus (autofocus attribute absent)"
        if name == "div":
            # Measured the opposite way twice: every other element with the same
            # attributes fired, `div` did not, and the difference is not
            # something this module can explain.  Guessing "inert" here would
            # bury a common payload, so the contradiction is reported rather than
            # resolved by a coin flip.
            return "unknown", ("div with tabindex+autofocus measured inconsistently "
                               "against every other element; needs the browser")
        return "live", f"{name}.onfocus fires via autofocus (focusable element)"
    if ev in ("ontoggle", "onbeforetoggle"):
        if name != "details":
            return "inert", (f"{name}.{ev} cannot fire: toggle is a <details> "
                             f"event")
        if "open" in dict(el.attrs):
            return "live", f"details.{ev} fires for details[open]"
        return "activation", "ontoggle needs the element to be toggled"
    if ev in MEDIA_LOAD_EVENTS:
        if name not in MEDIA_EVENT_TARGETS:
            # A media event is dispatched to a media element; a `<div>` cannot be
            # its target.  Measured, not read off the spec: an unquoted
            # `class=<audio oncanplay=CODE ...>` never forms the `<audio>`, the
            # handler lands on the div, and the browser executes nothing.
            return "inert", (f"{name}.{ev}: media events are only dispatched to "
                             f"media elements (measured no-exec)")
        if name != "audio":
            return "activation", (f"{name}.{ev} is not measured; only the six "
                                  f"<audio> loading events were")
        src = (el.get("src") or "").strip()
        if not src:
            # Nothing is fetched, so the load never starts and no load event can
            # fire.  Measured in all six contexts: `<audio oncanplay=CODE>` with
            # no src is dead, and so is `src=""`.
            return "inert", (f"audio.{ev} has no src: nothing loads, so no load "
                             f"event fires (measured)")
        if ev == "onloadstart":
            # `loadstart` is the one event that does not care what happens next:
            # measured live both with a decodable data: URI *and* with a src that
            # 404s, because the attempt to load is the event.
            return "live", ("audio.onloadstart fires as soon as the load begins, "
                            "which a 404 does not prevent (measured)")
        # The rest of the family needs the resource to actually decode.  Measured:
        # live with a valid `data:audio/wav`, dead with the same markup pointing
        # at a missing file, and dead with an undecodable data: URI.  Whether a
        # reflected `src` loads is not a fact about the markup, so this declines
        # rather than guessing a direction.
        return "unknown", (f"audio.{ev} needs the src to load and decode; measured "
                           f"live with a decodable src and dead with a 404, so a "
                           f"URL cannot be judged from markup")
    if ev == "onscroll":
        return "activation", "onscroll needs scroll position restoration"
    return "activation", f"{name}.{ev} requires user interaction"


def _js_uri_state(el: Node, attr: str, value: str) -> tuple[str, str]:
    key = (el.name.lower(), attr.lower())
    if key in JS_URI_EXECUTES:
        return "live", f"{key[0]}.{key[1]}=javascript: executes (measured)"
    if key in JS_URI_ACTIVATION and key not in JS_URI_EXECUTES:
        return "activation", f"{key[0]}.{key[1]}=javascript: runs only when activated"
    if key in JS_URI_INERT:
        return "inert", f"{key[0]}.{key[1]}=javascript: measured no-exec in Chromium"
    return "unknown", f"{key[0]}.{key[1]}=javascript: not measured"


# Browsers strip ASCII control characters (and space) from a URL before the
# scheme is resolved, which is the whole of `jav&#x09;ascript:` and
# `javascript:`.  Match on the normalised value, never the raw one: a
# regex over the raw text cannot express "the parser deletes these bytes first".
_JS_URI_RE = re.compile(r"^javascript:", re.I)
# C0 controls (0x00-0x1F), space and DEL: removed by the URL parser
# before it looks at the scheme.
_URL_STRIP_SET = frozenset(chr(c) for c in list(range(0x00, 0x21)) + [0x7F])


def normalize_uri(value: str) -> str:
    """The scheme-relevant form of a URL attribute, after the byte deletions a
    browser performs before parsing it."""
    return "".join(ch for ch in value if ch not in _URL_STRIP_SET)

#: Characters after which a `/` opens a regex literal.  Missing a keyword here
#: (return, typeof, ...) only ever misreads a regex as division or the reverse,
#: and both land in "unknown" when the token is inside the span -- the safe
#: direction.  A word-boundary matcher would be more accurate and buys nothing
#: that a fallback to the browser does not already cover.
_REGEX_PREV_CHARS = frozenset("(,=:[!&|?{};+-*%<>~^\n\r")


def js_state_at(text: str, needle: str) -> str:
    """Where does `needle` sit inside a <script> body: code, string, comment,
    template, regex/unknown, or absent?

    This is the check that stops `<script>var a = "<img src=x onerror=T>"</script>`
    being reported as executable.  The token is present and a `<script>` element
    exists, so a tree-shaped rule alone says live -- but the bytes are inside a
    JS string literal and no code path reaches them.  `verifier` solved this by
    counting unescaped quotes and pattern-matching `alert(`, which over-fits to
    alert payloads; a linear scan of the real lexical states is both smaller and
    right, and it still reports a payload that *closes* the quote (`';fetch(1)`),
    because closing the quote is exactly what the scan observes.

    "unknown" is returned when the scan cannot decide -- a regex-vs-division
    ambiguity covering the token, or an unterminated construct.  Callers must
    treat that as "ask the browser", never as inert.
    """
    idx = text.find(needle)
    if idx < 0:
        return "absent"
    i = 0
    n = len(text)
    prev = ""
    state = "code"
    quote = ""
    while i < n:
        if i == idx:
            return state
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line-comment"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block-comment"
                i += 2
                continue
            if c in "'\"":
                state, quote = "string", c
                i += 1
                continue
            if c == "`":
                state, quote = "template", "`"
                i += 1
                continue
            if c == "/" and (prev == "" or prev in _REGEX_PREV_CHARS):
                j = _skip_regex(text, i)
                if j < 0:
                    return "unknown"
                if i < idx < j:
                    return "unknown"
                i = j
                continue
            if not c.isspace():
                prev = c
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if state == "line-comment" and c == "\n":
            state = "code"
        elif state == "block-comment" and c == "*" and nxt == "/":
            state = "code"
            i += 1
        elif state == "string" and (c == quote or c == "\n"):
            # A raw newline ends a JS string literal: an unterminated quote in
            # the payload is what turns data back into code.
            state, quote = "code", ""
        elif state == "template" and c == quote:
            state, quote = "code", ""
        elif state == "template" and c == "$" and nxt == "{":
            # `${...}` is code again -- the template-literal bypass.
            state, quote = "code", ""
            i += 1
        i += 1
    return "unknown" if state != "code" else "code"


def _skip_regex(text: str, i: int) -> int:
    """End index of a regex literal starting at text[i] == '/', or -1."""
    n = len(text)
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return -1
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            return j + 1
        j += 1
    return -1


def _in_template(el: Node) -> bool:
    """Inside an HTML <template>.  The namespace test is the whole point: a
    `<template>` created inside `<svg>` is an SVG element that happens to be
    spelled that way -- it has no content document, and a `<script>` under it is
    a plain SVG script the parser runs.  Measured: `<svg><style><template>
    <script>CODE` executes, `<template><script>CODE` does not."""
    p = el.parent
    while p is not None:
        if p.kind == "element" and p.name == "template" and p.ns == "html":
            return True
        p = p.parent
    return False


#: Element names that only exist as HTML behaviours.  Carrying one of these
#: names inside `<svg>`/`<math>` produces an element the HTML spec has nothing
#: to say about: it is not focusable, has no `open` state, does not load a
#: resource -- so a handler written on it never fires.  Each name here is a row
#: of benchmark/results/browser_dom_oracle.json where Chromium created the
#: element, kept the handler attribute, and executed nothing.
HTML_ONLY_ELEMENTS = frozenset({
    "input", "button", "select", "textarea", "details", "summary", "source",
    "video", "audio", "iframe", "frame", "object", "embed", "marquee",
    "keygen", "output", "progress", "meter", "form", "a", "img", "div", "p",
    "span", "table", "td", "tr", "option", "label", "legend", "dialog",
})

#: SVG elements that reference no resource, so `onload` has nothing that could
#: ever raise it.  Each name is a row of `benchmark/probe_svg_ns.py`: served in a
#: document, handler attached, sentinel never reached -- and unlike a click-gated
#: sink there is no interaction that changes the answer, so the False is the
#: bounded kind that licenses INERT rather than the one that hides a finding.
#: `<use onload>` and `<image onload>` are deliberately absent: both take an href,
#: so a load event is at least conceivable, and what was measured was a broken
#: reference (`href="/nope"`, `xlink:href="#nope"`).  A broken reference proves
#: the failure path, not that a resolving one stays quiet.
SVG_UNLOADABLE_ELEMENTS = frozenset({
    "desc", "g", "clippath", "ellipse", "filter", "lineargradient", "path",
    "foreignobject",
})


def _foreign_handler_state(el: Node, ev: str, sink: str) -> tuple[str, str]:
    """Handler on an element in the svg/mathml namespace; ('', '') if not.

    Foreign content is where reflected-XSS claims go to die quietly: the
    attribute survives, the element is in the tree, and nothing can ever raise
    the event.  `<svg onload>` is the exception that is actually loadable, and
    it is measured as executing.
    """
    if el.ns == "html":
        return "", ""
    name = el.name.lower()
    if ev == "onload" and name in ("svg", "math"):
        # Measured, and the split is not intuitive: a fresh `<svg onload>`
        # reaching the page through the parser fires; the same element inserted
        # through innerHTML does not (its document already loaded) *unless* it is
        # nested inside another element of its own namespace, where it is a new
        # SVG document root and does fire.  `<math><mtext><svg onload>` is the
        # near-miss: an HTML-integration-point ancestor is not the same thing.
        if sink == "parser":
            return "live", (f"{el.ns}<{name}> load event fires when the document "
                            f"parses it (measured)")
        p = el.parent
        while p is not None:
            if p.kind == "element" and p.ns == el.ns:
                return "live", (f"nested <{name}> inside another {el.ns} element "
                                f"starts its own load (measured)")
            p = p.parent
        return "inert", (f"{el.ns}<{name}> inserted via innerHTML: its document "
                         f"has already loaded, so onload never fires (measured)")
    if name in HTML_ONLY_ELEMENTS:
        return "inert", (f"<{name}> here is in the {el.ns} namespace, so it "
                         f"implements none of the HTML behaviour that would "
                         f"raise {ev} (measured no-exec)")
    if ev == "onload" and name in SVG_UNLOADABLE_ELEMENTS:
        # Nothing behind these elements can finish loading, so the event has no
        # source at all -- and no gesture raises it either, which is what makes
        # the measured False a real inert instead of the bounded kind.
        return "inert", (f"<{name}> in the {el.ns} namespace loads nothing, so "
                         f"onload is never raised (measured)")
    return "unknown", (f"{name}[{ev}] in the {el.ns} namespace is not "
                       f"measured, and foreign elements do not inherit HTML "
                       f"event rules")


def _js_parses(body: str, wrapped: bool = False) -> Optional[bool]:
    """Can the JS engine even compile this?  None means "no parser available".

    Reflected markup inside a <script> block, or inside an inline handler, is
    only code if it *parses*.  `<script><img src=x onerror=T></script>` puts the
    token at code position and still runs nothing: `<img ...>` is a syntax
    error, the script never compiles, and the browser reports the error instead
    of executing.  Claiming that shape is the largest single source of reflected
    XSS false positives in the payloads a scanner likes best, and only a JS
    parser can settle it -- so `esprima` moves from optional to expected here.
    """
    if _esprima is None or len(body) > 20000:
        return None
    src = f"function __h(){{ {body} }}" if wrapped else body
    try:
        _esprima.parseScript(src, tolerant=False)
    except Exception:
        return False
    return True


#: Callees whose argument, if it carries the token, proves the token was
#: *reached*.  Deliberately the same family `verifier.mark()` stamps tokens
#: into: the token only means anything inside the call the scanner wrote it
#: into, so "is it an argument of any call at all" is the wrong question.
#: `console.log("...TOKEN...")` is a call carrying the token and it proves
#: nothing but that a string was printed -- measured the hard way, when that
#: reading turned the defended cases `neg-js-02` and `neg-sanitizer-01` into
#: false positives.
_EXECUTING_CALLEES = frozenset({
    "alert", "confirm", "prompt", "eval", "setTimeout", "setInterval",
    "Function", "write", "writeln", "unescape",
})


def _callee_name(callee) -> str:
    """`alert`, `window.alert`, `top.alert`, `document.write` -> last segment."""
    if not isinstance(callee, dict):
        return ""
    while callee.get("type") == "MemberExpression":
        callee = callee.get("property") or {}
    if isinstance(callee, dict) and callee.get("type") == "Identifier":
        return callee.get("name") or ""
    return ""


def _token_in_executing_call(body: str, token: str) -> str:
    """Is the token an argument of a call that would *demonstrate* execution?

    Returns "call", "data", or "no-parser".

    "The token sits inside a string literal" is not the same as "the token is
    data".  `alert('TOKEN')` puts the token in a string *and* executes it, which
    is the payload landing exactly where it was meant to land.  Reading the
    lexical state alone calls that inert -- and that cost the benchmark's
    `pos-cdata-01` a false negative on the first run of the gate that wraps this
    module, because the confirming payload was
    `]]></script><script>alert('TOKEN')</script><![CDATA[`.

    The opposite error is just as costly, and was the second lesson: the callee
    has to belong to the family markers are stamped into, not merely be callable.

    "no-parser" is returned only when the decision needs a JS parser that is not
    installed; the caller must then answer UNKNOWN, because a veto it cannot
    justify is worse than no veto at all.
    """
    if _esprima is None or len(body) > 20000:
        return "no-parser"
    idx = body.find(token)
    if idx < 0:
        return "data"
    span = (idx, idx + len(token))
    try:
        tree = _esprima.parseScript(body, range=True)
        data = json.loads(json.dumps(tree.toDict()))
    except Exception:
        return "no-parser"
    found = [False]

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") in ("CallExpression", "NewExpression"):
                r = node.get("range")
                if r and r[0] <= span[0] and span[1] <= r[1] \
                        and _callee_name(node.get("callee")) in \
                        _EXECUTING_CALLEES:
                    found[0] = True
                    return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return "call" if found[0] else "data"


def _script_candidate(el: Node, body: str, token: str, sink: str,
                      inert_host: bool) -> dict:
    """Decide a <script> element.

    Two independent reasons a script does not run, and a scanner that knows only
    one of them reports the other's cases as findings:

      * the sink.  A script element created by `innerHTML` is inserted but never
        started -- measured no-exec, and a serialise/re-parse round-trip does not
        change it (`div.innerHTML = <script>CODE` stays no-exec).
      * the position.  The token may be inside a JS string literal or a comment,
        where it is data, not code.
    """
    if inert_host:
        return {"node": "script[template]", "state": "inert",
                "why": "script inside <template> content never executes", "el": el}
    if el.get("src"):
        return {"node": "script[src]",
                "state": "live" if sink == "parser" else "inert",
                "why": "external script fetched by the parser; an innerHTML-"
                       "inserted script element is never started",
                "el": el}
    if sink != "parser":
        return {"node": "script[inert-sink]", "state": "inert",
                "why": "script created via innerHTML never executes (measured)",
                "el": el}
    # Nothing in a script that fails to compile executes -- not the part before
    # the error either.  Reflected markup that never broke out of its container
    # lands here, and this is the single largest family of reflected-XSS
    # over-claims.  Checked first, so the position analysis below only ever runs
    # on a body the engine will actually execute.
    compiles = _js_parses(body)
    if compiles is False:
        return {"node": "script[syntax-error]", "state": "inert",
                "why": "the script body is not valid JavaScript: markup "
                       "reflected into a script block without breaking out of "
                       "it is a syntax error, and nothing in the block runs",
                "el": el}
    pos = js_state_at(body, token) if token else "code"
    if pos == "code":
        return {"node": "script", "state": "live",
                "why": "<script> body reached by the parser, token at code "
                       "position" + ("" if compiles else " (JS validity "
                                                    "unchecked)"), "el": el}
    if pos == "unknown":
        return {"node": "script[undecided]", "state": "unknown",
                "why": "cannot tell code from regex/comment position at the "
                       "token; needs the browser", "el": el}
    # The token is inside a string / comment / template literal.  Whether that is
    # data or the payload landing exactly where it was meant to land is a
    # question about the syntax tree, not about quoting: `alert('TOKEN')`
    # executes, `var a = 'TOKEN'` does not.
    role = _token_in_executing_call(body, token) if token else "no-parser"
    if role == "call":
        return {"node": "script[argument]", "state": "live",
                "why": "token is an argument of the alert-family call the script "
                       "reaches: the literal is the payload landing where it was "
                       "meant to", "el": el}
    if role == "no-parser":
        return {"node": "script[undecided]", "state": "unknown",
                "why": "token sits in a JS literal whose role cannot be decided "
                       "without a JS parser installed (esprima); needs the "
                       "browser", "el": el}
    return {"node": "script[data]", "state": "inert",
            "why": f"token sits in a JS {pos} literal that is data, not a call "
                   f"argument, and the payload never breaks out of it",
            "el": el}


def find_live_nodes(root: Node, token: str = "", *,
                    nested: bool = False,
                    sink: str = "parser") -> tuple[str, list[dict]]:
    """Classify every candidate execution point in the tree.

    `sink` is not cosmetic.  A `<script>` element created by the *parser*
    executes; the same element created by `innerHTML` does not, ever, and a
    round-trip does not change that (both measured).  Reporting an inert
    script element as a finding is the single most common reflected-XSS false
    positive in the wild, and it is why the verdict carries its sink.

    Returns (worst_state, details) where worst_state folds live > unknown >
    activation > inert.
    """
    cands: list[dict] = []
    for el in root.walk():
        if el.kind != "element":
            continue
        name = el.name.lower()
        inert_host = _in_template(el)
        for an, av in el.attrs:
            al = an.lower()
            if not isinstance(av, str):
                av = " ".join(str(x) for x in av) if av else ""
            # `on` + letters only.  A U+FFFD from a NUL, or an `one-*`-style
            # name, is not an event handler and must not be scored as one.
            if _HANDLER_NAME_RE.match(al):
                if token and token not in av:
                    continue
                if inert_host:
                    cands.append({"node": f"{name}[{al}]", "state": "inert",
                                  "why": "handler inside <template> content "
                                         "is never rendered or run", "el": el})
                    continue
                st, why = _handler_state(el, al, sink, nested)
                if st == "live":
                    # An inline handler is compiled as a function body at parse
                    # time.  If the value does not compile -- typically because
                    # the attribute was truncated by its own quote and the tail
                    # landed outside it -- the handler is dead on arrival, which
                    # is why "the token is in an onerror= value" is not by
                    # itself a finding.
                    compiles = _js_parses(av, wrapped=True)
                    if compiles is False:
                        st = "inert"
                        why = (f"{name}.{al} value is not valid JavaScript "
                               f"(truncated by its own quote, or markup rather "
                               f"than code), so the handler never compiles")
                cands.append({"node": f"{name}[{al}]", "state": st, "why": why,
                              "el": el})
            elif al in ("href", "src", "action", "formaction", "data", "code",
                        "xlink:href") and _JS_URI_RE.match(normalize_uri(av or "")):
                if token and token not in av:
                    continue
                st, why = _js_uri_state(el, al, av)
                cands.append({"node": f"{name}[{al}]", "state": st, "why": why,
                              "el": el})
            elif al == "srcdoc" and name == "iframe" \
                    and el.ns == "html":
                # Only an iframe's `srcdoc` is a nested document.  A `<frame>`
                # does not have the attribute -- `<frame srcdoc="<img onerror=...>">`
                # measured no execution, because the frame gets no `src` and loads
                # about:blank (benchmark/probe_frame.py).  And in an unquoted
                # attribute context a payload's `srcdoc=` lands on a div instead,
                # and a div.srcdoc parses nothing -- claiming it "executes in a
                # nested document" is an over-statement.
                if token and token not in av:
                    continue
                if inert_host:
                    cands.append({"node": f"{name}[srcdoc]", "state": "inert",
                                  "why": "srcdoc inside <template> content is "
                                         "never instantiated", "el": el})
                    continue
                sub = parse(av or "", fragment=False)
                st, _sub = find_live_nodes(sub.root, token, sink="parser",
                                            nested=True)
                cands.append({"node": f"{name}[srcdoc]",
                              "state": st,
                              "why": "srcdoc value is parsed as a whole document"
                                     if st == "live" else
                                     "srcdoc value carries no live node",
                              "el": el})
        if name == "script":
            body = "".join(c.name for c in el.children if c.kind == "text")
            if not token or token in body:
                cands.append(_script_candidate(el, body, token, sink,
                                               inert_host))
                continue

    if not cands:
        return "inert", []
    order = {"live": 0, "unknown": 1, "activation": 2, "inert": 3}
    cands.sort(key=lambda c: order.get(c["state"], 4))
    worst = cands[0]["state"]
    return worst, cands


def judge(html: str, token: str = "", *, sink: str = "parser") -> Verdict:
    """Decide whether `html` (as served, or as re-parsed by a DOM sink) is live.

    `token` scopes the search to the payload we reflected, so an unrelated
    handler already present on the page cannot be credited to our payload.
    """
    if sink not in ("parser", "innerhtml"):
        raise ValueError(f"unknown sink {sink!r}")
    # The sink selects the parser, not just a scoring rule: a document parse and
    # a fragment parse disagree about <body>, and both measurements are in the
    # oracle.
    doc = parse(html, fragment=(sink == "innerhtml"))
    if token and token not in html:
        return Verdict("inert", "token absent from the document")
    state, detail = find_live_nodes(doc.root, token, sink=sink)
    if not detail:
        why = "no executable node carries the token"
        if doc.notes:
            return Verdict("unknown", "; ".join(doc.notes))
        return Verdict("inert", why)
    top = detail[0]
    ev = "; ".join(f"{d['node']} {d['state']} ({d['why']})" for d in detail[:4])
    if state == "live":
        return Verdict("live", top["why"], top["el"], False, ev)
    if state == "activation":
        return Verdict("live", top["why"], top["el"], True, ev)
    if state == "unknown":
        return Verdict("unknown", top["why"], None, False, ev)
    # INERT is the only verdict here that *costs* something to get wrong -- it
    # tells the scanner to stop looking, and (via the verify gate) it can retract
    # a confirmation.  So a parse that met something it had to note as
    # un-modelled may not conclude inert, even when a candidate was found and
    # each candidate looked dead.  Measured: the table-scope-inside-MathML shapes
    # were browser-live on the FIRST parse while every candidate read as inert,
    # and only this rule turns that from a wrong answer into a deferred one.
    if doc.notes:
        return Verdict("unknown", "parser met a construct it does not model: "
                       + "; ".join(doc.notes[:3]), None, False, ev)
    return Verdict("inert", "every token-bearing sink is inert: "
                   + "; ".join(f"{d['node']} {d['why']}" for d in detail[:3]),
                   None, False, ev)


def judge_roundtrip(html: str, token: str = "", *,
                    sink: str = "innerhtml", depth: int = 3) -> Verdict:
    """The mXSS question: does the payload become live only after the browser
    serialises and re-parses it?

    Each iteration is the real thing: parse -> serialise -> parse the
    serialisation.  A verdict that flips inert -> live at any depth is a
    mutation vector; that flip is what `mxss_verify` currently pays a browser
    launch for.
    """
    cur = html
    best = Verdict("inert", "no round-trip produced a live node")
    trail: list[tuple[str, str]] = []
    for k in range(depth):
        v = judge(cur, token, sink=sink)
        trail.append((f"round{k + 1}", f"{v.state}:{v.reason}"))
        if v.state == "live":
            if k == 0:
                return v
            v.evidence = (v.evidence or "") + " |MUTATED " + " ; ".join(
                f"{a}:{b}" for a, b in trail)
            return v
        if v.state == "unknown":
            best = v
        cur = serialize(parse(cur).root)
    return best


# ---------------------------------------------------------------------------
# Host templates for the CLI: mirrors benchmark/browser_dom_oracle.py
# ---------------------------------------------------------------------------

HOSTS = {
    "text": "<div>__P__</div>",
    "attr_dq": '<div class="__P__">t</div>',
    "attr_sq": "<div class='__P__'>t</div>",
    "attr_unq": "<div class=__P__>t</div>",
    "title": "<title>__P__</title>",
    "textarea": "<textarea>__P__</textarea>",
    "style": "<style>__P__</style>",
    "svg_style": "<svg><style>__P__</style></svg>",
    "math_mtext": "<math><mtext>__P__</mtext></math>",
    "script_dq": '<script>var a = "__P__";</script>',
    "script_block": "<script>__P__</script>",
    "comment": "<!--__P__-->",
    "noscript": "<noscript>__P__</noscript>",
    "xmp": "<xmp>__P__</xmp>",
    "template": "<template>__P__</template>",
    "table_td": "<table><tr><td>__P__</td></tr></table>",
    "select": "<select><option>__P__</option></select>",
    "event_dq": '<img src="__P__" alt="a">',
    "href_dq": '<a href="__P__">t</a>',
    "iframe_srcdoc": '<iframe srcdoc="__P__"></iframe>',
}


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="xssentinel.core.sandbox",
        description="Offline HTML sandbox: is this reflected payload live?")
    ap.add_argument("--payload", help="payload to evaluate")
    ap.add_argument("--host", default="text",
                    help=f"reflection context: {', '.join(sorted(HOSTS))}")
    ap.add_argument("--token", default="",
                    help="marker the payload reflects (default: the payload itself)")
    ap.add_argument("--sink", default="parser", choices=("parser", "innerhtml"))
    ap.add_argument("--file", help="judge a whole saved response body instead")
    ap.add_argument("--roundtrip", action="store_true",
                    help="also parse->serialise->re-parse (mXSS)")
    args = ap.parse_args(argv)

    if args.file:
        html = open(args.file, "r", encoding="utf-8", errors="replace").read()
    elif args.payload:
        html = HOSTS[args.host].replace("__P__", args.payload) \
            if args.host in HOSTS else args.payload
    else:
        ap.error("--payload or --file is required")

    token = args.token or (args.payload[:24] if args.payload else "")
    v = judge(html, token, sink=args.sink)
    print(f"sink={args.sink}  state={v.state.upper()}  activation={v.activation}")
    print(f"  why     : {v.reason}")
    print(f"  evidence: {v.evidence[:300]}")
    if args.roundtrip:
        r = judge_roundtrip(html, token, sink=args.sink)
        print(f"round-trip: state={r.state.upper()}  {r.reason}")
        for k, ser in enumerate(roundtrip(html)):
            print(f"  ser{k + 1}: {ser[:220]}")
    return 0 if v.state != "unknown" else 2


if __name__ == "__main__":
    raise SystemExit(main())
