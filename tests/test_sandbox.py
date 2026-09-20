# -*- coding: utf-8 -*-
"""The pure-Python HTML sandbox: every assertion here is a browser measurement.

`xssentinel/core/sandbox.py` claims to know what Chromium does with reflected
markup.  These tests lock the parts of that claim that were confirmed against
the browser itself -- the serialisation shapes come from
`benchmark/probe_foreign.py` and the execute/no-execute facts from
`benchmark/browser_dom_oracle.json` and `benchmark/sink_execution.py`.  A rule
added here without one of those behind it is a guess wearing a test.

Run:  pytest tests/test_sandbox.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import sandbox as sb  # noqa: E402

X = "__x()"          # the oracle's quote-free sentinel
NUL = "\x00"


def ser(html: str) -> str:
    return sb.serialize(sb.parse(html).root)


def live(html: str, sink: str = "parser", token: str = X) -> str:
    v = sb.judge(html, token, sink=sink)
    return v.state + ("+activation" if v.activation else "")


# ---------------------------------------------------------------------------
# Foreign content: the shapes probe_foreign.py recorded byte for byte
# ---------------------------------------------------------------------------

# Chromium's own innerHTML output, captured from a real browser.  The sandbox
# has to agree because the *round-trip* is what mXSS is judged on; a serialiser
# that diverges here cannot model mutation at all.
BROWSER_SERIALISATION = [
    (f'<svg><style><img src=x onerror="{X}"></style></svg>',
     f'<svg><style></style></svg><img src="x" onerror="{X}">'),
    (f'<svg><img src=x onerror="{X}"></svg>',
     f'<svg></svg><img src="x" onerror="{X}">'),
    (f'<svg><span><img src=x onerror="{X}"></span></svg>',
     f'<svg></svg><span><img src="x" onerror="{X}"></span>'),
    (f'<svg><text><img src=x onerror="{X}"></text></svg>',
     f'<svg><text></text></svg><img src="x" onerror="{X}">'),
    (f'<math><mi><img src=x onerror="{X}"></mi></math>',
     f'<math><mi><img src="x" onerror="{X}"></mi></math>'),
    (f'<svg><title><img src=x onerror="{X}"></title></svg>',
     f'<svg><title><img src="x" onerror="{X}"></title></svg>'),
    (f'<svg></p><style><a id="</style><img src=x onerror={X}>">',
     f'<svg></svg><p></p><style><a id="</style><img src="x" '
     f'onerror="{X}">"&gt;'),
    (f'<noscript><p title="</noscript><img src=x onerror={X}>">',
     f'<noscript><p title="</noscript><img src="x" onerror="{X}">"&gt;'),
    (f'<xmp><noscript></xmp><img src=x onerror={X}>',
     f'<xmp><noscript></xmp><img src="x" onerror="{X}">'),
]


def test_serialisation_matches_chromium_on_probed_shapes():
    for html, want in BROWSER_SERIALISATION:
        got = ser(html)
        assert got == want, f"\n got  {got}\n want {want}"


def test_svg_and_math_open_foreign_content_not_plain_html():
    """`<svg>` in HTML content must carry the svg namespace: that is what makes
    `<style>` inside it a non-raw-text element and `<img>` inside it a
    break-out.  Losing the namespace silently turns every foreign rule off."""
    doc = sb.parse("<svg><style>x</style></svg>")
    svg = doc.root.children[0]
    assert svg.name == "svg" and svg.ns == "svg"
    assert svg.children[0].name == "style"
    assert svg.children[0].ns == "svg"
    assert svg.children[0].children[0].kind == "text"


def test_style_inside_svg_is_not_raw_text():
    """The 'classic mXSS' premise in xssentinel/core/mutation.py is that
    `<svg><style><img onerror>` needs a round-trip to bite.  Measured: the img
    breaks out of foreign content on the FIRST parse and is live.  Reporting it
    as mutation-only is a false negative dressed up as sophistication."""
    html = f'<svg><style><img src=x onerror="{X}"></style></svg>'
    assert live(html, "innerhtml") == "live"
    assert sb.judge(html, X, sink="innerhtml").activation is False


def test_mathml_text_integration_point_keeps_children_html():
    html = f'<math><mtext><img src=x onerror="{X}"></mtext></math>'
    assert live(html, "innerhtml") == "live"
    assert f'<img src="x" onerror="{X}"' in ser(html)


# ---------------------------------------------------------------------------
# Context is what decides, not the payload
# ---------------------------------------------------------------------------

PAYLOAD = f'<img src=x onerror={X}>'


def test_same_payload_live_in_text_inert_in_every_container_that_eats_it():
    assert live(f"<div>{PAYLOAD}</div>") == "live"
    # attribute value: the `<` never opens a tag
    assert live(f'<div class="{PAYLOAD}">t</div>') == "inert"
    assert live(f"<div title='{PAYLOAD}'>t</div>") == "inert"
    # RCDATA / RAWTEXT: content is text until the matching close tag
    assert live(f"<title>{PAYLOAD}</title>") == "inert"
    assert live(f"<textarea>{PAYLOAD}</textarea>") == "inert"
    assert live(f"<style>{PAYLOAD}</style>") == "inert"
    assert live(f"<xmp>{PAYLOAD}</xmp>") == "inert"
    assert live(f"<iframe>{PAYLOAD}</iframe>") == "inert"
    assert live(f"<noscript>{PAYLOAD}</noscript>") == "inert"
    # comment
    assert live(f"<!--{PAYLOAD}-->") == "inert"


def test_breaking_the_container_makes_the_same_payload_live():
    assert live(f"<title></title>{PAYLOAD}</title>") == "live"
    assert live(f"<style></style>{PAYLOAD}</style>") == "live"
    assert live(f'<div class="">t</div>{PAYLOAD}') == "live"


def test_entity_encoded_markup_is_text_not_tags():
    enc = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    assert live(f"<div>{enc}</div>") == "inert"
    # and an entity inside an attribute value stays data
    assert live(f'<div class="&lt;img src=x onerror={X}&gt;">t</div>') == "inert"


# ---------------------------------------------------------------------------
# The sink decides the rest
# ---------------------------------------------------------------------------

def test_script_element_executes_from_the_parser_and_never_from_innerhtml():
    """Both measured in benchmark/sink_execution.py: `script.text = CODE`
    executes, `div.innerHTML = <script>CODE</script>` does not."""
    html = f"<div><script>{X}</script></div>"
    assert live(html, "parser") == "live"
    assert live(html, "innerhtml") == "inert"


def test_token_inside_a_js_string_is_data():
    html = f'<script>var a = "{PAYLOAD}";</script>'
    v = sb.judge(html, X, sink="parser")
    assert v.state == "inert", v.reason
    assert "string" in v.reason


def test_payload_that_closes_the_quote_is_code_again():
    trapped = """<script>var a = "%s";</script>""" % PAYLOAD
    assert sb.judge(trapped, X, sink="parser").state == "inert"
    # The realistic breakout comment-terminates the statement: without the `//`
    # the trailing quote of the host opens an unterminated string, the whole
    # script fails to compile, and -- this is the part a tree-only rule misses
    # -- nothing in it runs, not even the part before the error.
    escaped = "<script>var a = 'x';%s;//" % X
    assert sb.judge(escaped, X, sink="parser").state == "live"
    assert sb.judge("<script>var a = 'x';%s;var b='" % X, X,
                    sink="parser").state == "inert"


def test_a_string_that_is_a_call_argument_is_the_payload_landing():
    """`alert('TOKEN')` puts the token inside a string literal *and* executes.

    Deciding "in a string, therefore data" is quoting-blind, and it cost the
    benchmark's `pos-cdata-01` a false negative on this gate's first run: the
    confirming payload was
    `]]></script><script>alert('TOKEN')</script><![CDATA[`, whose script body is
    exactly a call with a string argument.  The lexical state says "string"; the
    syntax tree says "argument of a call the script reaches", and that is the
    answer.
    """
    tok = "xssv_9d3ab398"
    called = f"<html><body><svg><![CDATA[]]></script><script>alert('{tok}')" \
             f"</script><![CDATA[]]></svg></body></html>"
    v = sb.judge(called, tok, sink="parser")
    assert v.state == "live", f"CDATA breakout lost: {v.reason}"
    # The same quoting, in a position that is genuinely only data.
    data = f"<script>var config = {{ title: '{tok}' }};</script>"
    d = sb.judge(data, tok, sink="parser")
    assert d.state == "inert", d.reason


def test_a_real_mutation_vector_inert_once_and_live_twice():
    """The one browser-confirmed mXSS shape found so far, reproduced offline.

    `<math><mtext><table><mglyph><style><img onerror=CODE>`:

      * first parse -- `mtext` is a MathML text integration point so its
        children are HTML; `<table>` opens table scope, `<mglyph>` is not
        table content so it is **foster-parented before the table**, and
        `<style>` is therefore an HTML raw-text element: the `<img>` is text.
      * the browser serialises that tree with the empty `<table>` now *after*
        `<mglyph>`, so nothing sits in front of it any more.
      * re-parsing that serialisation hits the spec's mglyph exception --
        `<mglyph>` and `<style>` are created in the **MathML** namespace, so
        `<style>` is no longer a raw-text element, and the `<img>` becomes a
        live tag.

    A namespace flip caused by a reordering caused by a serialisation.  No
    sanitizer involved, which is why "innerHTML round-trips can't create XSS"
    was the wrong conclusion to have drawn from a corpus that had no payload of
    this shape in it.
    """
    payload = (f'<math><mtext><table><mglyph><style>'
               f'<img src=x onerror="{X}"></style>')
    # Round 1 must not claim LIVE.  It reports UNKNOWN rather than INERT because
    # a <table> opened inside a MathML integration point is a construct the
    # parser flags as un-modelled (see benchmark/mxss_family_probe.py: the
    # tbody/tr siblings of this shape fire on the FIRST parse, which the
    # foster-parenting rules here do not reproduce).  UNKNOWN is the honest
    # answer -- it sends the case to the browser instead of asserting a
    # false "inert" that the verify gate would act on.
    assert live(payload, "innerhtml") != "live"
    assert live(payload, "parser") != "live"
    v = sb.judge_roundtrip(payload, X, sink="innerhtml")
    assert v.state == "live", v.reason
    assert "MUTATED" in (v.evidence or ""), v.evidence
    # the sandbox's own first serialisation must BE the browser's, or the flip
    # it predicts next is an artefact of its own writer
    assert sb.roundtrip(payload, times=1)[0] == (
        f'<math><mtext><mglyph><style><img src=x onerror="{X}"></style>'
        f'</mglyph><table></table></mtext></math>')


def test_foster_parenting_moves_content_before_the_open_table():
    """Plain reflected markup in a table cell context, for the same rule."""
    got = ser("<table><tbody><tr><td>x</td></tr></tbody></table>")
    assert got == "<table><tbody><tr><td>x</td></tr></tbody></table>", got
    # a div cannot live inside <tr>: it goes before the table, table stays empty
    got = ser("<table><tr><div>d</div></tr></table>")
    assert got.startswith("<div>d</div><table>"), got


def test_a_note_about_unmodelled_syntax_vetoes_an_inert_verdict():
    """The three-state contract, enforced from the parser side.

    INERT is the verdict that costs something to get wrong: it tells the scanner
    to stop looking, and through the verify gate it retracts confirmations.  So a
    parse that had to record something it does not model is not allowed to
    conclude INERT even when every candidate it did find looks dead.  Without
    this rule the sandbox answers a confidently wrong question exactly where it
    has already admitted it does not know.
    """
    doc = sb.parse('<math><mtext><table><mglyph><style>'
                   '<img src=x onerror="__x()"></style></mtext></math>')
    assert doc.notes, "the un-modelled shape must be recorded by the parser"
    v = sb.judge('<math><mtext><table><mglyph><style>'
                 '<img src=x onerror="__x()"></style></mtext></math>',
                 "__x()", sink="innerhtml")
    assert v.state == "unknown", f"{v.state}: {v.reason}"
    # and an ordinary inert page still says inert -- the rule is not a blanket
    # "never say inert", which would make the sandbox useless
    assert sb.judge("<div class='<img onerror=__x()>'>t</div>", "__x()",
                    sink="innerhtml").state == "inert"


def test_focusability_comes_from_tabindex_not_from_being_a_form_control():
    """`autofocus` fires `onfocus` on anything focusable, and `tabindex` makes
    anything focusable.  Measured element by element in
    benchmark/autofocus_probe.py -- this rule was first written as "form
    controls only", which silently buries `<span tabindex=1 autofocus
    onfocus=...>`, a payload shape in wide use.

    `div` is the honest exception: it does NOT fire, reproducibly, while every
    other element above does.  That contradiction is reported as UNKNOWN rather
    than resolved by guessing which side of it to encode.
    """
    live_with_tabindex = (
        "span", "a", "img", "li", "video", "textarea", "input", "button")
    for tag in live_with_tabindex:
        html = f'<{tag} tabindex=1 autofocus onfocus="{X}">x</{tag}>' \
            if tag not in ("input", "button", "textarea") \
            else f'<{tag} tabindex=1 autofocus onfocus="{X}">'
        assert live(html) == "live", f"{tag}: " + live(html)
    # no tabindex and not a control -> genuinely inert
    assert live(f'<span autofocus onfocus="{X}">x</span>') == "inert"
    # a control needs no tabindex
    assert live(f'<input autofocus onfocus="{X}">') == "live"
    # autofocus absent -> a real XSS one interaction away, not inert
    v = sb.judge(f'<span tabindex=1 onfocus="{X}">x</span>', X, sink="parser")
    assert v.state == "live" and v.activation is True
    # the unexplained one
    d = sb.judge('<div tabindex=1 autofocus onfocus="x"></div>', "x",
                 sink="parser")
    assert d.state == "unknown", d.reason


def test_js_state_at_positions():
    assert sb.js_state_at("a=1", "a") == "code"
    assert sb.js_state_at("""var a = "TOKEN";""", "TOKEN") == "string"
    assert sb.js_state_at("var a = 'TOKEN';", "TOKEN") == "string"
    assert sb.js_state_at("// TOKEN\n", "TOKEN") == "line-comment"
    assert sb.js_state_at("/* TOKEN */", "TOKEN") == "block-comment"
    assert sb.js_state_at("var a = `x${TOKEN}y`;", "TOKEN") == "code"
    assert sb.js_state_at("no token here", "TOKEN") == "absent"
    # a regex spanning the token is the one thing the scan must not assert about
    assert sb.js_state_at("var r = /TOKEN/; x()", "TOKEN") == "unknown"


def test_script_inside_template_is_inert():
    assert live(f"<template><script>{X}</script></template>", "parser") == "inert"
    assert live(f'<template><img src=x onerror={X}></template>', "parser") == "inert"


# ---------------------------------------------------------------------------
# javascript: URIs, element by element (benchmark/sink_execution.py)
# ---------------------------------------------------------------------------

def test_javascript_uri_is_element_aware():
    assert live(f"<iframe src='javascript:{X}'></iframe>") == "live"
    # `<frame>` is not a smaller `<iframe>`: it only opens a browsing context
    # inside a frameset the parser actually honoured.  Measured both ways in
    # benchmark/probe_frame.py -- bare is inert, frameset-wrapped is live, with a
    # `<frame src=/child>` control proving a child document does reach the
    # sentinel.
    assert live(f"<frame src='javascript:{X}'></frame>") == "inert"
    assert live(f"<frameset><frame src='javascript:{X}'></frameset>") == "live"
    assert live("<html><body>x<frameset>"
                f"<frame src='javascript:{X}'></frameset>") == "inert"
    assert live(f'<img src="javascript:{X}">') == "inert"
    assert live(f'<link href="javascript:{X}">') == "inert"
    assert live(f'<script src="javascript:{X}"></script>') == "inert"
    assert live(f'<base href="javascript:{X}">') == "inert"
    assert live(f'<embed src="javascript:{X}">') == "inert"
    assert live(f'<object data="javascript:{X}"></object>') == "inert"


def test_frameset_ok_is_a_flag_not_a_tree_shape():
    """A `<frameset>` is honoured only while the document has not committed to
    body content, and what counts as committing was measured one name per page in
    `benchmark/probe_frameset_ok.py` (125 names) and one context per page in
    `benchmark/probe_frame.py` (47 rows).

    The set is not what a guesser would write: `<div>`, `<span>`, `<p>`, `<svg>`
    and the head metadata tags all LEAVE the flag alone, while `<br>`, `<hr>`,
    `<li>`, `<img>`, `<table>`, `<object>`, `<iframe>` and one character of text
    switch it off.  A model that cleared on "any element, or anything but html"
    loses every honoured case above; one that only looked for `<body>` loses the
    OVER that started this, `<html><body><frameset><frame src=javascript:CODE>`.
    """
    T = f"<frameset><frame src='javascript:{X}'></frameset>"
    honoured_after = ["<html>", "<html>  ", "<html><!--c-->",
                      "<!doctype html><html>", "<html><head>",
                      "<html><head><meta charset=utf-8>",
                      "<html><style>p{}</style>", "<html><title>t</title>",
                      "<html><div></div>", "<html><span>", "<html><p>",
                      "<html><svg></svg>", "<html><math><mi></mi></math>",
                      "<html><template>t</template>"]
    dead_after = ["<html>x", "<html>text", "<html><body>", "<html><br>",
                  "<html><hr>", "<html><img src=x>", "<html><table>",
                  "<html><li>", "<html><input>", "<html><button>",
                  "<html><object></object>", "<html><iframe></iframe>",
                  "<html><svg>text</svg>", "<html><frameset></frameset>",
                  "<html><textarea>t</textarea>", "<html><xmp></xmp>"]
    for pre in honoured_after:
        assert live(pre + T) == "live", pre + ": " + live(pre + T)
    for pre in dead_after:
        assert live(pre + T) == "inert", pre + ": " + live(pre + T)
    # text that is a template's CONTENT does not count as body text, but the
    # same text inside a `<div>` does -- the pair has to stay asymmetric or the
    # flag is just "any text at all", which measures wrong in both directions.
    assert live("<html><div>t</div>" + T) == "inert"
    # a fragment parser never builds a frameset, whatever precedes it
    assert sb.judge(T, X, sink="innerhtml").state == "inert"
    # `srcdoc` is an `<iframe>` attribute: a `<frame>` with only a srcdoc gets no
    # document at all (measured no execution, while `<frame src=/child>` runs).
    assert live("<html><frameset>"
                f'<frame srcdoc="&lt;img src=x onerror={X}&gt;"></frameset>') \
        == "inert"


def test_anchor_javascript_uri_is_real_xss_behind_a_click():
    v = sb.judge(f'<div><a href="javascript:{X}">go</a></div>', X, sink="parser")
    assert v.state == "live" and v.activation is True


def test_svg_anchor_uri_and_foreign_onload_follow_their_own_measurements():
    """The foreign namespace has its own rules, and both directions of them were
    measured in `benchmark/probe_svg_ns.py` (35 shapes, three arms each: page as
    served, a trusted mouse click, and the same bytes through innerHTML).

    An SVG `<a>` is an anchor: `javascript:` runs on click, with or without the
    `xmlns:xlink` declaration -- and the row is only meaningful once the `<a>` has
    a box, which is the mistake the first revision of that probe made (a 0x0 box
    "proved" nothing executed).  A foreign *resource* element has no click to
    wait for, and an SVG element that references nothing can never raise `onload`
    at all, so those two False answers are the bounded kind that license inert.
    """
    v = sb.judge('<svg width=60 height=30><a xlink:href='
                 f'"javascript:{X}"><text y="12">g</text></a></svg>',
                 X, sink="parser")
    assert v.state == "live" and v.activation is True, v.reason
    assert live(f'<svg><image href="javascript:{X}"></image></svg>') == "inert"
    assert live(f'<svg><image xlink:href="javascript:{X}"></image></svg>') \
        == "inert"
    assert live(f'<svg><use xlink:href="javascript:{X}"></use></svg>') == "inert"
    assert live(f'<svg><feImage href="javascript:{X}"></feImage></svg>') == "inert"
    for tag in ("desc", "g", "clipPath", "ellipse", "filter", "linearGradient",
                "path", "foreignObject"):
        html = f'<svg><{tag} onload="{X}"></{tag}></svg>'
        assert live(html) == "inert", f"{tag}: " + live(html)
    # the two that stay declined: both take an href, so a load event is
    # conceivable and what was measured was only the broken-reference path.
    assert live(f'<svg><use xlink:href="#nope" onload="{X}"></use></svg>') \
        == "unknown"
    assert live(f'<svg><image href="/nope" onload="{X}"></image></svg>') \
        == "unknown"
    # and the live side of the same rule, so the inert assertions above are not
    # just "nothing in this file ever fires"
    assert live(f'<svg onload="{X}"></svg>') == "live"
    assert live('<svg><a xlink:href='
                f'"javascript:{X}"><text y="12">g</text></a></svg>',
                "innerhtml") == "live+activation"


def test_control_characters_in_a_uri_are_stripped_before_the_scheme():
    """`jav&#x09;ascript:` and `java\\x01script:` reach the scheme parser as
    `javascript:` because the URL parser deletes C0 bytes and spaces first."""
    assert live(f'<div><a href="jav&#x09;ascript:{X}">g</a></div>') == "live+activation"
    assert live('<div><a href="java\x01script:%s">g</a></div>' % X) == "live+activation"


def test_meta_refresh_to_javascript_uri_does_not_execute():
    assert live(f'<meta http-equiv="refresh" content="0;url=javascript:{X}">') == "inert"


# ---------------------------------------------------------------------------
# Attribute-name handling
# ---------------------------------------------------------------------------

def test_nul_in_an_attribute_name_does_not_become_that_attribute():
    """`sr<NUL>c=` tokenises as `sr\ufffdc`, which is not `src`, so the image
    never loads and `onerror` never fires.  Several bypass notes claim the
    opposite; the browser says the payload dies."""
    html = "<div><img sr%s" "c=x onerror=%s>" % (NUL, X)
    assert live(html) == "inert"


def test_handler_names_must_be_on_plus_letters():
    assert live(f"<div><img src=x one-error={X}>") == "inert"
    assert live(f'<div on{NUL}click="{X}">t</div>') == "inert"
    assert live(f"<div><img src=x onerror={X}>") == "live"


def test_duplicate_attribute_keeps_the_first():
    assert live('<div><img src=x onerror=dead onerror=%s>' % X) == "inert"


# ---------------------------------------------------------------------------
# Namespace decides behaviour, not the attribute.  Every rule in this section
# came from a browser row where the handler was present in the tree and the
# payload still did not execute -- which is precisely the case a tree-shaped
# scanner reports as a finding.
# ---------------------------------------------------------------------------

def test_html_behaviour_does_not_cross_into_foreign_content():
    """`<svg><style>` keeps its children foreign (measured, not break-out), so
    an input/details/iframe/source written inside it is an element in the SVG
    namespace that implements none of the HTML behaviour its handler needs."""
    for frag in (f'<svg><style><input autofocus onfocus="{X}"></style></svg>',
                 f'<svg><style><details open ontoggle="{X}"></style></svg>',
                 f'<svg><style><video><source onerror="{X}"></video></style></svg>',
                 f'<svg><style><iframe srcdoc="&lt;img src=x onerror='
                 f'{X}&gt;"></iframe></style></svg>'):
        assert live(frag, "innerhtml") == "inert", frag
        assert live(frag, "parser") == "inert", frag


def test_nested_svg_load_event_fires_but_a_fresh_one_does_not():
    """Both measured.  `<svg onload>` reaching the page through the parser
    fires; inserted through innerHTML it does not, because the document already
    loaded -- unless it is nested inside another SVG element, where it is a new
    document root and fires again."""
    fresh = f'<div><svg onload="{X}"></svg></div>'
    assert live(fresh, "parser") == "live"
    assert live(fresh, "innerhtml") == "inert"
    nested = f'<svg><style><svg onload="{X}"></svg></style></svg>'
    assert live(nested, "innerhtml") == "live"
    # An HTML-integration-point ancestor is not the same as a same-namespace one
    beside = f'<math><mtext><svg onload="{X}"></svg></mtext></math>'
    assert live(beside, "innerhtml") == "inert"


def test_foreign_template_is_not_an_html_template():
    """A `<template>` inside `<svg>` has no content document, so a `<script>`
    under it is an ordinary SVG script and the parser runs it.  Only an HTML
    namespace <template> makes its subtree inert."""
    assert live(f"<template><script>{X}</script></template>", "parser") == "inert"
    nested = f'<svg><style><template><script>{X}</script></template></style></svg>'
    assert live(nested, "parser") == "live"


def test_source_needs_a_media_parent_to_ever_error():
    assert live(f'<div><source onerror={X}>') == "inert"
    assert live(f'<video><source onerror={X}></video>') == "live"


def test_html_void_rules_stop_at_the_foreign_boundary():
    """`<base>` is void in HTML and an unknown container in SVG.  Chromium
    really does nest the following element inside it, which is what the
    serialisation has to reproduce for the round-trip to be comparable."""
    foreign = ser("<svg><base href=x><a href=y>c</a></svg>")
    assert '<base href="x"><a href="y">' in foreign, foreign
    assert "</base>" in foreign, foreign
    # and still void in HTML content: no </base>, nothing nested inside it
    html = ser("<div><base href=x><a href=y>c</a></div>")
    assert html == '<div><base href="x"><a href="y">c</a></div>', html


def test_option_closes_for_a_control_reflected_into_it():
    """`<select><option><input autofocus onfocus=...>` puts the input beside the
    select, not inside it -- measured, and the difference between a firing
    autofocus and a buried one."""
    got = ser("<select><option><input autofocus></option></select>")
    assert "</option></select><input" in got, got


# Every expectation below is Chromium's own `innerHTML`, byte for byte, from the
# 96-name x 3-context matrix in benchmark/results/option_probe.json.  The spec's
# "in select"/"in option" insertion modes do NOT describe this behaviour, which
# is the whole reason the matrix was measured rather than transcribed.

def test_content_reflected_into_an_option_stays_inside_the_option():
    assert ser("<select><option><img src=x></option></select>") \
        == '<select><option><img src="x"></option></select>'
    assert ser("<select><option>a<div>b</div>c</option></select>") \
        == "<select><option>a<div>b</div>c</option></select>"
    assert ser("<select><option><svg></svg></option></select>") \
        == "<select><option><svg></svg></option></select>"
    assert ser("<select><option><video><source></video></option></select>") \
        == "<select><option><video><source></video></option></select>"


def test_select_scope_discards_the_document_and_table_names():
    """These names are *ignored outright* inside an open select -- not fostered,
    not moved.  The spec pops the select closed for most of them; Chromium drops
    the token, so the payload never appears anywhere in the DOM."""
    for name in ("caption", "col", "colgroup", "tbody", "tfoot", "thead",
                 "tr", "th", "select"):
        assert ser(f"<select><{name}></{name}></select>") == "<select></select>", name
        assert ser(f"<select><option><{name}></{name}></option></select>") \
            == "<select><option></option></select>", name
        assert ser(f"<select><optgroup><{name}></{name}></optgroup></select>") \
            == "<select><optgroup></optgroup></select>", name


def test_option_and_optgroup_imply_exactly_the_close_the_browser_applies():
    assert ser("<select><option>1<option>2</select>") \
        == "<select><option>1</option><option>2</option></select>"
    assert ser("<select><option>1<optgroup>x</optgroup></select>") \
        == "<select><option>1</option><optgroup>x</optgroup></select>"
    # an option inside an optgroup belongs to the group -- it does NOT escape it
    assert ser("<select><optgroup><option>x</option></optgroup></select>") \
        == "<select><optgroup><option>x</option></optgroup></select>"
    # but a second optgroup closes the first, and <hr> closes the option scope
    assert ser("<select><optgroup>a<optgroup>b</optgroup></select>") \
        == "<select><optgroup>a</optgroup><optgroup>b</optgroup></select>"
    assert ser("<select><option><hr></option></select>") \
        == "<select><option></option><hr></select>"


# ---------------------------------------------------------------------------
# NUL: where a U+0000 actually goes.  Each expectation is the browser's own
# innerHTML plus the code points it holds, from benchmark/results/nul_probe.json
# ---------------------------------------------------------------------------

def test_nul_in_an_attribute_value_becomes_u_fffd():
    assert ser('<img alt="a\x00b" src=x>') == '<img alt="a\ufffdb" src="x">'
    assert ser('<img src="x\x00" onerror="__x()">') \
        == '<img src="x\ufffd" onerror="__x()">'
    assert ser('<img src=x onerror="ale\x00rt(1)">') \
        == '<img src="x" onerror="ale\ufffdrt(1)">'
    assert ser("<img alt='a\x00b' src=x>") == '<img alt="a\ufffdb" src="x">'
    assert ser("<img alt=a\x00b src=x>") == '<img alt="a\ufffdb" src="x">'


def test_nul_is_dropped_in_text_but_becomes_u_fffd_in_rcdata_and_rawtext():
    """The two rules are opposite, which is why they are two assertions.
    `<p>` holds `61 62`; `<title>`/`<textarea>`/`<style>` hold `61 fffd 62`."""
    assert ser("<p>a\x00b</p>") == "<p>ab</p>"
    assert ser("<div>a\x00b</div>") == "<div>ab</div>"
    assert ser("<title>a\x00b</title>") == "<title>a\ufffdb</title>"
    assert ser("<textarea>a\x00b</textarea>") == "<textarea>a\ufffdb</textarea>"
    assert ser("<style>a\x00{color:red}</style>") \
        == "<style>a\ufffd{color:red}</style>"


def test_a_nul_in_a_comment_is_replaced_before_it_is_re_serialised():
    assert ser("<!--a\x00b-->") == "<!--a\ufffdb-->"


def test_a_nul_in_a_start_tag_name_makes_an_unknown_element():
    """`bypass.py` and `data/payloads.json` both ship
    `<scr<NUL>ipt>alert(1)</scr<NUL>ipt>` as a null-byte-insertion bypass.  It is
    not one: Chromium builds an element named `scr\ufffdipt` (code points
    `73 63 72 fffd 69 70 74`) whose content is text, so nothing runs.  The
    sandbox used to delete the NUL on the *start* tag while correctly keeping it
    on the end tag and on attribute names -- which read as a live <script> whose
    own close tag failed, i.e. a confirmed finding out of a dead payload.
    Expected strings are Chromium's own innerHTML from
    benchmark/results/nul_probe.json."""
    p = "<scr\x00ipt>alert(1)</scr\x00ipt>"
    assert ser(p) == "<scr\ufffdipt>alert(1)</scr\ufffdipt>"
    # `judge` scopes to the token, so the token has to be the payload here --
    # with the default sentinel these three would read inert for having no
    # token at all, which is a green that proves nothing.
    assert live(p, token="alert(1)") == "inert"
    assert live(p, token="alert(1)", sink="innerhtml") == "inert"
    # and the rule is the same for a name that is not a security word
    assert ser("<div\x00x>a</div\x00x>") == "<div\ufffdx>a</div\ufffdx>"
    # a real script is still live through the parser and inert through innerHTML
    assert live("<script>alert(1)</script>", token="alert(1)").startswith("live")
    assert live("<script>alert(1)</script>", token="alert(1)",
                sink="innerhtml") == "inert"
    # the shipped second family member: a handler value that *starts* with NUL
    assert live("<svg onload=\x00top.__x()>", token=X) == "inert"
    # ... and that the same shape WITHOUT the NUL is the live case, so the rule
    # above cannot be passing because the harness never detects svg onload
    assert live("<svg onload=top.__x()>", token=X) != "inert"


# ---------------------------------------------------------------------------
# SMIL and CSS-animation events: expectations are Chromium's own exec/no-exec
# answers, both sinks, from benchmark/results/smil_probe.json (23 shapes)
# ---------------------------------------------------------------------------

def test_smil_timing_events_fire_on_the_animation_element_alone():
    """`<svg><animate onbegin=CODE>` runs during the load itself, with no
    interaction and through innerHTML as well -- the sandbox used to abstain on
    the whole family (`{'*'}` in the table, "not measured" from the foreign
    branch), so the browser probe was mandatory for 27 shipped payloads."""
    for tag in ("animate", "set", "animateTransform", "animateMotion"):
        assert live(f"<svg><{tag} onbegin={X} dur=1s>", sink="parser") == "live"
        assert live(f"<svg><{tag} onbegin={X} dur=1s>", sink="innerhtml") == "live"
    assert live(f"<svg><animate onend={X} dur=1s>") == "live"
    assert live(f"<svg><animate onrepeat={X} dur=1s repeatCount=3>") == "live"


def test_smil_timing_events_never_fire_without_a_timeline():
    """The over-claim half: a handler name alone is not an event.  Every one of
    these read as live-with-activation before, which kept the gate from vetoing
    them; `<discard>` is the instructive case -- an animation element that still
    does not raise `begin`."""
    for shape in (f'<div onbegin="{X}">t</div>', f'<p onbegin="{X}">t</p>',
                  f'<input onbegin="{X}">', f'<svg width=4 onbegin="{X}">',
                  f'<svg><circle onbegin="{X}">',
                  f'<svg><discard onbegin="{X}" begin="0s">',
                  f'<svg><set onbegin="{X}" begin="indefinite">'):
        assert live(shape) == "inert", shape
        assert live(shape, sink="innerhtml") == "inert", shape


def test_smil_begin_distinguishes_time_from_a_gesture():
    """`begin="2s"` needs the clock, not a click: demanding interaction there
    would leave a real vector unpromoted.  `begin="mouseover"` is the opposite."""
    assert live(f'<svg><animate onbegin="{X}" begin="2s" dur=1s>') == "live"
    assert live(f'<svg><animate onbegin="{X}" begin="0s" dur=1s>') == "live"
    got = live(f'<svg><animate onbegin="{X}" begin="mouseover" dur=1s>')
    assert got == "live+activation", got
    # and syntax this module has not measured is declined, not guessed
    assert live(f'<svg><animate onbegin="{X}" begin="a.end+1s" dur=1s>') == "unknown"


def test_css_animation_events_are_declined_not_judged():
    """Both sides measured, and they cancel out to "abstain".

    `<style>@keyframes k{...}</style>` + inline `animation:k 1s` fires with no
    interaction; the *same* two declarations reflected through an unquoted
    attribute or a `<style>` host fire nothing, because the `@keyframes` rule is
    text there and never comes into existence.  An inline `animation:` therefore
    proves nothing on its own, and this module does not resolve stylesheets.
    """
    for shape in (f'<div style="animation:k 1s" onanimationstart="{X}">t</div>',
                  f'<div onanimationstart="{X}">t</div>'):
        assert live(shape) == "unknown", shape


def test_a_reflected_svg_can_degrade_to_html_and_lose_the_timeline():
    """`<div class=<svg><animate onbegin=CODE>` -- the unquoted value swallows
    `<svg>`, so `animate` is an HTML element with no SMIL timeline.  Chromium's
    own serialisation shows that tree and does not execute; namespace has to be
    part of the rule, not just the tag name."""
    shape = ('<div class=<svg><animate onbegin=__x() attributeName="x"'
             ' dur="1s"></animate></svg>>t</div>')
    assert live(shape) == "inert"
    assert live(shape, sink="innerhtml") == "inert"
    # and the same payload with a real <svg> stays live
    assert live(f'<svg><animate onbegin={X} attributeName="x" dur="1s">'
                f'</animate></svg>') == "live"


def test_smil_inside_srcdoc_is_declined():
    """Every SMIL payload carried into a nested document by `srcdoc` measured
    no-exec across all 20 hosts.  Nothing here explains why that timeline does
    not start, so nothing claims a verdict either way."""
    shape = ('<iframe srcdoc="&lt;svg&gt;&lt;animate onbegin=__x()'
             ' attributeName=&quot;x&quot; dur=&quot;1s&quot;&gt;&lt;/animate&gt;'
             '&lt;/svg&gt;"></iframe>')
    assert live(shape) == "unknown", live(shape)


def test_smil_attribute_animation_to_a_javascript_url_does_not_navigate():
    for shape in (f'<svg><a><text>x</text><animate attributeName="href"'
                  f' values="javascript:{X}" dur=1s fill=freeze></a></svg>',
                  f'<svg><animate attributeName="href"'
                  f' values="javascript:{X}" dur=1s>',
                  f'<svg><set attributeName="onload" to="{X}" begin="0s" dur=1s>'):
        assert live(shape) == "inert", shape


# ---------------------------------------------------------------------------
# Media loading events.  19 shapes x 6 reflection contexts, browser-measured in
# benchmark/results/media_probe.json; `src` validity is deliberately not claimed.
# ---------------------------------------------------------------------------

def test_media_events_on_a_non_media_element_are_inert():
    """`<div class=<audio oncanplay=CODE src=...>>` never forms the `<audio>`:
    the handler lands on the div and nothing executes.  The live-side mirror is
    the same markup with a real `<audio>` -- see the next test."""
    swallowed = ('<div class=<audio oncanplay="__x()" src="/a.wav">t</div>')
    assert live(swallowed, token=X) == "inert"
    assert live('<p oncanplay="__x()">t</p>', token=X) == "inert"


def test_a_media_event_without_a_src_can_never_fire():
    """Nothing is fetched, so the load never starts.  Measured no-exec in all six
    contexts, with `src` absent and with `src=""`."""
    assert live(f'<audio oncanplay="{X}"></audio>') == "inert"
    assert live(f'<audio oncanplay="{X}" src=""></audio>') == "inert"


def test_onloadstart_is_the_one_media_event_a_dead_url_still_fires():
    """Measured both ways: `loadstart` fires for a decodable data: URI *and* for a
    src that 404s, because the attempt is the event.  The other five in the family
    (`canplay`/`loadeddata`/...) need the resource to decode, so a markup-only
    model declines them -- and playback events stay gated (`onplaying` measured
    no-exec even with a valid src, because autoplay policy blocks the play)."""
    good = f'<audio onloadstart="{X}" src="data:audio/wav;base64,AAAA"></audio>'
    dead = f'<audio onloadstart="{X}" src="/no-such-file.wav"></audio>'
    assert live(good) == "live"
    assert live(dead) == "live"
    canplay_dead = f'<audio oncanplay="{X}" src="/no-such-file.wav"></audio>'
    assert live(canplay_dead) == "unknown"
    assert live(f'<audio onplaying="{X}" src="data:audio/wav;base64,AAAA"></audio>') \
        == "live+activation"


def test_a_bare_track_is_never_processed_but_one_in_a_video_is():
    """`<source>` already had this rule; `<track>` measured the same way.  The
    mirror pair matters: without it, "inert" here would be indistinguishable from
    "this harness never detects track errors"."""
    inside = f'<video><track onerror="{X}" src="/nope.vtt" kind="captions" default>'
    assert live(inside) == "live", live(inside)
    assert live('<div><track onerror="__x()" src="/nope.vtt">') == "inert"


def test_a_nul_does_not_reassemble_a_javascript_uri():
    """The reason any of this matters.  `jav&#x00;ascript:` is not `javascript:`:
    Chromium stores `jav\ufffdascript:` and resolves it as a *relative URL*, so a
    scanner that decoded the NUL into nothing reports a finding that cannot fire.
    A leading space, by contrast, really is stripped by the URL parser."""
    assert live('<a href="javascript:__x()">c</a>').startswith("live")
    assert live('<a href="jav&#x00;ascript:__x()">c</a>') == "inert"
    assert live('<a href="java\x00script:__x()">c</a>') == "inert"
    assert live('<a href=" javascript:__x()">c</a>').startswith("live")


def test_document_mode_inserts_inside_body_not_beside_it():
    """The document parser used to append <body> to the tree without making it
    the insertion point, so an entire served page came back as siblings of
    <body>.  Liveness survived by accident -- an img fires wherever it sits --
    but every ancestor-dependent rule read a flat tree."""
    doc = sb.parse("<html><body><div><span>x</span></div></body></html>",
                   fragment=False)
    body = next(c for c in doc.root.children if c.name == "body")
    assert [c.name for c in body.children] == ["div"]
    assert body.children[0].children[0].name == "span"
    assert not [c.name for c in doc.root.children if c.name != "body"]
    # the select scope no longer pops through the body either
    doc2 = sb.parse("<html><body><select><option><img src=x></option></select>"
                    "</body></html>", fragment=False)
    body2 = next(c for c in doc2.root.children if c.name == "body")
    assert [c.name for c in body2.children] == ["select"]
    assert sb.serialize(body2) \
        == '<select><option><img src="x"></option></select>'


def test_table_implies_tbody_the_way_chromium_serialises_it():
    assert ser("<table><tr><td>x</td></tr></table>") \
        == "<table><tbody><tr><td>x</td></tr></tbody></table>"


# ---------------------------------------------------------------------------
# Verdict contract
# ---------------------------------------------------------------------------

def test_verdict_states_are_exactly_the_three():
    for html in ("<div>x</div>", "<svg><style><img src=x onerror=%s>" % X,
                 "<div class='", "<!---->", "<p", "<script>/a/</script>",
                 "", "<math><annotation-xml encoding='text/html'><img src=x "
                 "onerror=%s></annotation-xml></math>" % X):
        for sink in ("parser", "innerhtml"):
            v = sb.judge(html, X, sink=sink)
            assert v.state in ("live", "inert", "unknown"), (html, sink, v.state)


def test_roundtrip_is_idempotent_once_stable():
    """Two consecutive serialisations that agree mean the sandbox reached a
    fixed point.  An inert input must stay inert across the round-trip -- if it
    does not, the serialiser is inventing markup the parser then believes."""
    html = f'<div class="{PAYLOAD}">t</div>'
    a, b = sb.roundtrip(html, times=2)
    assert a == b, f"the serialiser has no fixed point: {a!r} then {b!r}"
    assert sb.judge_roundtrip(html, X, sink="innerhtml").state == "inert"


def test_judge_roundtrip_reports_first_parse_liveness_directly():
    """A vector that is live on round 1 must come back without the MUTATED
    stamp: calling ordinary XSS "mutation XSS" is what made the old mXSS corpus
    claim a round-trip it never needed."""
    v = sb.judge_roundtrip(f"<div>{PAYLOAD}</div>", X, sink="innerhtml")
    assert v.state == "live"
    assert "MUTATED" not in (v.evidence or "")


def test_srcdoc_value_is_parsed_as_a_document():
    """An attribute value consumes character references first, so the entity
    form is the NORMAL way to write srcdoc markup -- both spellings reach the
    nested document as a live img."""
    encoded = '<iframe srcdoc="&lt;img src=x onerror=%s&gt;"></iframe>' % X
    assert live(encoded) == "live"
    # A quoted attribute value may contain `>`, so the raw spelling reaches the
    # nested document too -- the entity form is only needed inside unquoted
    # values, and treating `>` as a tag terminator in a quoted value truncates
    # every srcdoc payload on the way past the parser.
    raw = '<iframe srcdoc="<img src=x onerror=%s>"></iframe>' % X
    assert live(raw) == "live"


def test_unknown_is_reachable_and_not_silently_inert():
    """A sandbox that only ever answers live/inert is lying about something."""
    hit = None
    for html in ("<script>var r = /x/; var s = 'TOKEN</script>",
                 "<div><script>var a = /TOKEN/;</script></div>"):
        v = sb.judge(html, "TOKEN", sink="parser")
        if v.state == "unknown":
            hit = v
            break
    assert hit is not None, "no input produced UNKNOWN -- check the guards"
