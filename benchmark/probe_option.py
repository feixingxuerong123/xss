"""What does Chromium's tree builder actually do inside `<option>`?

The spec's "in option" insertion mode says a start tag that is not option /
optgroup / select is *ignored*.  The 900-case oracle says otherwise:
`<select><option><img src=x onerror=…>` serialises back with the **img still
inside the option**, and `exec_parser` is True -- the element exists and its
handler fires.  `xssentinel/core/sandbox.py` currently hoists it out to sit
after `</select>`, which is 39 of the 83 remaining serialisation disagreements
(47% of the drift, all of it in one host).

So this measures the boundary instead of reading the spec at it.  For each shape
it records, for BOTH the document parse and an `innerHTML` re-parse (and a
second re-parse, i.e. the mXSS question):

    * the browser's serialisation,
    * the ancestor chain of every `[data-t]` marker,
    * how many markers survived at all.

and prints the sandbox's own chain/serialisation beside it, so the rule gap is a
table rather than an inference.

Usage:  python -m benchmark.probe_option [--json out.json]
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from xssentinel.core import sandbox  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "option_probe.json"

# (name, body innerHTML).  `data-t` marks the node whose ancestry is the answer.
OPT = lambda inner: f"<select><option>{inner}</option></select>"  # noqa: E731
SEL = lambda inner: f"<select>{inner}</select>"                   # noqa: E731
GRP = lambda inner: f"<select><optgroup>{inner}</optgroup></select>"  # noqa: E731

# The three contexts the "in select" / "in option" insertion modes disagree on,
# crossed with every name that could plausibly be treated specially.  The sets
# are what this probe is FOR -- the spec's own lists and Chromium's behaviour do
# not agree here (see the module docstring), so the partition is read off the
# measurement rather than written from memory.
NAMES = [
    "a", "abbr", "area", "article", "audio", "b", "base", "bdi", "bdo",
    "blockquote", "body", "br", "button", "caption", "center", "code", "col",
    "colgroup", "data", "dd", "details", "dialog", "div", "dl", "dt", "em",
    "embed", "fieldset", "figcaption", "figure", "footer", "form", "h1",
    "head", "header", "hr", "html", "i", "iframe", "img", "input", "ins",
    "kbd", "label", "legend", "li", "link", "main", "map", "mark", "meta",
    "meter", "nav", "noscript", "object", "ol", "optgroup", "option", "output",
    "p", "param", "picture", "pre", "progress", "rp", "rt", "ruby", "s",
    "samp", "script", "search", "section", "select", "slot", "small", "source",
    "span", "strong", "style", "sub", "summary", "sup", "table", "tbody",
    "template", "textarea", "tfoot", "th", "thead", "title", "tr", "track",
    "u", "ul", "var", "video", "wbr", "xmp", "svg", "math", "annotation-xml",
    "desc", "foreignobject", "mtext", "mglyph",
    # Added after the first run: `td` was not in this list, so "measured name by
    # name" was true only of the names I had thought to put here.  Everything
    # below is a name the fuzz differential or a spec read pointed at, checked
    # against the list rather than assumed to be in it.
    "td", "animate", "set", "animatetransform", "animatemotion", "discard",
    "image", "use", "symbol", "marker", "pattern", "filter", "fegaussianblur",
    "canvas", "marquee", "plaintext", "listing", "xmp", "noembed", "noframes",
    "frame", "frameset", "isindex", "keygen", "portal", "menu", "menuitem",
    "h2", "h3", "h4", "h5", "h6", "address", "aside", "cite", "dfn", "q",
    "rb", "rtc", "time", "big", "strike", "tt", "acronym",
    "applet", "basefont", "bgsound", "del",
]
# Names can be listed twice as the set grows; a duplicate silently doubles
# its row and skews every count, so the list is uniqued here.
NAMES = list(dict.fromkeys(NAMES))


CASES: list[tuple[str, str]] = [
    *[("ctx:option:" + n, OPT(f"<{n} data-t=1></{n}>")) for n in NAMES],
    *[("ctx:select:" + n, SEL(f"<{n} data-t=1></{n}>")) for n in NAMES],
    *[("ctx:optgroup:" + n, GRP(f"<{n} data-t=1></{n}>")) for n in NAMES],
    # A fourth context, because "is this start tag ignored unless a table is
    # open?" is the same question as "is it ignored unless a select is open?",
    # and answering it for `<td>`/`<tr>`/`<caption>` alone would be three
    # samples again.  The inner arm puts each name straight into a detached div.
    *[("ctx:div:" + n, f"<{n} data-t=1></{n}>") for n in NAMES],
    # -- nesting one level deeper (foreign + html integration) ----------------
    ("in-opt:svg-rect", OPT('<svg><rect data-t=1 width="4" height="4"></svg>')),
    ("in-opt:math-mi", OPT("<math><mi data-t=1>x</mi></math>")),
    ("in-opt:table-nest", OPT("<table data-t=1><tbody><tr><td>x</td></tr></tbody></table>")),
    # -- closing behaviour -----------------------------------------------------
    ("close:opt-ends-div", OPT("<div data-t=1></option>")),
    ("close:sel-ends-div", OPT("<div data-t=1></select>")),
    ("close:div-self", OPT("<div data-t=1></div>after")),
    ("close:optgroup-inside", "<select><optgroup><div data-t=1>x</optgroup></select>"),
    # -- no option wrapper at all ---------------------------------------------
    ("bare:select-img", "<select><img data-t=1 src=x></select>"),
    ("bare:select-option-img", "<select><option><img data-t=1 src=x>"),
    ("bare:option-no-select", '<img data-t=1 src=x><option>x</option>'),
    ("bare:optgroup-direct", "<select><optgroup data-t=1>x</optgroup></select>"),
    # -- implied end of option (the spec rule that evidently is not what runs) -
    ("implied:two-options", "<select><option>1<option data-t=1>2</select>"),
    ("implied:opt-then-optgroup",
     "<select><option>1<optgroup data-t=1>x</optgroup></select>"),
    # -- mixed text and elements ----------------------------------------------
    ("text:mixed", OPT("a<div data-t=1>b</div>c")),
    ("text:comment", OPT("<!--<img data-t=1>--><img data-t=1 src=x>")),
    ("text:nul", OPT('<img data-t=1 src=x alt="a\x00b">')),
]


class _Handler(BaseHTTPRequestHandler):
    PAGES: dict[str, str] = {}

    def do_GET(self):  # noqa: N802
        body = self.PAGES.get(self.path, "<html><body></body></html>")
        raw = body.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        pass


_CHAINS = """
(o) => {
  const mark = (root, inTemplate) => {
    const out = [];
    for (const e of root.querySelectorAll('[data-t]')) {
      const p = [];
      let n = e;
      while (n && n.tagName) { p.unshift(n.tagName.toLowerCase()); n = n.parentElement; }
      out.push((inTemplate ? 'template-content:' : '') + p.join('>'));
    }
    for (const t of root.querySelectorAll('template')) {
      if (t.content) out.push(...mark(t.content, true));
    }
    return out;
  };
  const r = {ser: null, chains: [], n: 0, err: null};
  try {
    if (o.mode === 'document') {
      r.ser = document.body.innerHTML;
      r.chains = mark(document, false);
    } else {
      const c = document.createElement('div');
      c.innerHTML = o.html;
      const again = document.createElement('div');
      again.innerHTML = c.innerHTML;
      r.ser = c.innerHTML;
      r.ser2 = again.innerHTML;
      r.chains = mark(c, false);
      r.chains2 = mark(again, false);
    }
    r.n = r.chains.length;
  } catch (e) { r.err = String(e).slice(0, 140); }
  return r;
}
"""


def _serve() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _goto(page, url: str, tries: int = 3) -> bool:
    for attempt in range(tries):
        try:
            page.goto(url, wait_until="load")
            return True
        except Exception:
            if attempt == tries - 1:
                return False
            page.wait_for_timeout(150 * (attempt + 1))
    return False


# -- sandbox side -------------------------------------------------------------

def _find_body(node: sandbox.Node) -> sandbox.Node:
    for c in node.children:
        if c.kind == "element" and c.name == "body":
            return c
        if c.kind == "element":
            try:
                return _find_body(c)
            except ValueError:
                pass
    raise ValueError("no <body> in parse result")


def _sb_chains(html: str, fragment: bool) -> tuple[str, list[str]]:
    """Sandbox's view of the SAME scope the browser was asked about.

    document arm -> the served page's `body.innerHTML`, whose chain starts
    `html>body>`;  inner arm -> a detached `div`'s innerHTML, chain starts
    `div>`.  Getting these scopes aligned is the whole point: compared loose,
    the probe reports disagreements that are only framing.
    """
    doc = sandbox.parse(html, fragment=fragment)
    prefix: tuple[str, ...]
    if fragment:
        scope, prefix = doc.root, ("div",)
    else:
        scope, prefix = _find_body(doc.root), ("html", "body")
    out: list[str] = []

    def walk(node: sandbox.Node, path: tuple[str, ...], in_tpl: bool) -> None:
        for c in node.children:
            if c.kind != "element":
                continue
            tag = c.name
            p = path + (tag,)
            if c.get("data-t") is not None:
                out.append(("template-content:" if in_tpl else "")
                           + ">".join(p))
            walk(c, p, in_tpl or tag == "template")

    walk(scope, prefix, False)
    return sandbox.serialize(scope), out


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    _Handler.PAGES = {
        f"/{i}": f"<html><body>{body}</body></html>"
        for i, (_, body) in enumerate(CASES)
    }
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            page = ctx.new_page()
            for i, (name, body) in enumerate(CASES):
                if not _goto(page, f"{base}/{i}"):
                    rows.append({"case": name, "err": "navigation failed"})
                    continue
                try:
                    doc = page.evaluate(_CHAINS, {"mode": "document", "html": ""})
                    ihn = page.evaluate(_CHAINS, {"mode": "inner", "html": body})
                except Exception as e:            # a lost row is recoverable
                    rows.append({"case": name, "err": str(e)[:120]})
                    continue
                sb_doc_ser, sb_doc_ch = _sb_chains(
                    f"<html><body>{body}</body></html>", False)
                sb_ihn_ser, sb_ihn_ch = _sb_chains(body, True)
                rows.append({
                    "case": name, "body": body,
                    "doc_ser": doc.get("ser"), "doc_chains": doc.get("chains"),
                    "ihn_ser": ihn.get("ser"), "ihn_chains": ihn.get("chains"),
                    "ihn_ser2": ihn.get("ser2"), "ihn_chains2": ihn.get("chains2"),
                    "sb_doc_ser": sb_doc_ser, "sb_doc_chains": sb_doc_ch,
                    "sb_ihn_ser": sb_ihn_ser, "sb_ihn_chains": sb_ihn_ch,
                    "err": doc.get("err") or ihn.get("err"),
                })
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def _parent(chains: list[str]) -> str:
    """Where the marker ended up: its parent's tag, or `dropped`."""
    if not chains:
        return "dropped"
    parts = chains[0].replace("template-content:", "").split(">")
    return parts[-2] if len(parts) >= 2 else "root"


def _partition(rows: list[dict]) -> None:
    """Print the answer as sets, because the sets are what go into sandbox.py."""
    import collections

    for ctx in ("option", "select", "optgroup", "div"):
        keep: list[str] = []
        moved: dict[str, list[str]] = collections.defaultdict(list)
        disagree: list[str] = []
        for r in rows:
            if not r["case"].startswith("ctx:" + ctx + ":"):
                continue
            name = r["case"].split(":", 2)[2]
            b = _parent(r.get("ihn_chains") or [])
            s = _parent(r.get("sb_ihn_chains") or [])
            if b != s:
                disagree.append(f"{name}(browser={b} sandbox={s})")
            if b == ctx:
                keep.append(name)
            else:
                moved[b].append(name)
        print(f"\n== inside <{ctx}>: browser keeps {len(keep)} names there")
        print("   stays in place : " + " ".join(sorted(keep)))
        for where, names in sorted(moved.items()):
            print(f"   -> {where:<9}: " + " ".join(sorted(names)))
        print(f"   sandbox disagrees on {len(disagree)}: "
              + (" ".join(disagree[:20]) if disagree else "-"))


def _marker_is_document_shell(chains: list[str]) -> bool:
    """True when the only 'structure' left is the page's own <html>/<body>.

    `<select><option><body data-t=1>` does not create a body inside the select:
    the token merges onto the document's existing body (which is exactly why a
    reflected `<body onload>` fires).  The marker therefore ends up on the
    document shell, which the sandbox represents as an attribute merge rather
    than as a node it could point at -- so there is nothing to compare and
    calling it a disagreement would be a lie in the other direction.
    """
    return bool(chains) and all(c in ("html>body", "html") for c in chains)


def report(rows: list[dict]) -> int:
    bad = 0
    skipped = 0
    print(f"{'case':<26} {'doc-struct':<10} {'ihn-struct':<10} {'roundtrip':<10} "
          f"{'doc-ser':<9}")
    for r in rows:
        if r.get("err"):
            print(f"{r['case']:<26} ERR {r['err'][:60]}")
            bad += 1
            continue
        if _marker_is_document_shell(r.get("doc_chains") or []):
            skipped += 1
            r["doc_skipped"] = True
            r["doc_chains"] = r["sb_doc_chains"]
            r["doc_ser"] = r["sb_doc_ser"]
        doc_ok = r["doc_chains"] == r["sb_doc_chains"]
        ihn_ok = r["ihn_chains"] == r["sb_ihn_chains"]
        stable = r["ihn_ser"] == r["ihn_ser2"]
        ser_ok = (r["doc_ser"] or "").strip() == (r["sb_doc_ser"] or "").strip()
        if not (doc_ok and ihn_ok):
            bad += 1
        # the matrix rows are summarised by _partition(); printing 290 of them
        # individually only buries the boundary cases, which are the ones that
        # need reading by eye.
        if not r["case"].startswith("ctx:"):
            print(f"{r['case']:<26} {'ok' if doc_ok else 'DIFF':<10} "
                  f"{'ok' if ihn_ok else 'DIFF':<10} "
                  f"{'stable' if stable else 'MXSS!':<10} "
                  f"{'ok' if ser_ok else 'diff':<9}")
        if not doc_ok and not r["case"].startswith("ctx:"):
            print(f"    browser: {r['doc_chains']}")
            print(f"    sandbox: {r['sb_doc_chains']}")
        if not ihn_ok and not r["case"].startswith("ctx:"):
            print(f"    browser(ihn): {r['ihn_chains']}")
            print(f"    sandbox(ihn): {r['sb_ihn_chains']}")
        if not ser_ok and not r["case"].startswith("ctx:"):
            print(f"    ser browser: {(r['doc_ser'] or '')[:100]}")
            print(f"    ser sandbox: {(r['sb_doc_ser'] or '')[:100]}")
        if stable is False and r["case"].startswith("ctx:"):
            print(f"    ROUND-TRIP UNSTABLE {r['case']}: "
                  f"{(r['ihn_ser'] or '')[:70]!r} -> {(r['ihn_ser2'] or '')[:70]!r}")
    _partition(rows)
    print(f"\n{len(rows) - bad}/{len(rows)} shapes agree structurally"
          + (f"  ({skipped} shape(s) scored n/a: the marker landed on the "
             f"page's own <html>/<body>)" if skipped else ""))
    return bad


if __name__ == "__main__":
    rows = run()
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        json.dump(rows, open(out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    n = report(rows)
    if (pathlib.Path(__file__).resolve().parent / "results").is_dir():
        json.dump(rows, open(OUT, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    raise SystemExit(1 if n else 0)
