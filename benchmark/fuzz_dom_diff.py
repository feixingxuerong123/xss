"""Random differential fuzzing of the sandbox against Chromium's own DOM.

Everything the sandbox is trusted for right now rests on shapes a human thought
of: 45-60 payloads x 20 hosts in the oracle, the 105-name select matrix, the NUL
and media probes.  That has caught real bugs -- select scoping, three NUL rules,
a bare `<track>` -- but it can only catch bugs in shapes somebody already
imagined.  This generates markup instead.

The comparison is deliberately narrow and therefore hard to get wrong:

    bytes -> Chromium: div.innerHTML = s ; read div.innerHTML  (round-trip x2)
    bytes -> sandbox   : serialize(parse(s, fragment=True).root)  (round-trip x2)

No execution, no sentinel, no settle window, so none of the "browser said False
because we looked too early" failure mode that bit this project three times is
even available here.  Either the serialisation agrees byte for byte or it does
not.

A mismatch is not a finding until it is small, so every failing input goes
through greedy delta-debugging over tag/text chunks: the smallest sequence that
still disagrees is what gets reported and what should become a regression test.

Usage:
  python -m benchmark.fuzz_dom_diff --trials 300
  python -m benchmark.fuzz_dom_diff --seed 7 --trials 2000 --json out.json
  python -m benchmark.fuzz_dom_diff --demo        # fixed 6 inputs, prints both sides
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from xssentinel.core import sandbox  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "fuzz_dom_diff.json"

# Containers whose content model is where parsers and hand-written models part
# company.  Every one of these was added because a real bug lives near it.
CONTAINERS = [
    "div", "span", "p", "form", "a", "table", "tbody", "tr", "td", "caption",
    "select", "option", "optgroup", "textarea", "title", "style", "script",
    "xmp", "iframe", "noframes", "noscript", "plaintext", "template", "svg",
    "math", "mtext", "foreignObject", "details", "marquee", "video", "audio",
    "source", "track", "animate", "set", "object", "embed", "label", "button",
    "input", "img", "br", "hr", "base", "link", "meta", "keygen", "isindex",
]
VOID = {"img", "br", "hr", "input", "base", "link", "meta", "keygen",
        "col", "source", "track", "wbr", "area"}

ATTR_NAMES = ["class", "id", "sr\x00c", "o\x00nerror", "onerror", "href",
              "src", "srcdoc", "xlink:href", "data-x", "attributename",
              "begin", "to", "open", "tabindex", "autofocus", "style", "type",
              "kind", "default", "width", "dur", "value", "content"]
ATTR_VALUES = ["", "x", "a b", '"q"', "'s'", "<t>", "&lt;", "&quot;", "&#0;",
               "jav&#x00;ascript:x", "javascript:x", "a\x00b", "a\ufffdb",
               "&#34;", "&amp;", " ", "\t", "/x", "0", "indefinite", "1s"]

TEXT_BITS = ["", "t", "a b", "<", ">", "</", "/*", "-->", "]]>", "&", "&amp;",
             "&nbsp;", "\x00", "\ufffd", "\xa0", "\n", "<!--", "<![CDATA[",
             "]]", "'\"", "&lt;script&gt;", " ]]> ", "onmouseover="]
TAGS_AFTER_OPEN = ["", "/", "!", "?", "--", "!--", ":"]


def _attrs(rnd: random.Random) -> str:
    out = []
    for _ in range(rnd.randint(0, 3)):
        name = rnd.choice(ATTR_NAMES)
        if rnd.random() < 0.12:
            out.append(name)                                  # valueless
            continue
        val = rnd.choice(ATTR_VALUES)
        style = rnd.choices(["dq", "sq", "uq", "spacey"],
                            weights=[45, 20, 25, 10])[0]
        if style == "dq":
            out.append(f'{name}="{val}"')
        elif style == "sq":
            out.append(f"{name}='{val}'")
        elif style == "uq":
            # Unquoted values end at whitespace, so a value containing a space
            # silently splits the tag in half -- that is the interesting case.
            out.append(f"{name}={val}")
        else:
            out.append(f"{name} = {val}")
    sep = rnd.choice([" ", " ", " ", "  ", "\n", "\t"])
    return (sep + sep.join(out)) if out else ""


def _frag(rnd: random.Random, depth: int) -> str:
    """One randomly-shaped piece of markup."""
    roll = rnd.random()
    if depth <= 0:
        return rnd.choice(TEXT_BITS)
    if roll < 0.22:
        return rnd.choice(TEXT_BITS)
    if roll < 0.28:
        return f"<!--{rnd.choice(TEXT_BITS)}-->"
    if roll < 0.31:
        return f"<{rnd.choice(TAGS_AFTER_OPEN)}{rnd.choice(TEXT_BITS)}>"
    if roll < 0.36:
        return f"</{rnd.choice(CONTAINERS)}>"          # unbalanced closer
    tag = rnd.choice(CONTAINERS)
    a = _attrs(rnd)
    sc = "/" if (tag in VOID and rnd.random() < 0.3) else ""
    open_tag = f"<{tag}{a}{sc}>"
    if tag in VOID or rnd.random() < 0.10:
        return open_tag
    inner = "".join(_frag(rnd, depth - 1)
                    for _ in range(rnd.randint(0, 3)))
    close = f"</{tag}>"
    if rnd.random() < 0.12:
        close = rnd.choice(["", f"</ {tag}>", f"</{tag.upper()}>", f"</{tag}"])
    return open_tag + inner + close


def random_doc(rnd: random.Random) -> str:
    return "".join(_frag(rnd, rnd.randint(1, 3))
                   for _ in range(rnd.randint(1, 4)))


# --------------------------------------------------------------------------
# The browser side: two chained innerHTML round-trips of the same bytes.
# --------------------------------------------------------------------------

_PROBE = """
(o) => {
  const a = document.createElement('div');
  a.innerHTML = o.html;
  const s1 = a.innerHTML;
  const b = document.createElement('div');
  b.innerHTML = s1;
  const s2 = b.innerHTML;
  return {s1: s1, s2: s2, n1: a.querySelectorAll('*').length,
          n2: b.querySelectorAll('*').length};
}
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        raw = b"<html><body></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


_CHUNK_RE = re.compile(r"(<[^>]*>?)|([^<]+)")


def _chunks(s: str) -> list[str]:
    return [m.group(0) for m in _CHUNK_RE.finditer(s)] or ([s] if s else [])


def differs(html: str, br) -> bool:
    mine = sandbox.serialize(sandbox.parse(html, fragment=True).root)
    if mine != br["s1"]:
        return True
    return sandbox.serialize(sandbox.parse(mine, fragment=True).root) != br["s2"]


def shrink(html: str, br_fn, budget: int = 90) -> tuple[str, int]:
    """Greedy delta debugging over chunk lists: keep only what the mismatch
    needs.  `br_fn` re-measures a candidate in the browser (that is the whole
    cost, so it is counted and capped)."""
    cur = html
    used = 0
    changed = True
    while changed and used < budget:
        changed = False
        parts = _chunks(cur)
        for size in (max(1, len(parts) // 2), max(1, len(parts) // 4), 1):
            i = 0
            while i < len(parts) and used < budget:
                cand = "".join(parts[:i] + parts[i + size:])
                if cand != cur:
                    used += 1
                    try:
                        br = br_fn(cand)
                    except Exception:
                        return cur, used
                    if br and differs(cand, br):
                        cur = cand
                        changed = True
                        parts = _chunks(cur)
                        continue
                i += max(1, size // 2)
    return cur, used


def _skeleton(s: str) -> str:
    """The tag sequence with text and attribute values stripped.

    Without this the report fills its 40 slots with forty near-identical
    instances of one mechanism, because random generation reproduces whatever is
    most common.  Deduplicating on the skeleton is what turns the output into a
    list of distinct bugs.
    """
    tags = [m.group(1).lower() for m in re.finditer(r"<\s*/?\s*([a-zA-Z][\w:-]*)", s)]
    return ",".join(tags) or "(no tags)"


def run(trials: int, seed: int, json_out: str, demo: bool) -> int:
    from playwright.sync_api import sync_playwright

    rnd = random.Random(seed)
    srv, base = _serve()
    found: list[dict] = []
    seen: dict[str, int] = {}
    total = 0
    n_err = 0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context().new_page()
            for attempt in range(3):
                try:
                    page.goto(base + "/", wait_until="load")
                    break
                except Exception:
                    page.wait_for_timeout(150 * (attempt + 1))

            def measure(s: str):
                try:
                    return page.evaluate(_PROBE, {"html": s})
                except Exception:
                    return None

            if demo:
                for s in [random_doc(rnd) for _ in range(6)]:
                    br = measure(s)
                    mine = sandbox.serialize(sandbox.parse(s, fragment=True).root)
                    print("IN   :", repr(s)[:120])
                    print("CHROM:", repr(br["s1"])[:120] if br else "ERR")
                    print("MINE :", repr(mine)[:120])
                    print("agree:", bool(br and br["s1"] == mine), "\n")
                browser.close()
                return 0

            for t in range(trials):
                doc = random_doc(rnd)
                br = measure(doc)
                if br is None:
                    n_err += 1
                    continue
                if not differs(doc, br):
                    continue
                total += 1
                minimal, q = shrink(doc, measure)
                sk = _skeleton(minimal)
                if sk in seen or len(found) >= 40:
                    seen.setdefault(sk, 0)
                    seen[sk] += 1
                    continue
                seen[sk] = 1
                br2 = measure(minimal)
                mine = sandbox.serialize(sandbox.parse(minimal, fragment=True).root)
                found.append({"trial": t, "seed": seed, "input": minimal,
                              "skeleton": sk, "raw_len": len(doc),
                              "shrink_queries": q,
                              "chromium": (br2 or {}).get("s1"),
                              "sandbox": mine})
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()

    print(f"trials={trials} seed={seed} browser-errors={n_err} "
          f"mismatching trials={total} distinct mechanisms={len(found)} "
          f"(+{max(0, len(seen) - len(found))} further skeletons not printed)")
    cluster: collections.Counter = collections.Counter()
    for f in found:
        cluster[tuple(f["skeleton"].split(",")[:3])] += 1
    for sig, n in cluster.most_common(12):
        print(f"   x{n:<3} {'/'.join(sig)}")
    for f in found[:12]:
        print(f"\n--- trial {f['trial']} (shrunk in {f['shrink_queries']} probes, "
              f"{f['raw_len']} -> {len(f['input'])} bytes) skeleton={f['skeleton']}")
        print("    in : " + repr(f["input"])[:150])
        print("    chr: " + repr(f["chromium"])[:150])
        print("    mine:" + repr(f["sandbox"])[:150])
    dest = json_out or str(OUT)
    pathlib.Path(dest).parent.mkdir(parents=True, exist_ok=True)
    json.dump({"seed": seed, "trials": trials, "mismatching_trials": total,
               "distinct_skeletons": len(seen), "mismatches": found},
              open(dest, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\nwritten:", dest)
    return len(found)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20260920)
    ap.add_argument("--json", default=None)
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()
    raise SystemExit(1 if run(a.trials, a.seed, a.json, a.demo) else 0)
