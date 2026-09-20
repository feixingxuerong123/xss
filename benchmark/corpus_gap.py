"""Which shipped payloads has the referee never seen?

`data/payloads.json` is what the scanner actually sends.  `browser_dom_oracle.
json` is what the sandbox's rules are allowed to be believed about.  Those two
sets are maintained separately, so a payload family can sit in the corpus for
hundreds of rounds of "MISSED 0 / OVER 0" without ever being judged -- which is
exactly how the SMIL timing family (`<svg><animate onbegin=...>`, 27 payloads)
stayed unmeasured while the sandbox claimed an answer for it.

This reports the gap: every corpus string whose interesting tokens (tag names,
`on*` handler names, URL-bearing attributes) never appear anywhere in the
oracle's documents, grouped by token so the answer is a work list rather than a
number.  A token being *present* in the oracle is not the same as that payload
having been judged -- it says only that the shape is in play.

Usage:
  python -m benchmark.corpus_gap                 # top 30 unseen tokens
  python -m benchmark.corpus_gap --show 60       # print the payload strings
  python -m benchmark.corpus_gap --json out.json
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAYLOADS = _ROOT / "xssentinel" / "data" / "payloads.json"
ORACLE = _ROOT / "benchmark" / "results" / "browser_dom_oracle.json"
EXTRA_GROUND_TRUTH = [                     # other measured corpora that count
    _ROOT / "benchmark" / "results" / "sink_execution.json",
    _ROOT / "benchmark" / "results" / "foreign_breakout.json",
    _ROOT / "benchmark" / "results" / "option_probe.json",
    _ROOT / "benchmark" / "results" / "nul_probe.json",
    _ROOT / "benchmark" / "results" / "smil_probe.json",
    _ROOT / "benchmark" / "results" / "mxss_family.json",
]

_TAG_RE = re.compile(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9:-]*)")
_EVT_RE = re.compile(r"\b(on[a-z]+)\s*=", re.I)
_URL_ATTR_RE = re.compile(
    r"\b(href|src|srcdoc|action|formaction|data|code|background|xlink:href)"
    r"\s*=", re.I)


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def _tokens(text: str) -> set[str]:
    out = {m.group(1).lower() for m in _TAG_RE.finditer(text)}
    out |= {m.group(1).lower() for m in _EVT_RE.finditer(text)}
    out |= {m.group(1).lower() for m in _URL_ATTR_RE.finditer(text)}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--show", type=int, default=30,
                    help="how many unseen tokens to print with their payloads")
    ap.add_argument("--json", metavar="PATH", default=None)
    args = ap.parse_args(argv)

    corpus = set(_strings(json.loads(PAYLOADS.read_text(encoding="utf-8"))))
    known = " ".join(_strings(json.loads(ORACLE.read_text(encoding="utf-8"))))
    covered_by: dict[str, str] = {}
    for path in EXTRA_GROUND_TRUTH:
        if not path.exists():
            continue
        blob = " ".join(_strings(json.loads(path.read_text(encoding="utf-8"))))
        covered_by[path.name] = blob

    seen_in_oracle = 0
    unseen: dict[str, list[str]] = collections.defaultdict(list)
    for text in sorted(corpus):
        if len(text) < 6 or len(text) > 400:
            continue
        toks = _tokens(text)
        if not toks:
            continue
        if all(t in known for t in toks):
            seen_in_oracle += 1
            continue
        # a payload counts as covered by *any* measured corpus that carries every
        # token it uses -- those files are referee evidence too
        if any(all(t in blob for t in toks) for blob in covered_by.values()):
            seen_in_oracle += 1
            continue
        for t in sorted(toks):
            if t not in known:
                unseen[t].append(text)

    print(f"corpus strings: {len(corpus)}   token-covered by measured corpora: "
          f"{seen_in_oracle}   with at least one never-measured token: "
          f"{len(corpus) - seen_in_oracle}")
    print("\ntokens that no measured corpus has ever judged "
          "(count = payloads using them):")
    ordered = sorted(unseen.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    out_rows = []
    for tok, payloads in ordered[:args.show]:
        print(f"  {tok:<22}{len(payloads):<6}{payloads[0][:78]}")
        out_rows.append({"token": tok, "n": len(payloads),
                         "example": payloads[0],
                         "in_sandbox_tables": tok in _sandbox_tokens()})
    if args.json:
        json.dump(out_rows, open(args.json, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("written:", args.json)
    return 0


def _sandbox_tokens() -> str:
    """The element/event/attribute names the sandbox has a rule about, so a gap
    can be told apart from 'this project simply never sends that shape'.

    The tables are mixed -- sets of names, dicts of dicts, one tuple list -- so
    the names are pulled out with the same generic walk used on the corpora.
    """
    try:
        from xssentinel.core import sandbox as sb
    except ImportError:
        return ""                       # optional-module degradation only; a
                                        # real import bug must not be swallowed
    parts: list[str] = []
    for name in dir(sb):
        if not name.isupper():
            continue
        parts.extend(_strings(getattr(sb, name)))
    return " ".join(parts).lower()


if __name__ == "__main__":
    raise SystemExit(main())
