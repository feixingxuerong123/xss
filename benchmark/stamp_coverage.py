"""Marker coverage: how many payloads can carry a marker that ALSO
lands somewhere structurally executable?

Counting "the token is in the stamped payload" is too loose -- a stamp
appended outside a quoted handler value puts the token in the tag but not in
the handler, and proves nothing.  So ask verify_semantic itself: synthesise
the response as if the server reflected the stamped payload verbatim and see
whether the structural gate confirms.

Usage: python -m benchmark.stamp_coverage
"""
from __future__ import annotations

import collections
import sys

sys.path.insert(0, ".")

from xssentinel.core import payloads as P                      # noqa: E402
from xssentinel.core import verifier                            # noqa: E402

TOK = "xssv_1234abcd"
CONTEXTS = ("html_element", "html_attribute_dq", "script_string_dq",
            "script_block", "url_href", "event_handler", "svg_context",
            "css_context", "url_javascript", "template_angular")


def _shape(p: str) -> str:
    low = p.lower()
    if "<script" in low:
        return "script-tag"
    import re
    if re.search(r"on[a-z]+\s*=", low):
        return "on*-attr"
    if "javascript:" in low:
        return "javascript-uri"
    return "no-execution-point"


def main() -> int:
    seen, rows = set(), []
    for ctx in CONTEXTS:
        for x in P.for_context(ctx):
            p = x if isinstance(x, str) else (x.get("payload") or "")
            if p and p not in seen:
                seen.add(p)
                rows.append(p)

    def confirms(stamped: str) -> bool:
        r = verifier.verify_semantic(f"<html><body>{stamped}</body></html>",
                                     TOK)
        return bool(r.get("confirmed"))

    for style in ("plain", "concat"):
        ok, bad = [], []
        for p in rows:
            m = verifier.mark(p, TOK, style=style)
            (ok if (TOK in m and confirms(m)) else bad).append(p)
        print(f"{style:<7} marker lands executable: {len(ok)}/{len(rows)} "
              f"({100 * len(ok) / len(rows):.0f}%)")
        if style == "concat":
            print("  still unstampable by shape:",
                  dict(collections.Counter(_shape(p) for p in bad)))
            for p in bad[:6]:
                print("   -", p[:70])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
