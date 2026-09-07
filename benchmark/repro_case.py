# -*- coding: utf-8 -*-
"""Reproduce one benchmark case and dump the finding(s) that fired."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from benchmark.server import load_routes, BenchmarkHandler  # noqa: E402
from benchmark.runner import evaluate_case  # noqa: E402

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8893
CASE_ID = sys.argv[1] if len(sys.argv) > 1 else "neg-escape-03"
ENGINE = sys.argv[3] if len(sys.argv) > 3 else "sync"

cases = json.load(open(os.path.join(_HERE, "manifest.json"),
                       encoding="utf-8"))["cases"]
case = next(c for c in cases if c["id"] == CASE_ID)

BenchmarkHandler.routes = load_routes()
srv = ThreadingHTTPServer(("127.0.0.1", PORT), BenchmarkHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.6)
base = f"http://127.0.0.1:{PORT}"

# 1) raw behaviour of the endpoint
import urllib.request  # noqa: E402
import urllib.parse  # noqa: E402
probe = "Pz'\"<z>"
url = f"{base}{case['path']}?{urllib.parse.urlencode({case['param']: probe})}"
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        body = r.read().decode("utf-8", "replace")
    print(f"[endpoint] GET {url}\n[response] {body[:600]}\n")
except Exception as e:
    print(f"[endpoint] probe failed: {e}\n")

# 2) scanner verdict + finding details
res = evaluate_case(base, case, timeout=90, max_payloads=14,
                    max_transforms=12, engine=ENGINE)
print(f"[verdict] {res.verdict} detected={res.detected} "
      f"findings={res.findings_count} time={res.scan_time_s:.2f}s "
      f"requests={res.requests} err={res.error}")
for d in (getattr(res, "finding_details", None) or []):
    print("  -", json.dumps(d, ensure_ascii=False)[:400])
srv.shutdown()
