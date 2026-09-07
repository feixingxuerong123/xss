# -*- coding: utf-8 -*-
"""Dump the per-request shape a benchmark case generates (server side)."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import Counter
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from benchmark.server import load_routes, BenchmarkHandler
from benchmark.runner import evaluate_case

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8930
CASE_ID = sys.argv[1] if len(sys.argv) > 1 else "neg-escape-01"
ENGINE = sys.argv[3] if len(sys.argv) > 3 else "sync"

cases = json.load(open(os.path.join(_HERE, "manifest.json"),
                       encoding="utf-8"))["cases"]
case = next(c for c in cases if c["id"] == CASE_ID)

BenchmarkHandler.routes = load_routes()

seen = []


def _log(self, fmt, *args):
    line = fmt % args
    if " " in line:
        seen.append(line)


BenchmarkHandler.log_message = _log
srv = ThreadingHTTPServer(("127.0.0.1", PORT), BenchmarkHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.6)
base = f"http://127.0.0.1:{PORT}"

res = evaluate_case(base, case, timeout=90, max_payloads=14,
                    max_transforms=12, engine=ENGINE)
print(f"[verdict] {res.verdict} findings={res.findings_count} "
      f"time={res.scan_time_s:.2f}s scanner_reqs={res.requests} "
      f"server_saw={len(seen)}")
paths = Counter()
for line in seen:
    # '"GET /s/esc01?q=.... HTTP/1.1" 200 -' -> (method, path, query-shape)
    try:
        reqline = line.split('"')[1]
        method, full = reqline.split(" ", 1)[0], reqline.split(" ", 1)[1]
        path, _, q = full.partition("?")
        # bucket query values: keep param name + length bucket + charset hint
        import urllib.parse as up
        parts = [f"{k}={'V' * min(len(v) // 10, 4)}" if v else k
                 for k, v in up.parse_qsl(q, keep_blank_values=True)]
        paths[f"{method} {path}?{'&'.join(parts) or '-'}"] += 1
    except Exception:
        paths[line[:80]] += 1
print("-- server-side request shapes --")
for shape, n in paths.most_common(30):
    print(f"  {n:4d}x {shape}")
print("-- sample raw long-payload queries --")
shown = 0
for line in seen:
    try:
        reqline = line.split('"')[1]
        method, full = reqline.split(" ", 1)[0], reqline.split(" ", 1)[1]
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(full).query, keep_blank_values=True)
        v = (q.get("q") or [""])[0]
        if len(v) >= 30 and shown < 8:
            print(f"  {v[:110]}")
            shown += 1
    except Exception:
        pass
srv.shutdown()
