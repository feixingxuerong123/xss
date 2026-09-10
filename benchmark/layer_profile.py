#!/usr/bin/env python
"""Phase 108: where does a scan spend its requests, and what buys a finding?

Motivation: the cross-tool run (Phase 107) measured us as slower than
nuclei's DAST templates (30.5s vs 13.7s, up to 12x in an earlier run).
Speed is now a measured gap, so this profiler answers the next question:
WHICH layers cost the requests, and which layers actually produce
findings?

Method (zero extra instrumentation beyond Phase 108's accounting):
  * scan a set of benchmark cases through the real Scanner API
  * per case: reset the layer counters, scan, then record
      - requests attributed to each layer
      - findings produced, attributed to the layer that owns the finding
        type (reflected -> L1, dom -> DOM, header_xss -> L8_header, ...)
  * report requests / share / findings / cost-per-finding per layer

The point is NOT to declare layers useless -- header/cookie/JSONP
injection are real vulnerabilities.  It is to see which layers are paying
full price on EVERY endpoint regardless of whether the endpoint can
possibly carry that vector.

Usage:
    python benchmark/layer_profile.py
    python benchmark/layer_profile.py --ids pos-elem-01,neg-escape-01
    python benchmark/layer_profile.py --md benchmark/results/layer_profile.md
"""
from __future__ import annotations

import argparse
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

from benchmark.server import BenchmarkHandler, load_routes  # noqa: E402

# finding type -> the layer that produced it.  Types not listed fall back
# to "(other)" so a new finding type shows up instead of being hidden.
TYPE_TO_LAYER = {
    "reflected": "L1_reflected",
    "dom": "L3_dom",
    "dom_dynamic": "L3_dom",
    "header_xss": "L8_header",
    "cookie_xss": "L8_cookie",
    "jsonp": "L7_jsonp",
    "cors": "L7_cors",
    "path_xss": "L8_path",
    "error_xss": "L8_error_page",
    "markdown_xss": "L8_markdown",
    "css_injection": "L8_css",
    "postmessage_xss": "L7_postmessage",
    "prototype_pollution": "L7_prototype",
    "service_worker_xss": "L7_service_worker",
    "web_worker_xss": "L7_web_worker",
    "template_xss": "L7_template",
    "dom_clobbering": "L7_dom_clobber",
    "mutation_xss": "L7_mutation",
    "upload_xss": "L9_upload_filename",
    "stored_upload": "L9_upload_filename",
    "stored": "L6_stored",
    "second_order": "L6_second_order",
    "blind": "L4_blind",
    "csp_nonce": "L1_csp_nonce",
}

DEFAULT_IDS = [
    "pos-elem-01", "pos-attr-01", "pos-attr-05", "pos-script-01",
    "pos-comment-01", "pos-url-01", "pos-dom-01", "pos-svg-01",
    "neg-escape-01", "neg-comment-01", "neg-attr-01", "neg-csp-01",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="")
    ap.add_argument("--md", default=os.path.join(
        _HERE, "results", "layer_profile.md"))
    ap.add_argument("--json", default=os.path.join(
        _HERE, "results", "layer_profile.json"))
    ap.add_argument("--port", type=int, default=8893)
    ap.add_argument("--max-payloads", type=int, default=10)
    ap.add_argument("--max-transforms", type=int, default=6)
    args = ap.parse_args()

    from xssentinel.core import coverage as cov
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    man = json.load(open(os.path.join(_HERE, "manifest.json"),
                         encoding="utf-8"))
    all_cases = man["cases"] if isinstance(man, dict) else man
    by_id = {c["id"]: c for c in all_cases}
    ids = [s.strip() for s in args.ids.split(",") if s.strip()] \
        or DEFAULT_IDS
    cases = [by_id[i] for i in ids if i in by_id]

    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{args.port}"
    time.sleep(0.5)

    per_layer: dict = {}
    per_case = []
    total_requests = 0
    total_findings = 0
    t0 = time.time()
    try:
        for c in cases:
            cov.reset_layer_request_counts()
            sc = Scanner(requester=Requester(timeout=10), verbose=False,
                         max_payloads=args.max_payloads,
                         max_transforms=args.max_transforms)
            sc.use_headless = False
            sc.scan_endpoint(f"{base}{c['path']}", method="GET",
                             params={c.get("param", "q"): "probe"}, data={})
            counts = cov.layer_request_counts()
            reqs = sum(counts.values())
            total_requests += reqs

            # attribute findings to layers
            contributed = {}
            for f in sc.findings:
                ftype = (f.data or {}).get("type") or ""
                layer = TYPE_TO_LAYER.get(ftype, "(other)")
                contributed[layer] = contributed.get(layer, 0) + 1
                total_findings += 1

            for layer, n in counts.items():
                d = per_layer.setdefault(
                    layer, {"requests": 0, "findings": 0, "cases": 0})
                d["requests"] += n
                d["cases"] += 1
            for layer, n in contributed.items():
                per_layer.setdefault(
                    layer, {"requests": 0, "findings": 0, "cases": 0}
                )["findings"] += n

            per_case.append({
                "case": c["id"], "requests": reqs,
                "findings": len(sc.findings),
                "layers": len(counts),
                "top_layer": max(counts, key=counts.get) if counts else None,
            })
            print(f"  {c['id']:20} requests={reqs:4} findings="
                  f"{len(sc.findings)} layers={len(counts)}", flush=True)
    finally:
        srv.shutdown()

    rows = []
    for layer, d in per_layer.items():
        reqs = d["requests"]
        fnd = d["findings"]
        rows.append({
            "layer": layer, "requests": reqs, "findings": fnd,
            "share": round(100.0 * reqs / total_requests, 1)
            if total_requests else 0.0,
            "cost_per_finding": (round(reqs / fnd, 1) if fnd else None),
        })
    rows.sort(key=lambda r: -r["requests"])

    out = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cases": len(cases), "total_requests": total_requests,
        "total_findings": total_findings,
        "elapsed_s": round(time.time() - t0, 1),
        "layers": rows, "per_case": per_case,
    }
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    lines = ["# Layer cost profile (where the requests go)", "",
             f"Generated: {out['generated']}  ",
             f"Cases: {len(cases)}  Requests: {total_requests}  "
             f"Findings: {total_findings}  Elapsed: {out['elapsed_s']}s",
             "",
             "| layer | requests | share | findings | req/finding |",
             "|---|---|---|---|---|"]
    for r in rows:
        cpf = r["cost_per_finding"] if r["cost_per_finding"] else "-"
        lines.append(f"| {r['layer']} | {r['requests']} | {r['share']}% | "
                     f"{r['findings']} | {cpf} |")
    with open(args.md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n[+] {total_requests} requests for {total_findings} findings "
          f"in {out['elapsed_s']}s")
    print(f"[+] saved {args.md} and {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
