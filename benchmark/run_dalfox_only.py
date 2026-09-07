#!/usr/bin/env python
"""Run dalfox-only comparison against the 98-case benchmark (no XSSentinel).

Adds per-case progress + exception guards + guaranteed save (finally).
"""
from __future__ import annotations

import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from benchmark.server import load_routes, BenchmarkHandler  # noqa: E402
from benchmark.adapters import get_adapters, run_comparison  # noqa: E402
from http.server import HTTPServer  # noqa: E402
import threading  # noqa: E402

PORT = 8878

def main():
    adapters = [a for a in get_adapters(only_available=True) if a.name == "dalfox"]
    if not adapters:
        print("[!] dalfox not found in PATH")
        return 1
    print(f"[*] dalfox binary: {adapters[0]._binary}", flush=True)

    routes = load_routes()
    BenchmarkHandler.routes = routes
    server = HTTPServer(("127.0.0.1", PORT), BenchmarkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    manifest_path = os.path.join(_HERE, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    cases = manifest["cases"]
    base_url = f"http://127.0.0.1:{PORT}"
    print(f"[*] Running dalfox on {len(cases)} cases (port {PORT})", flush=True)

    comparison = None
    try:
        comparison = run_comparison(base_url, cases, adapters=adapters, verbose=False)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"[!] run_comparison failed: {e}", flush=True)

    if comparison:
        m = comparison.get("dalfox", {})
        print("=" * 64, flush=True)
        print(f"  dalfox: tp={m.get('tp')} fp={m.get('fp')} tn={m.get('tn')} "
              f"fn={m.get('fn')} errors={m.get('errors', 0)}", flush=True)
        print(f"  recall={m.get('recall'):.4f} precision={m.get('precision'):.4f} "
              f"fpr={m.get('fpr'):.4f} f1={m.get('f1'):.4f} "
              f"time={m.get('total_time_s', 0):.1f}s", flush=True)
        print("=" * 64, flush=True)
        for d in m.get("details", []):
            if d.get("verdict") in ("FP", "FN", "ERROR"):
                print(f"  [{d.get('verdict')}] {d.get('case_id')} "
                      f"err={d.get('error')}", flush=True)

        out = os.path.join(_HERE, "results",
                           f"dalfox_standalone_{time.strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(comparison, f, indent=2, ensure_ascii=False)
            print(f"[+] Saved: {out}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[!] Save failed: {e}", flush=True)
    else:
        print("[!] No comparison data", flush=True)

    try:
        server.shutdown()
    except Exception:  # noqa: BLE001
        pass
    print("[*] DONE", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
