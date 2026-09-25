# -*- coding: utf-8 -*-
"""Diagnostic: re-run the async benchmark's unstable FN cases in isolation.

The full async matrix drifts between FN 6 and FN 10 across runs.  This
driver evaluates each suspect case individually -- async twice and sync
once, same budget as the batched runner (10/6/45) -- to separate

  * stable divergences (async FN while sync TP on the SAME server), from
  * environment artifacts (passes in isolation -> contention/timing).

Run:  python dev/diag_async_fn_20260925.py [port]
"""
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.runner import _MANIFEST_PATH, CaseResult, evaluate_case  # noqa: E402
from benchmark.server import run_server  # noqa: E402

SUSPECTS = [
    "pos-elem-05", "pos-dom-02", "neg-filter-05", "pos-ctoss-01",
    "pos-so2-01", "pos-scn-01", "pos-formmine-01", "pos-jsmine-01",
    "pos-tb-01",
]
BUDGET = dict(max_payloads=10, max_transforms=6, timeout=45)


def show(tag: str, r: CaseResult) -> None:
    print(f"  [{tag}] {r.case_id:16} {r.verdict:5} reqs={r.requests:4} "
          f"time={r.scan_time_s:6.1f}s findings={r.findings_count} "
          f"err={str(r.error)[:60]!r}", flush=True)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8878
    base_url = f"http://127.0.0.1:{port}"
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in manifest["cases"]}

    started = threading.Event()
    threading.Thread(target=run_server, args=(port,),
                     kwargs={"ready_callback": lambda s: started.set()},
                     daemon=True).start()
    if not started.wait(timeout=10):
        print("[!] benchmark server failed to start")
        return 1
    time.sleep(0.3)
    print(f"[*] server ready on {base_url}; {len(SUSPECTS)} suspects, "
          f"2x async + 1x sync each")

    summary: dict[str, dict[str, str]] = {}
    for cid in SUSPECTS:
        case = by_id[cid]
        print(f"\n=== {cid} (mode={case['mode']}) ===", flush=True)
        rounds = {}
        for rnd in (1, 2):
            r = evaluate_case(base_url, case, engine="async", **BUDGET)
            show(f"async#{rnd}", r)
            rounds[f"async{rnd}"] = r.verdict
        r = evaluate_case(base_url, case, engine="sync", **BUDGET)
        show("sync    ", r)
        rounds["sync"] = r.verdict
        summary[cid] = rounds

    print("\n==== SUMMARY (async FN + sync TP == real divergence) ====")
    for cid, rounds in summary.items():
        flag = "  <-- REAL DIVERGENCE" if rounds["sync"] == "TP" \
            and "FN" in (rounds["async1"], rounds["async2"]) else ""
        print(f"  {cid:16} {rounds}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
