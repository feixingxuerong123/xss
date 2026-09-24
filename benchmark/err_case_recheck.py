"""Re-measure benchmark cases that ERRORED instead of being scored.

`run_benchmark.py` excludes an errored case from its rate metrics -- correct, a
scan that never finished carries no information.  Until Phase 176n it also only
*retried* errored vulnerable cases (`r.verdict != "FN"` broke the retry loop), so
an errored NEGATIVE dropped out on the first try: a full run could report
recall/precision = 1.0 while a safe case went unmeasured.  Both classes are now
retried in `runner._evaluate_with_retries`.

This tool is what a retry cannot reach.  The sweep gives every case the same
90 s ceiling and two attempts; a case that still errors there needs a budget the
sweep cannot afford per cell, and needs to be re-measured alone so nothing else
on the box is competing for loopback.  That is how `neg-graphql-01` (ERROR after
90.0 s inside the sweep) came back TN in 9.2 s on its own -- an environment
artefact, recorded as such rather than assumed to be TN.

Usage:
  python -m benchmark.err_case_recheck                     # the known two
  python -m benchmark.err_case_recheck neg-escape-05
  python -m benchmark.err_case_recheck --timeout 300 id...
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, ".")

from benchmark import runner, server                      # noqa: E402

# What `run_benchmark.py` defaults to -- the re-measurement has to use the same
# payload budget as the sweep it is filling in for, or the comparison is void.
MAX_PAYLOADS = 10
MAX_TRANSFORMS = 6
DEFAULT_CASES = ("neg-escape-05", "neg-formmine-01")


def _find(cases: list[dict], want: set[str]) -> list[dict]:
    got = {c["id"]: c for c in cases if c["id"] in want}
    missing = want - set(got)
    if missing:
        raise SystemExit(f"not in manifest: {', '.join(sorted(missing))}")
    return [got[w] for w in sorted(want)]


def main(argv: list[str]) -> int:
    timeout = 300
    if "--timeout" in argv:
        k = argv.index("--timeout") + 1
        timeout = int(argv[k])
        argv = argv[:k - 1] + argv[k + 1:]
    ids = set(argv) or set(DEFAULT_CASES)

    manifest = json.load(open(os.path.join("benchmark", "manifest.json"),
                              encoding="utf-8"))
    cases = _find(manifest["cases"] if isinstance(manifest, dict) else manifest,
                  ids)

    # Port 0, then read it back: a killed sweep leaves its fixed-port lab server
    # behind and the next client hangs in SYN_SENT.
    ready = threading.Event()
    holder: dict = {}

    def on_ready(srv):
        holder["port"] = srv.server_address[1]
        ready.set()

    th = threading.Thread(target=server.run_server, args=(0,),
                          kwargs={"ready_callback": on_ready}, daemon=True)
    th.start()
    if not ready.wait(timeout=10):
        raise SystemExit("lab server failed to start")
    base_url = f"http://127.0.0.1:{holder['port']}"
    time.sleep(0.2)

    bad = 0
    for case in cases:
        t0 = time.perf_counter()
        r = runner.evaluate_case(base_url, case, timeout,
                                 MAX_PAYLOADS, MAX_TRANSFORMS)
        scored = r.verdict not in ("ERROR", "SKIP")
        if not scored:
            bad += 1
        print(f"  {case['id']:<20} gt={case['ground_truth']:<6} "
              f"verdict={r.verdict:<6} detected={r.detected} "
              f"errors={r.error!r} {time.perf_counter()-t0:.1f}s")
    print("all cases scored" if not bad else f"{bad} case(s) still unscored")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
