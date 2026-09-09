# -*- coding: utf-8 -*-
"""Batched evaluator for the full 98-case benchmark (loopback-degradation safe).

``run_benchmark.py`` runs every case inside ONE long-lived process; on
machines where a security agent intermittently kills loopback connections
(WinError 10053/10054) that process stalls mid-matrix and never completes.

This runner is the workaround -- and the preferred local entry point on
Windows:

  * cases are evaluated in small batches (default 6) instead of one long run
  * partial results are flushed to JSON after EVERY batch, so a kill never
    loses prior work and a re-run resumes from where it stopped
  * a batch that errors is retried once before giving up on those cases
  * Phase 97: an FN whose shape says ENVIRONMENT (timeout / zero requests /
    wall time at the ceiling) is re-evaluated once; the retry REPLACES the
    record and the first run is preserved inside a ``fn_retry`` note, so
    the substitution is auditable.  A real code FN (normal finish, normal
    request count) is never retried.  Cross-run comparisons must check
    ``meta.fn_retry_on`` -- the FN semantics differ when it flips.

Verified: full 98 cases in ~7 min on a machine where run_benchmark.py could
not finish once in 7 attempts.

Usage::

    python benchmark/run_benchmark_batched.py [out.json] [batch_size] [port]
                                              [sync|async] [max_payloads]
                                              [max_transforms] [timeout]

Positional 4-7 are optional and default to sync / 10 / 6 / 45.  Pass
``sync 14 12 90`` to reproduce the calibrated numbers that
``python -m benchmark.runner`` produces (that entry point defaults to
max_payloads=14, max_transforms=12, timeout=90).  The budget is recorded
in the output file's ``meta`` block so two runs are never silently
compared at different budgets.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

from benchmark.server import load_routes, BenchmarkHandler  # noqa: E402
from benchmark.runner import evaluate_case  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else "benchmark/results/batch_full.json"
BATCH = int(sys.argv[2]) if len(sys.argv) > 2 else 6
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8877
ENGINE = sys.argv[4] if len(sys.argv) > 4 else "sync"
if ENGINE not in ("sync", "async"):
    sys.exit(f"engine must be sync or async, got {ENGINE!r}")
MAX_PAYLOADS = int(sys.argv[5]) if len(sys.argv) > 5 else 10
MAX_TRANSFORMS = int(sys.argv[6]) if len(sys.argv) > 6 else 6
TIMEOUT = int(sys.argv[7]) if len(sys.argv) > 7 else 45

# Phase 101: how a degraded-FN is re-confirmed.  On this host a loopback
# degradation window can outlast a single immediate retry (observed:
# neg-rcdata-02 timed out twice in p97 and reproduced as TP in 13
# requests standalone -- the window, not the scanner, decided it).  So:
# retry up to FN_RETRY_MAX times, pausing FN_RETRY_WAIT seconds between
# attempts to let the window pass.  Only degraded-shaped FNs are retried
# (see _is_degraded_fn) and only FNs pay this cost.
FN_RETRY_MAX = int(os.environ.get("XSS_FN_RETRY_MAX", "2"))
FN_RETRY_WAIT = float(os.environ.get("XSS_FN_RETRY_WAIT", "20"))


def start_server(port: int) -> ThreadingHTTPServer:
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import http.client
    for _ in range(40):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/health")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return srv
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("server did not become ready")


def load_cases():
    with open(os.path.join(_HERE, "manifest.json"),
              "r", encoding="utf-8") as f:
        return json.load(f)["cases"]


def manifest_id() -> str:
    """Fingerprint of the manifest so resumed results can be validated
    against the manifest that produced them (audit: stale records must not
    silently mix into a run after manifest edits)."""
    import hashlib
    with open(os.path.join(_HERE, "manifest.json"), "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()[:12]


_META = {  # budget of THIS runner (audit: cross-run comparison needs it)
    "runner": "run_benchmark_batched.py",
    "max_payloads": MAX_PAYLOADS,
    "max_transforms": MAX_TRANSFORMS,
    "timeout": TIMEOUT,
    "engine": ENGINE,
    "batch": BATCH,
    "fn_retry_on": True,   # Phase 97: degraded-FN second confirmation
    "fn_retry_max": FN_RETRY_MAX,
    "fn_retry_wait": FN_RETRY_WAIT,
}

FN_RETRY_BUDGET_KEYS = ("engine", "max_payloads", "max_transforms",
                        "timeout", "fn_retry_on", "fn_retry_max",
                        "fn_retry_wait")


def _log_fn_exhausted(rec: dict) -> None:
    """Note (in the printed log only) that retries were exhausted.

    The record itself already carries every attempt inside fn_retry, so
    nothing needs to be added -- this only makes the exhausted case
    obvious in a long run's console output.
    """
    print(f"  [fn-retry] {rec.get('case_id')}: still degraded after "
          f"{FN_RETRY_MAX} attempt(s) -- recorded as FN", flush=True)


def _is_degraded_fn(rec: dict) -> bool:
    """Phase 97: an FN whose SHAPE says 'environment', not 'engine'.

    On the degraded-loopback host a vulnerable case dies mid-scan: the
    CLI times out, a request never gets through (requests == 0), or the
    wall time hits the ceiling.  Those runs measure the ENVIRONMENT, not
    the scanner, so they are re-evaluated once.  A REAL code FN finishes
    normally with a normal request count and no error -- it must stay
    visible for human judgment and is NOT retried.
    """
    if rec.get("verdict") != "FN":
        return False
    if rec.get("error"):
        return True
    if rec.get("requests", 0) == 0:
        return True
    if rec.get("scan_time_s", 0) >= 0.9 * TIMEOUT:
        return True
    return False


def _atomic_flush(out_path, rows, tp, fp, tn, fn, err, mid):
    """Write results via tmp + os.replace so a mid-write kill can never
    truncate the output file and lose all resumed progress."""
    import tempfile
    # fn_retry_* are read at WRITE time (not at import): the retry policy
    # may be tuned after import (env vars, tests), and the meta block must
    # describe the policy that actually produced these records.
    doc = {"meta": {"manifest_id": mid, **_META,
                    "fn_retry_max": FN_RETRY_MAX,
                    "fn_retry_wait": FN_RETRY_WAIT},
           "cases": rows,
           "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                      "errors": err}}
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    os.replace(tmp_path, out_path)  # atomic on POSIX and Windows


def main() -> int:
    done: dict[str, dict] = {}
    mid = manifest_id()
    if os.path.isfile(OUT):                       # resume support
        try:
            with open(OUT, "r", encoding="utf-8") as f:
                saved = json.load(f)
            done = {c["case_id"]: c for c in saved.get("cases", [])}
            prev_mid = (saved.get("meta") or {}).get("manifest_id")
            prev_meta = saved.get("meta") or {}
            _budget_keys = FN_RETRY_BUDGET_KEYS
            prev_budget = {k: prev_meta.get(k) for k in _budget_keys}
            my_budget = {k: _META[k] for k in _budget_keys}
            if prev_mid != mid:
                print(f"[!] manifest changed ({prev_mid} -> {mid}); "
                      f"discarding {len(done)} stale results")
                done = {}
            elif prev_budget != my_budget:
                print(f"[!] budget changed ({prev_budget} -> {my_budget}); "
                      f"discarding {len(done)} results measured at the "
                      f"old budget")
                done = {}
            else:
                print(f"[*] resume: {len(done)} cases already done "
                      f"(manifest {mid})")
        except Exception:
            done = {}

    cases = load_cases()
    todo = [c for c in cases if c["id"] not in done]
    print(f"[*] total {len(cases)} cases, {len(todo)} to run (batch={BATCH})")

    srv = start_server(PORT)
    base = f"http://127.0.0.1:{PORT}"
    t0 = time.time()

    def _eval(c: dict) -> dict:
        """Evaluate one case and shape it into a result record."""
        res = evaluate_case(
            base, c, timeout=TIMEOUT,
            max_payloads=MAX_PAYLOADS,
            max_transforms=MAX_TRANSFORMS,
            engine=ENGINE)
        return {
            "case_id": res.case_id, "path": res.path,
            "param": res.param, "mode": res.mode,
            "ground_truth": res.ground_truth,
            "context": res.context,
            "difficulty": res.difficulty,
            "detected": res.detected, "verdict": res.verdict,
            "scan_time_s": round(res.scan_time_s, 2),
            "findings_count": res.findings_count,
            "requests": res.requests,
            "error": res.error,
        }

    def _error_rec(c: dict, e: Exception) -> dict:
        return {"case_id": c["id"], "path": c.get("path"),
                "param": c.get("param"), "mode": c.get("mode"),
                "ground_truth": c.get("ground_truth"),
                "context": c.get("context"),
                "difficulty": c.get("difficulty"),
                "detected": False, "verdict": "ERROR",
                "scan_time_s": 0.0, "findings_count": 0,
                "requests": 0,
                "error": f"{type(e).__name__}: {e}"}

    try:
        for i in range(0, len(todo), BATCH):
            chunk = todo[i:i + BATCH]
            for attempt in (1, 2):
                for c in chunk:
                    if c["id"] in done:
                        continue
                    try:
                        rec = _eval(c)
                    except Exception as e:
                        rec = _error_rec(c, e)
                    # Phase 97: second-confirmation retry for FNs shaped
                    # like environment failures.  The retry REPLACES the
                    # record and the first run is preserved inside the
                    # fn_retry note, so the substitution is always
                    # auditable -- never silently discarded.
                    if _is_degraded_fn(rec):
                        attempts = [{k: rec.get(k) for k in
                                     ("verdict", "scan_time_s", "requests",
                                      "error")}]
                        for _attempt in range(1, FN_RETRY_MAX + 1):
                            if _attempt > 1:
                                # Let the degradation window pass: an
                                # immediate second retry only re-measures
                                # the same broken loopback.
                                time.sleep(FN_RETRY_WAIT)
                            try:
                                rec2 = _eval(c)
                            except Exception as e2:
                                rec["fn_retry"] = {
                                    "retried": True,
                                    "retry_error":
                                        f"{type(e2).__name__}: {e2}",
                                    "attempts": attempts,
                                }
                                print(f"  [fn-retry] {rec['case_id']} "
                                      f"retry {_attempt} raised ({e2}); "
                                      f"keeping FN", flush=True)
                                break
                            attempts.append({k: rec2.get(k) for k in
                                             ("verdict", "scan_time_s",
                                              "requests", "error")})
                            rec2["fn_retry"] = {
                                "retried": True,
                                "first": attempts[0],
                                "attempts": attempts,
                            }
                            print(f"  [fn-retry] {rec['case_id']} attempt "
                                  f"{_attempt}: FN({attempts[0]['scan_time_s']}s)"
                                  f" -> {rec2['verdict']} "
                                  f"({rec2['scan_time_s']}s)", flush=True)
                            rec = rec2
                            if not _is_degraded_fn(rec2):
                                break      # recovered -- stop spending time
                        else:
                            # Every attempt still looked degraded: the FN is
                            # real as far as this environment can tell.
                            _log_fn_exhausted(rec)
                    done[c["id"]] = rec
                    print(f"  [{len(done)}/{len(cases)}] {rec['case_id']} "
                          f"{rec['verdict']} ({rec['scan_time_s']}s)"
                          f"{' ERR:' + str(rec['error'])[:40] if rec['error'] else ''}",
                          flush=True)
                # retry only cases that errored
                bad = [c for c in chunk if done[c["id"]]["verdict"] == "ERROR"]
                if not bad or attempt == 2:
                    break
                print(f"  [retry {attempt}] {len(bad)} errored cases", flush=True)
                for c in bad:
                    done.pop(c["id"], None)

            # flush partial results after every batch
            rows = list(done.values())
            tp = sum(1 for r in rows if r["verdict"] == "TP")
            fp = sum(1 for r in rows if r["verdict"] == "FP")
            tn = sum(1 for r in rows if r["verdict"] == "TN")
            fn = sum(1 for r in rows if r["verdict"] == "FN")
            err = sum(1 for r in rows if r["verdict"] == "ERROR")
            _atomic_flush(OUT, rows, tp, fp, tn, fn, err, mid)
            print(f"[*] flushed: TP{tp} FP{fp} TN{tn} FN{fn} ERR{err} "
                  f"({time.time() - t0:.0f}s)", flush=True)
    finally:
        srv.shutdown()

    rows = list(done.values())
    tp = sum(1 for r in rows if r["verdict"] == "TP")
    fp = sum(1 for r in rows if r["verdict"] == "FP")
    tn = sum(1 for r in rows if r["verdict"] == "TN")
    fn = sum(1 for r in rows if r["verdict"] == "FN")
    err = sum(1 for r in rows if r["verdict"] == "ERROR")
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    print("\n" + "=" * 46)
    print(f"TOTAL {len(rows)} cases: TP{tp} FP{fp} TN{tn} FN{fn} ERROR{err}")
    print(f"recall={recall:.3f} precision={prec:.3f} fpr={fpr:.3f} f1={f1:.3f}")
    print(f"elapsed {time.time() - t0:.0f}s -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
