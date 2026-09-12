"""Run the whole test suite file-by-file with one automatic retry.

Why this exists: on this host a security product intermittently kills
loopback connections, so a SINGLE-process `pytest tests/` wedges.  Running
file-by-file with a per-file timeout and one retry is the only reliable
full-suite gate here (46 files, ~8 minutes).  Usage:

    python tests/run_all_batched.py            # all files
    python tests/run_all_batched.py --quiet    # only print failures

Exit code: number of files that still fail after the retry (0 = green).
"""
from __future__ import annotations
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PER_FILE_TIMEOUT = 540        # seconds
# Phase 114: per-file overrides.  test_benchmark_fp.py runs one FULL CLI
# scan per safe manifest case (47+ of them since Phases 109-113 added the
# blind-spot families), which on a slow host exceeds the default budget
# even though nothing is wrong.  The file is the FPR regression gate, so
# it gets its own, larger budget instead of being trimmed down.
PER_FILE_TIMEOUT_OVERRIDES = {
    "test_benchmark_fp.py": 1800,
}
RETRIES = 1


LOG_DIR = os.path.join(ROOT, "benchmark", "results", "regression_logs")
RUN_TS = time.strftime("%Y%m%d-%H%M%S")


def _dump_log(path: str, attempts: list) -> None:
    """Persist captured pytest output.

    With --quiet the runner used to throw every file's output away and
    print only "FAIL <file>" -- a red gate with no way to see WHY short of
    re-running the whole file (which, on a degraded-loopback host, can
    take hours).  Evidence must survive the run.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        buf = []
        for attempt, rc, out, err in attempts:
            buf.append(f"===== attempt {attempt} rc={rc} =====")
            for label, blob in (("stdout", out), ("stderr", err)):
                if not blob:
                    continue
                text = blob.decode("utf-8", "replace") \
                    if isinstance(blob, bytes) else str(blob)
                buf.append(f"--- {label} ---")
                buf.append(text[-20000:])
        buf.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(buf))
    except Exception as e:          # logging must never break the gate
        print(f"[!] could not write {path}: {e}", flush=True)


def main() -> int:
    quiet = "--quiet" in sys.argv
    # Any argv item that names a test file limits the run to those files --
    # lets a long degraded run be resumed file by file instead of redone.
    wanted = [a for a in sys.argv[1:] if a.startswith("test_")]
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    if wanted:
        files = [f for f in files if f in wanted]
    failures: list[str] = []
    t0 = time.perf_counter()
    for f in files:
        budget = PER_FILE_TIMEOUT_OVERRIDES.get(f, PER_FILE_TIMEOUT)
        rc = 1
        attempts: list = []
        for attempt in range(RETRIES + 1):
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pytest", os.path.join(HERE, f),
                     "-q"],
                    cwd=ROOT, timeout=budget,
                    capture_output=True)
                rc = r.returncode
                attempts.append((attempt, rc, r.stdout, r.stderr))
            except subprocess.TimeoutExpired as exc:
                rc = 2   # hung file: treat as failure, do not kill the gate
                attempts.append((attempt, "TIMEOUT",
                                 exc.stdout or b"", exc.stderr or b""))
            if rc == 0:
                break
        log_path = os.path.join(LOG_DIR, RUN_TS, f + ".log")
        if attempts and (rc != 0 or len(attempts) > 1):
            _dump_log(log_path, attempts)
        if rc != 0:
            failures.append(f)
            if os.path.exists(log_path):
                print(f"FAIL {f}  log: {log_path}", flush=True)
            else:
                print(f"FAIL {f}", flush=True)
            if not quiet:
                tail = (r.stdout or b"")[-2000:].decode("utf-8", "replace")
                print(tail, flush=True)
        else:
            if not quiet:
                print(f"ok   {f}", flush=True)
    dt = time.perf_counter() - t0
    print(f"\n{len(files) - len(failures)}/{len(files)} files green "
          f"in {dt:.0f}s; failures: {failures or 'none'}")
    if failures:
        print(f"logs: {os.path.join(LOG_DIR, RUN_TS)}")
    return len(failures)


if __name__ == "__main__":
    sys.exit(main())
