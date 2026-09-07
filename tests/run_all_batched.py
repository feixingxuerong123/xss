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
RETRIES = 1


def main() -> int:
    quiet = "--quiet" in sys.argv
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    failures: list[str] = []
    t0 = time.perf_counter()
    for f in files:
        rc = 1
        for attempt in range(RETRIES + 1):
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pytest", os.path.join(HERE, f),
                     "-q"],
                    cwd=ROOT, timeout=PER_FILE_TIMEOUT,
                    capture_output=True)
                rc = r.returncode
            except subprocess.TimeoutExpired:
                rc = 2   # hung file: treat as failure, do not kill the gate
            if rc == 0:
                break
        if rc != 0:
            failures.append(f)
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
    return len(failures)


if __name__ == "__main__":
    sys.exit(main())
