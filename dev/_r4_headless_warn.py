# -*- coding: utf-8 -*-
"""Does `--async --headless` now say out loud that it is not confirmed?

Phase 180: AsyncScanner has no verify_headless wiring, so async findings
carry no browser confirmation.  Silence is what let that pass as a
result.  This checks the warning actually reaches stderr.

Usage:  python dev/_r4_headless_warn.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "range4"))

from server import run_server  # noqa: E402

PORT = 19708


def main() -> int:
    started = threading.Event()
    threading.Thread(target=run_server, args=(PORT,),
                     kwargs={"ready_callback": lambda s: started.set()},
                     daemon=True).start()
    if not started.wait(10):
        print("[!] server failed to start")
        return 1
    time.sleep(0.3)

    cmd = [sys.executable, "-m", "xssentinel",
           "-u", f"http://127.0.0.1:{PORT}/react?search=xssentinel",
           "-f", "json", "-o", str(ROOT / "dev" / "_r4_hl.json"),
           "--async", "--headless", "--progress", "none",
           "--log-level", "error", "--max-payloads", "4",
           "--max-transforms", "2", "--timeout", "8"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=180, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        print("[!] scanner subprocess hung (known local loopback issue)")
        return 1
    err = (proc.stderr or "") + (proc.stdout or "")
    warned = "--headless is sync-only" in err
    print(f"exit={proc.returncode}  warned={warned}")
    for ln in err.splitlines():
        if "sync-only" in ln:
            print("  stderr:", ln.strip())
    print("VERDICT:", "PASS (operator is told)" if warned
          else "FAIL (still silent)")
    return 0 if warned else 1


if __name__ == "__main__":
    sys.exit(main())
