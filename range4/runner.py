# -*- coding: utf-8 -*-
"""Range #4 runner: real-framework SPA cases, scored with the real CLI.

All four cases are client-side DOM sinks, so every case runs --headless
(a real Chromium must execute the framework render for confirmation).
The server runs in THIS process; the scanner runs as a subprocess --
the same topology as an engagement.

Usage:  python range4/runner.py [--engine both] [--timeout 120]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402
from server import run_server  # noqa: E402


def _invoke_scanner(url: str, timeout: int, max_payloads: int,
                    max_transforms: int, engine: str) -> tuple[dict | None, float, str]:
    out_path = os.path.join(tempfile.gettempdir(),
                            f"r4_poc_{os.getpid()}.json")
    cmd = [sys.executable, "-m", "xssentinel",
           "-u", url, "-f", "json", "-o", out_path,
           "--progress", "none", "--log-level", "error",
           "--max-payloads", str(max_payloads),
           "--max-transforms", str(max_transforms),
           "--headless", "--timeout", "10"]
    if engine == "async":
        cmd += ["--async", "--threads", "4"]
    start = time.perf_counter()
    err = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(ROOT))
        if proc.returncode not in (0, 1):
            err = f"exit={proc.returncode}: {proc.stderr[:200]}"
    except subprocess.TimeoutExpired:
        err = f"timeout after {timeout}s"
    elapsed = time.perf_counter() - start
    report = None
    try:
        if os.path.isfile(out_path):
            content = open(out_path, encoding="utf-8").read().strip()
            if content:
                report = json.loads(content)
    except Exception as e:
        if not err:
            err = f"report parse: {e}"
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    return report, elapsed, err


def score(report: dict | None, case: dict) -> str:
    fs = (report or {}).get("findings", [])
    if case["gt"] == "safe":
        bad = [f for f in fs
               if f.get("severity") in ("high", "medium", "critical")
               and not str(f.get("type", "")).startswith("csp_")]
        return "FP" if bad else "TN"
    hits = [f for f in fs
            if f.get("severity") in ("high", "medium", "critical")]
    return "TP" if hits else "FN"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="both", choices=["sync", "async", "both"])
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    started = threading.Event()
    threading.Thread(target=run_server, args=(19704,),
                     kwargs={"ready_callback": lambda s: started.set()},
                     daemon=True).start()
    if not started.wait(10):
        print("[!] range4 server failed to start")
        return 1
    time.sleep(0.3)
    base = "http://127.0.0.1:19704"
    # The runner owns this server: trust it only after a real probe.
    r = requests.get(f"{base}/", timeout=5)
    assert r.status_code == 200 and "Range4" in r.text, "probe failed"
    print(f"[*] Range4 ready on {base}")

    manifest = json.loads((Path(__file__).parent / "manifest.json")
                          .read_text(encoding="utf-8"))
    engines = ["sync", "async"] if args.engine == "both" else [args.engine]
    all_rows = []
    for eng in engines:
        print(f"\n=== engine={eng} ===")
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
        for case in manifest["cases"]:
            url = f"{base}{case['path']}?{case['param']}=xssentinel"
            report, elapsed, err = _invoke_scanner(
                url, timeout=args.timeout, max_payloads=8,
                max_transforms=4, engine=eng)
            verdict = "ERROR" if (err and report is None) else score(report, case)
            counts[verdict] += 1
            n = len((report or {}).get("findings", []))
            mark = "" if verdict in ("TP", "TN") else f"   <-- {verdict} {err[:60]!r}"
            print(f"  [{eng:5}] {case['id']:20} {verdict:5} "
                  f"findings={n:2} {elapsed:5.1f}s{mark}")
            all_rows.append({"engine": eng, "case_id": case["id"],
                             "verdict": verdict, "findings": n})
        print(f"  => TP{counts['TP']} FP{counts['FP']} TN{counts['TN']} "
              f"FN{counts['FN']} ERR{counts['ERROR']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
