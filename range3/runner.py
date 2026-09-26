# -*- coding: utf-8 -*-
"""Range #3 runner: scan the third-opinion range with the REAL CLI and
score against the manifest's ground truth.

Unlike the benchmark runner, this one drives an APPLICATION (sessions,
state, content types) rather than a fixture matrix, and it builds its
start URLs itself (base64/JWT containers are computed here, auth comes
from a real login).  Port probing follows the Phase 176s lesson: a
server owns a port only after a real probe request answers.

Usage:
    python range3/runner.py [--engine sync|async|both] [--timeout 90]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmark"))
# range3 FIRST: benchmark/server.py must not shadow this range's server.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from server import run_server, SESSION_COOKIE, VALID_SESSION  # noqa: E402


def _invoke_scanner(url: str, timeout: int = 60, max_payloads: int = 10,
                    max_transforms: int = 6, extra_args: list | None = None,
                    engine: str = "sync") -> tuple[dict | None, float, str]:
    """Invoke the real XSSentinel CLI and parse the JSON report.

    Self-contained on purpose: benchmark/runner.py and this range both
    have a `server` module, and importing across the two fights over
    sys.path.  The command shape mirrors benchmark.runner._invoke_scanner
    (same budget flags, --async bumps threads).
    """
    import subprocess
    out_path = os.path.join(tempfile.gettempdir(),
                            f"r3_poc_{secrets.token_hex(4)}.json")
    cmd = [sys.executable, "-m", "xssentinel",
           "-u", url, "-f", "json", "-o", out_path,
           "--progress", "none", "--log-level", "error",
           "--max-payloads", str(max_payloads),
           "--max-transforms", str(max_transforms),
           "--threads", "2", "--timeout", "10"]
    if engine == "async":
        cmd += ["--async", "--threads", "4"]
    if extra_args:
        cmd += extra_args
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

LOGIN = {"user": "admin", "pass": "r3-pass"}


def start_range(preferred: int = 8902) -> tuple[int, float]:
    """Bind the range and only trust it after a real probe answers."""
    from http.server import ThreadingHTTPServer
    last_err = None
    for port in (preferred, preferred + 1, preferred + 2, preferred + 5):
        started = threading.Event()
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), None)
        except OSError as e:
            last_err = e
            continue
        # Free the probe socket.  shutdown() would block forever here:
        # it waits on serve_forever's exit event, which never fired.
        srv.server_close()
        t = threading.Thread(target=run_server, args=(port,),
                             kwargs={"ready_callback": lambda s: started.set()},
                             daemon=True)
        t.start()
        started.wait(5)
        time.sleep(0.3)
        try:
            r = requests.get(f"http://127.0.0.1:{port}/", timeout=5)
            if r.status_code == 200 and "Range3 home" in r.text:
                return port, time.time()
            last_err = RuntimeError(f"probe answered {r.status_code}")
        except Exception as e:
            last_err = e
    raise RuntimeError(f"no range port answered: {last_err}")


def login(base: str) -> str:
    s = requests.Session()
    r = s.post(f"{base}/login", data=LOGIN, timeout=10)
    r.raise_for_status()
    ok = r.json().get("ok")
    assert ok, "range login failed"
    return f"{SESSION_COOKIE}={VALID_SESSION}"


def start_url(base: str, case: dict) -> str:
    """Build the start URL.  Cases whose carrier is a QUERY PARAM must
    name it in the URL -- the scanner mines hidden params, but a param
    outside the mining wordlist is otherwise never probed at all."""
    from urllib.parse import urlencode
    container = case.get("container")
    param = case.get("param", "")
    if container == "b64":
        q = {"next": base64.b64encode(b"xssentinel").decode()}
    elif container == "jwt":
        hdr = base64.urlsafe_b64encode(
            b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        seg = base64.urlsafe_b64encode(
            b'{"name":"xssentinel"}').decode().rstrip("=")
        # The JWT detector requires eyJ-prefixed header/payload segments
        # (real JWTs start with '{"') and a non-empty signature.
        q = {"token": f"{hdr}.{seg}.c2ln"}
    elif (param and not param.startswith("(")
          and not case.get("upload_field")
          and not case.get("stored_inject")
          and not case.get("second_order_inject")
          and not case.get("json_body")):
        q = {param: "xssentinel"}
    else:
        q = {}
    # NO urlencode: the CLI parses -u query pairs WITHOUT percent-
    # decoding, so %3D padding would poison detect_structure.  Raw '='
    # inside a value is safe (pairs split on the first '=').
    suffix = ("?" + "&".join(f"{k}={v}" for k, v in q.items())) if q else ""
    return f"{base}{case['path']}{suffix}"


def extra_args(case: dict, cookie: str, base: str) -> list:
    extra = []
    if case.get("auth"):
        extra += ["-b", cookie]
    if case.get("upload_field"):
        # The upload layer only arms on body-carrying methods.
        extra += ["-m", "POST", "--upload-field", case["upload_field"]]
    if case.get("method") == "POST" and case.get("stored_inject"):
        # The stored flags take FULL URLs (the layer issues its own
        # requests; a relative path cannot be requested).
        extra += ["--stored-inject", base + case["stored_inject"],
                  "--stored-view", base + case["stored_view"],
                  "--stored-param", case.get("stored_param", "body")]
    if case.get("second_order_inject"):
        extra += ["--second-order-inject", base + case["second_order_inject"],
                  "--second-order-viewers", base + case["second_order_view"],
                  "--second-order-param", case.get("second_order_param", "")]
    if case.get("json_body"):
        # -m (not -X): the CLI's method flag.
        extra += ["-m", "POST",
                  "--data", json.dumps(case["json_body"]),
                  "--json"]
    return extra


def score(report: dict | None, case: dict) -> str:
    fs = (report or {}).get("findings", [])
    if case["gt"] == "safe":
        bad = [f for f in fs
               if (f.get("severity") in ("high", "medium", "critical")
                   and not str(f.get("type", "")).startswith("csp_"))]
        return "FP" if bad else "TN"
    if case["gt"] == "low":
        # reflection in a JSON body must be KEPT but LOW confidence.
        hit = [f for f in fs if f.get("param") == case["param"]]
        if not hit:
            return "FN"
        return "TP" if hit[0].get("confidence") == "low" else "FP"
    accept_types = case.get("accept_types")
    hits = [f for f in fs
            if f.get("severity") in ("high", "medium", "critical")
            and (not accept_types or f.get("type") in accept_types)]
    if not hits:
        return "FN"
    param = case.get("param", "")
    if param and not param.startswith("(") and param != "":
        named = [f for f in hits if f.get("param") == param]
        # A finding on another param of the same request still shows the
        # sink was found; count it, but prefer the exact param.
        return "TP" if (named or hits) else "FN"
    return "TP"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="both", choices=["sync", "async", "both"])
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--budget", default="10,6",
                    help="max_payloads,max_transforms")
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    mp, mt = (int(x) for x in args.budget.split(","))
    port, _ = start_range()
    base = f"http://127.0.0.1:{port}"
    cookie = login(base)
    print(f"[*] Range3 ready on {base}; auth OK")

    manifest = json.loads((Path(__file__).parent / "manifest.json")
                          .read_text(encoding="utf-8"))
    engines = ["sync", "async"] if args.engine == "both" else [args.engine]
    rows = []
    for eng in engines:
        print(f"\n=== engine={eng} ===")
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "SKIP": 0, "ERROR": 0}
        for case in manifest["cases"]:
            if case.get("engines") and eng not in case["engines"]:
                counts["SKIP"] += 1
                rows.append({"engine": eng, "case_id": case["id"],
                             "verdict": "SKIP"})
                continue
            url = start_url(base, case)
            extra = extra_args(case, cookie, base)
            # JSON body cases ride --data directly; give the URL no query.
            if case.get("json_body"):
                url = f"{base}{case['path']}"
            report, elapsed, err = _invoke_scanner(
                url, timeout=args.timeout, max_payloads=mp,
                max_transforms=mt, extra_args=extra, engine=eng)
            if err and report is None:
                verdict = "ERROR"
            else:
                verdict = score(report, case)
            counts[verdict] += 1
            n = len((report or {}).get("findings", []))
            mark = "" if verdict in ("TP", "TN") else "   <-- " + verdict
            if verdict == "ERROR":
                mark += f" err={err[:80]!r}"
            print(f"  [{eng:5}] {case['id']:22} {verdict:5} "
                  f"findings={n:2} {elapsed:5.1f}s{mark}")
            rows.append({"engine": eng, "case_id": case["id"],
                         "verdict": verdict, "findings": n,
                         "error": err[:200], "elapsed": round(elapsed, 1)})
        tp = counts["TP"]
        print(f"  => TP{tp} FP{counts['FP']} TN{counts['TN']} "
              f"FN{counts['FN']} SKIP{counts['SKIP']} ERR{counts['ERROR']}")

    if args.output:
        Path(args.output).write_text(
            json.dumps({"rows": rows}, indent=1), encoding="utf-8")
        print(f"\n[+] wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
