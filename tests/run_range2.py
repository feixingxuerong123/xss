"""Run the full pipeline over Attack Range #2 and report TP/TN/FP/FN.

Usage:  python tests/run_range2.py [--quick]

Ground truth lives in range2_server.py (VULN_CASES / SAFE_CASES).
Headless (Playwright) confirmation is ON — this is a full-pipeline drill.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "tests"))

from range2_server import SAFE_CASES, VULN_CASES, start_range2  # noqa: E402

from xssentinel.core.requester import Requester  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402


def _scan_case(base: str, path: str, param: str, kind: str,
               scanner: Scanner) -> None:
    """Drive the scanner exactly like a real operator would."""
    if kind == "stored":
        # Two-step flow: operator names the inject endpoint and its view.
        scanner.scan_stored(
            f"{base}{path}", view_url=f"{base}/r2/stored/view",
            method="POST", param=param)
        # Also probe the view endpoint directly (it reflects stored entries).
        scanner.scan_target(f"{base}/r2/stored/view", method="GET")
        return
    if kind == "second_order":
        # core/second_order path: inject at A, verify at an EXPLICIT view B
        # (no crawl) -- exercises so_mod.inject_payload/check_viewers.
        scanner.scan_second_order(
            f"{base}{path}", param=param, method="POST",
            viewer_urls=[f"{base}/r2/stored/view"])
        return
    if kind == "json_post":
        # Operator sends a JSON document (--json -d '{"q": ...}').
        scanner.json_body = {"q": "probe"}
        scanner.scan_target(f"{base}{path}", method="POST")
        scanner.json_body = None
        return
    if kind == "put_upload":
        # RESTful upload: operator names the file field, method PUT.
        scanner.upload_fields = ["file"]
        scanner.scan_target(f"{base}{path}", method="PUT")
        scanner.upload_fields = []
        return
    if kind in ("cors", "xsleak", "xsleak_isolated"):
        # No parameters -- the audits ride on the baseline response.
        scanner.scan_target(f"{base}{path}", method="GET")
        return
    scanner.scan_target(f"{base}{path}", method="GET", params={param: "probe"})


def _make_scanner(kind: str) -> Scanner:
    return Scanner(requester=Requester(timeout=8), use_headless=True,
                   verbose=False, max_payloads=12, max_transforms=8,
                   xsleak_audit=(kind in ("xsleak", "xsleak_isolated")))


def main() -> int:
    quick = "--quick" in sys.argv

    server = start_range2(8896, ready_callback=lambda srv: print(
        f"[+] range2 on http://127.0.0.1:{srv.server_port}"))
    base = f"http://127.0.0.1:{server.server_port}"
    time.sleep(0.2)

    vuln = VULN_CASES[:6] if quick else VULN_CASES
    safe = SAFE_CASES[:2] if quick else SAFE_CASES

    results: list[dict] = []
    for path, param, kind in vuln:
        t0 = time.perf_counter()
        sc = _make_scanner(kind)
        _scan_case(base, path, param, kind, sc)
        dt = time.perf_counter() - t0
        types = sorted({f.data.get("type", "?") for f in sc.findings})
        results.append({"path": path, "truth": "vuln",
                        "hit": bool(sc.findings), "types": types, "s": dt})
        print(f"  [{'TP' if sc.findings else 'FN'}] {path} "
              f"({dt:.1f}s) {types}")

    for case in safe:
        path, param = case[0], case[1]
        kind = case[2] if len(case) > 2 else "query"
        t0 = time.perf_counter()
        sc = _make_scanner(kind)
        _scan_case(base, path, param, kind, sc)
        dt = time.perf_counter() - t0
        types = sorted({f.data.get("type", "?") for f in sc.findings})
        results.append({"path": path, "truth": "safe",
                        "hit": bool(sc.findings), "types": types, "s": dt})
        print(f"  [{'FP' if sc.findings else 'TN'}] {path} "
              f"({dt:.1f}s) {types}")

    tp = sum(1 for r in results if r["truth"] == "vuln" and r["hit"])
    fn = sum(1 for r in results if r["truth"] == "vuln" and not r["hit"])
    tn = sum(1 for r in results if r["truth"] == "safe" and not r["hit"])
    fp = sum(1 for r in results if r["truth"] == "safe" and r["hit"])
    total = len(results)
    recall = tp / (tp + fn) if tp + fn else 1.0
    precision = tp / (tp + fp) if tp + fp else 1.0

    print("=" * 64)
    print(f"  Range2 result: TP={tp} FN={fn} TN={tn} FP={FPStr(fp)} "
          f"(n={total})")
    print(f"  recall={recall:.2%}  precision={precision:.2%}")
    if fn:
        print("  Missed (FN):")
        for r in results:
            if r["truth"] == "vuln" and not r["hit"]:
                print(f"    - {r['path']}")
    if fp:
        print("  False positives (FP):")
        for r in results:
            if r["truth"] == "safe" and r["hit"]:
                print(f"    - {r['path']} -> {r['types']}")
    print("=" * 64)
    server.shutdown()
    return 0 if (fn == 0 and fp == 0) else 1


def FPStr(n: int) -> str:
    return str(n)


if __name__ == "__main__":
    sys.exit(main())
