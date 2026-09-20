"""Phase 170: what SEVERITY are the findings the benchmark hides?

`fp_probe` reports the type of every finding a safe case carries that the
benchmark's `finding_types` filter hides -- but not its severity, and the rule
settled in Phase 160 is that only high / medium / critical (non-`csp_`) count as
a false positive; `low` is hygiene information a scanner is allowed to emit.
Same scan, same helpers, but print the severity so the four flagged cases can be
told apart.

Usage: python -m benchmark.probe_fp_severity [port]
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.fp_probe import (  # noqa: E402
    _build_target_url,
    _case_extra_args,
    _invoke_scanner,
    start_server,
)

CASES = ["neg-redirect-01", "neg-tt-01", "neg-clobber-01", "neg-clobber-02"]


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18897
    srv = start_server(port)
    base = f"http://127.0.0.1:{port}"
    manifest = json.load(open("benchmark/manifest.json", encoding="utf-8"))
    cases = manifest["cases"] if isinstance(manifest, dict) else manifest

    rows = []
    for cid in CASES:
        case = next(c for c in cases if c["id"] == cid)
        url = _build_target_url(base, case)
        report, elapsed, err = _invoke_scanner(
            url, timeout=90, max_payloads=14, max_transforms=12,
            engine="sync", extra_args=_case_extra_args(base, case))
        declared = set(case.get("finding_types") or [])
        if err:
            print(f"  {cid}: err={err[:60]}", flush=True)
        for f in (report or {}).get("findings", []):
            if f.get("severity", "") == "info":
                continue
            if f.get("type", "") == "fuzzer_triage":
                continue
            ftype = f.get("type", "")
            rows.append({
                "case": cid, "type": ftype, "severity": f.get("severity"),
                "declared": ftype in declared, "param": f.get("param"),
                "detail": str(f.get("detail", ""))[:90],
            })
            print(f"  {cid:16s} sev={str(f.get('severity')):8s} "
                  f"type={ftype:30s} declared={ftype in declared} "
                  f"param={f.get('param')}", flush=True)

    srv.shutdown()
    fp = [r for r in rows
          if r["severity"] in ("high", "medium", "critical")
          and not r["type"].startswith("csp_")]
    print(f"\n=== {len(rows)} non-info findings; "
          f"{len(fp)} count as a real false positive (Phase 160 rule) ===")
    for r in fp:
        print("   -", r["case"], r["severity"], r["type"])

    out = "benchmark/results/probe_fp_severity.json"
    json.dump(rows, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
