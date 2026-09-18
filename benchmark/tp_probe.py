"""TP probe: what does each positive case actually prove?

Phase 160 fixed the scorer's blind spot on SAFE cases (a finding of another
layer was invisible).  The same branch has a second, opposite risk on
POSITIVE cases, and this probe measures it instead of assuming:

  * ``case["param"]`` empty  -> ANY finding whose url contains the case path
    credits the case, whatever its type.  A DOM case can therefore be scored
    TP by a page-level Trusted-Types note while the DOM engine is broken.
  * ``case["finding_types"]`` declared -> the type is checked, the PARAMETER
    never is.  A case about ``q`` can be credited by a finding the scanner
    produced on a different parameter of the same page.

For every positive case this probe re-runs the scan and reports:

  credited      -- what the scorer counts today (must be > 0)
  vector_bound  -- the subset that is bound to the case's own input: the
                   finding's param equals the case param, or (param empty)
                   the finding comes from DOM work
  collateral    -- credited but NOT vector_bound: the case would be TP even
                   if its own vector never fired
  dom_dependent -- removing DOM-family findings from the report un-credits
                   the case, i.e. this case is evidence the browser engine
                   works.  The complement is evidence it does not.

Flags are advisory output for a human; nothing is asserted here.

Usage: python -m benchmark.tp_probe [port] [max_payloads] [max_transforms] [timeout]
Writes benchmark/results/tp_probe.json.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, ".")

from benchmark.runner import _build_target_url, _case_extra_args  # noqa: E402
from benchmark.runner import _invoke_scanner, _is_detected  # noqa: E402
from benchmark.server import BenchmarkHandler, load_routes  # noqa: E402

# Finding types produced by DOM work (the real-browser engine, the static DOM
# analysis and the DOM prototype/clobber layers).  If a case is credited by
# one of these, the DOM side of the scanner earned it.
DOM_TYPES = {"dom_dynamic", "dom", "dom_prototype", "dom_prototype_pollution"}


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


def _credited_without(report: dict, case: dict, drop: set) -> bool:
    """Re-score the same report with ``drop`` finding types removed."""
    if not report:
        return False
    trimmed = {"findings": [f for f in report.get("findings", [])
                            if f.get("type", "") not in drop]}
    detected, _, _ = _is_detected(trimmed, case)
    return detected


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18899
    max_p = int(sys.argv[2]) if len(sys.argv) > 2 else 14
    max_t = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 90
    # "static" runs the whole pass with --dom-engine static: the real-browser
    # layer is removed (scanner._resolve_dom_engine returns None for it) while
    # the static L3 DOM analysis keeps running.  Comparing the two runs answers
    # the question this phase exists for: how many positive cases would the
    # benchmark lose if the browser engine were dead?
    # NOTE the CLI choice is auto|playwright|static -- "off" is not a value and
    # argparse exits 2, which the runner reports as "exit=2" with 0 findings.
    dom_mode = sys.argv[5] if len(sys.argv) > 5 else "on"
    dom_extra = ["--dom-engine", "static"] if dom_mode == "static" else []

    srv = start_server(port)
    base = f"http://127.0.0.1:{port}"
    manifest = json.load(open("benchmark/manifest.json", encoding="utf-8"))
    cases = manifest["cases"] if isinstance(manifest, dict) else manifest
    pos = [c for c in cases if c.get("ground_truth") == "vulnerable"]

    rows = []
    for i, case in enumerate(pos, 1):
        url = _build_target_url(base, case)
        report, elapsed, err = _invoke_scanner(
            url, timeout=timeout, max_payloads=max_p, max_transforms=max_t,
            engine="sync",
            extra_args=(_case_extra_args(base, case) or []) + dom_extra)
        detected, count, credited = _is_detected(report, case)
        case_param = case.get("param") or ""

        declared = set(case.get("finding_types") or [])
        bound, collateral = [], []
        for f in credited:
            f_param = f.get("param") or ""
            f_type = f.get("type", "")
            if case_param and f_param == case_param:
                bound.append(f)
            elif not case_param and f_type in DOM_TYPES:
                bound.append(f)
            elif f_type in declared:
                # Phase 109 carrier-labelled vectors (cookie/path/upload/...)
                # are bound by DECLARED TYPE, not by param name -- judged
                # against ``declared``, not against the case param.  Note this
                # branch is what the scorer uses for declared cases, so the
                # residual risk there is PARAM-MISMATCH, not COLLATERAL-ONLY.
                bound.append(f)
            else:
                collateral.append(f)

        dom_dep = detected and not _credited_without(report, case, DOM_TYPES)

        # A finding on a concrete parameter that is not this case's parameter:
        # careless credit for the finding_types branch (which ignores param).
        param_mismatch = bool(case_param) and any(
            (f.get("param") or "") not in ("", case_param)
            and not str(f.get("param", "")).startswith("(")
            for f in credited)

        flags = []
        if not detected:
            flags.append("NO-CREDIT")
        if detected and not bound:
            flags.append("COLLATERAL-ONLY")
        if param_mismatch:
            flags.append("PARAM-MISMATCH")
        if detected and len(collateral) > len(bound):
            flags.append("MOSTLY-COLLATERAL")

        rows.append({
            "case_id": case["id"],
            "mode": case.get("mode"),
            "context": case.get("context"),
            "case_param": case_param,
            "declared_types": case.get("finding_types") or [],
            "detected": detected,
            "credited": len(credited),
            "credited_types": sorted({f.get("type", "") for f in credited}),
            "bound_types": sorted({f.get("type", "") for f in bound}),
            "collateral_types": sorted({f.get("type", "") for f in collateral}),
            "dom_dependent": dom_dep,
            "flags": flags,
            "elapsed": round(elapsed, 1),
            "error": err[:80],
        })
        mark = ",".join(flags) if flags else ("DOM" if dom_dep else "ok")
        print(f"[{i}/{len(pos)}] {case['id']:<18} {mark:<18} "
              f"credited={len(credited)} bound={len(bound)} "
              f"collateral={sorted({f.get('type','') for f in collateral})}",
              flush=True)

    wrote = [r for r in rows if not r["detected"]]
    coll = [r for r in rows if "COLLATERAL-ONLY" in r["flags"]]
    mism = [r for r in rows if "PARAM-MISMATCH" in r["flags"]]
    dom = [r for r in rows if r["dom_dependent"]]
    print("\n=== summary ===")
    print(f"positive cases: {len(rows)}")
    print(f"scored TP: {len(rows) - len(wrote)}   not credited: {len(wrote)}")
    print(f"credited ONLY by collateral findings: {len(coll)} "
          f"{[r['case_id'] for r in coll]}")
    print(f"credited by a finding on another param: {len(mism)} "
          f"{[r['case_id'] for r in mism]}")
    print(f"DOM-dependent (evidence the browser engine works): {len(dom)} "
          f"{[r['case_id'] for r in dom]}")
    print(f"NOT DOM-dependent positive cases: {len(rows) - len(dom)}")
    out = os.path.join("benchmark", "results",
                       "tp_probe.json" if dom_mode != "static"
                       else "tp_probe_nodom.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
