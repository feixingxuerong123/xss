"""Does the sandbox gate cost a CASE-level detection?

`benchmark/sandbox_fidelity.py` judges the sandbox per payload.  The benchmark
scores per case: a case is a true positive if ANY payload confirms it.  So
"86 per-payload vetoes over 33 vulnerable cases" answers nothing on its own --
the only question is whether any case lost its LAST confirming payload.

`run_benchmark.py` is the end-to-end answer and also the flakiest thing in the
repo (it hung at 40/185 with its loopback server thread already dead), so this
script answers the same question in minutes instead:

  1. find, offline, exactly which cases the gate changed any verdict on;
  2. evaluate those cases plus every defended case, once with the gate on and
     once with `XSS_SANDBOX_GATE=0`;
  3. diff the CASE-level verdicts.

Step 2's gate-off arm is not a second opinion, it is the pre-sandbox scanner
reproduced exactly, so any difference is attributable to this Phase and nothing
else.  The gate is read from the environment inside the scanner CLI, and
`_invoke_scanner` runs it with `subprocess.run` without `env=`, so the parent's
environment really does reach the child -- worth stating because if it did not,
both arms would measure the same thing and the check would pass vacuously.

Port is not 8877 on purpose: a killed benchmark run leaves its lab server
LISTENING there and the next client then hangs in SYN_SENT (see the delivery
report, Phase 169c).

Usage: python -m benchmark.gate_case_check
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, ".")

from benchmark import runner, server                    # noqa: E402
from xssentinel.core import verifier as vf             # noqa: E402

PORT = 8901
MARK = "xssv_g2delta"
# The shapes a reflected scan actually sends, so step 1 exercises the same
# contexts the payload corpus does.
FORMS = [
    f"<script>alert('{MARK}')</script>",
    f"<img src=x onerror=alert('{MARK}')>",
    f'<svg><style><img src=x onerror="alert(\'{MARK}\')"></style></svg>',
    f'"><img src=x onerror=alert(\'{MARK}\')>',
    f"</title><img src=x onerror=alert('{MARK}')>",
    f"]]></script><script>alert('{MARK}')</script><![CDATA[",
]


def _cases():
    m = json.load(open(os.path.join("benchmark", "manifest.json"),
                       encoding="utf-8"))
    return m["cases"] if isinstance(m, dict) else m


def _render(mode: str, payload: str):
    fn = getattr(server, "MODES", {}).get(mode) \
        or getattr(server, "MODES_CTX", {}).get(mode) \
        or getattr(server, "PAGE_MODES", {}).get(mode)
    if fn is None:
        return None, None
    try:
        try:
            res = fn(payload, {})
        except TypeError:
            res = fn(payload)
    except Exception:
        return None, None
    headers = res[1] if isinstance(res, tuple) and len(res) > 1 else {}
    body = res[-1] if isinstance(res, tuple) else res
    return body, headers


def step_one_touched(cases) -> tuple[set, set, int]:
    """Cases whose per-payload verdict the gate changes, and the FP-risk set."""
    touched_vuln, fp_risk, judged = set(), set(), 0
    for c in cases:
        for form in FORMS:
            body, headers = _render(c.get("mode", ""), form)
            if not body or MARK not in body:
                continue
            judged += 1
            os.environ.pop("XSS_SANDBOX_GATE", None)
            gated = vf.verify_semantic(body, MARK, headers)
            os.environ["XSS_SANDBOX_GATE"] = "0"
            plain = vf.verify_semantic(body, MARK, headers)
            os.environ.pop("XSS_SANDBOX_GATE", None)
            if gated["confirmed"] == plain["confirmed"]:
                continue
            if c["ground_truth"] == "vulnerable" and not gated["confirmed"]:
                touched_vuln.add(c["id"])
            if c["ground_truth"] != "vulnerable" and gated["confirmed"]:
                fp_risk.add(c["id"])
    return touched_vuln, fp_risk, judged


def arm(base_url: str, cases_by_id: dict, ids: list, gate: str) -> dict:
    os.environ["XSS_SANDBOX_GATE"] = gate
    out = {}
    for cid in ids:
        try:
            r = runner.evaluate_case(base_url, cases_by_id[cid], 90, 14, 12)
            out[cid] = bool(getattr(r, "detected", False))
            err = getattr(r, "error", "") or ""
            if err:
                out[cid] = None          # errored: not evidence of a miss
        except Exception as exc:
            out[cid] = None
            print(f"    ! {cid}: {type(exc).__name__} {exc}", flush=True)
        mark = {True: "detected", False: "MISSED", None: "error"}[out[cid]]
        print(f"  [{gate}] {cid:16s} {mark}", flush=True)
    os.environ.pop("XSS_SANDBOX_GATE", None)
    return out


def main() -> int:
    cases = _cases()
    by_id = {c["id"]: c for c in cases}
    print("=== step 1: which cases does the gate touch, per payload ===")
    touched, fp_risk, judged = step_one_touched(cases)
    print(f"  payload/context pairs judged : {judged}")
    print(f"  vulnerable cases touched     : {len(touched)}")
    print(f"  defended cases the gate would newly confirm: {len(fp_risk)} "
          f"{sorted(fp_risk)}")

    defended = [c["id"] for c in cases
                if c["ground_truth"] != "vulnerable"]
    ids = list(dict.fromkeys(sorted(touched) + sorted(fp_risk) + defended))
    print(f"\n=== step 2: case-level, gate ON then OFF, {len(ids)} cases ===")

    started = threading.Event()
    t = threading.Thread(target=server.run_server, args=(PORT,),
                         kwargs={"ready_callback": lambda s: started.set()},
                         daemon=True)
    t.start()
    if not started.wait(timeout=15):
        print("[!] lab server did not come up", file=sys.stderr)
        return 2
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{PORT}"

    on = arm(base_url, by_id, ids, "1")
    off = arm(base_url, by_id, ids, "0")

    lost = [c for c in ids if off.get(c) and on.get(c) is False]
    gained_fp = [c for c in ids if on.get(c) and not off.get(c)
                 and by_id[c]["ground_truth"] != "vulnerable"]
    gained_tp = [c for c in ids if on.get(c) and not off.get(c)
                 and by_id[c]["ground_truth"] == "vulnerable"]
    errored = [c for c in ids if on.get(c) is None or off.get(c) is None]

    print("\n=== case-level effect of the sandbox gate ===")
    print(f"  detected with gate OFF : {sum(1 for v in off.values() if v)}")
    print(f"  detected with gate ON  : {sum(1 for v in on.values() if v)}")
    print(f"  LOST  (case-level FN)  : {len(lost)} {lost}")
    print(f"  GAINED FP (over-claim) : {len(gained_fp)} {gained_fp}")
    print(f"  GAINED TP (fixed miss) : {len(gained_tp)} {gained_tp}")
    print(f"  errored (not evidence) : {len(errored)} {errored[:6]}")
    bad = bool(lost or gained_fp)
    print("\nVERDICT:", "gate costs a case-level detection -- do not ship"
          if bad else "no case-level regression")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
