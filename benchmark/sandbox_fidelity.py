"""Score the pure-Python HTML sandbox against the Chromium DOM oracle.

This file exists so that `xssentinel/core/sandbox.py` is never trusted more than
it has earned.  Every row of `benchmark/results/browser_dom_oracle.json` is a
(payload x context x sink) case where Chromium said what it does; the sandbox is
re-run over the same bytes here and the two are folded into a confusion matrix.

The two numbers are NOT equally bad:

    MISSED   browser executed, sandbox said inert
             -> a false negative in a scanner: a real XSS goes unreported.
                This is the only class the sandbox must reduce to zero, and
                where it cannot, the case must become UNKNOWN so the caller
                falls back to the browser.

    OVER     sandbox said live-without-activation, browser executed nothing
             -> a false positive, and the kind that costs a pentest credibility
                (Phase 167/168 both spent themselves walking these back).

    UNKNOWN  sandbox declined to answer -> browser probe (~5.6 s) still paid.
             Cheap in correctness terms, expensive in time; the goal is to shrink
             it once MISSED and OVER are at zero.

Usage:  python -m benchmark.sandbox_fidelity [--json out.json]
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

sys.path.insert(0, ".")

# The serialised forms contain U+FFFD and U+00A0, and the default Windows console
# codec is cp936 here -- printing them killed the process mid-report with an
# encode error that looked like "no disagreements found".
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from xssentinel.core import sandbox  # noqa: E402

TOKEN = "__x()"          # the oracle's quote-free sentinel, present in payload
ORACLE = os.path.join("benchmark", "results", "browser_dom_oracle.json")


def _load() -> list[dict]:
    if not os.path.exists(ORACLE):
        raise SystemExit(f"missing oracle: run `python -m "
                         f"benchmark.browser_dom_oracle` first ({ORACLE})")
    return json.load(open(ORACLE, encoding="utf-8"))["rows"]


def score(rows: list[dict]) -> dict:
    per_sink: dict[str, dict] = {}
    for sink, key in (("parser", "exec_parser"), ("innerhtml", "exec_ihn1")):
        buckets: dict[str, Any] = {"MISSED": [], "OVER": [], "UNKNOWN": [],
                                   "ok_live": 0, "ok_inert": 0,
                                   "activation_only": 0}
        for r in rows:
            doc = r["document"]
            browser = r.get(key)
            if browser is None:
                continue                      # inconclusive: not evidence
            v = sandbox.judge(doc, TOKEN, sink=sink)
            claimed = (v.state == "live") and not v.activation
            if v.state == "unknown":
                buckets["UNKNOWN"].append((r["payload"], r["host"], v.reason))
                continue
            if v.state == "live" and v.activation and not claimed:
                # a real XSS behind a gesture: the harness never gestures, so
                # "browser did not execute" is agreement, not an over-claim.
                buckets["activation_only"] += 1
                if browser:
                    buckets["OVER"].append((r["payload"], r["host"],
                                            f"activation-gated but browser ran: "
                                            f"{v.reason}"))
                continue
            if browser and not claimed:
                buckets["MISSED"].append((r["payload"], r["host"], v.reason))
            elif claimed and not browser:
                buckets["OVER"].append((r["payload"], r["host"], v.reason))
            elif claimed:
                buckets["ok_live"] += 1
            else:
                buckets["ok_inert"] += 1
        per_sink[sink] = buckets

    # mXSS: browser says ihn2 without ihn1 -> the sandbox's round-trip must see it
    mx: dict[str, Any] = {"caught": 0, "missed": [], "false_claim": []}
    for r in rows:
        e1, e2 = r.get("exec_ihn1"), r.get("exec_ihn2")
        if e1 is None or e2 is None:
            continue
        v = sandbox.judge_roundtrip(r["document"], TOKEN, sink="innerhtml")
        sandbox_mxss = (v.state == "live" and v.activation is False
                        and "MUTATED" in (v.evidence or ""))
        if e2 and not e1:
            if sandbox_mxss:
                mx["caught"] += 1
            else:
                mx["missed"].append(
                    (r["payload"], r["host"], v.state, v.reason[:70]))
        elif not e2 and sandbox_mxss:
            mx["false_claim"].append((r["payload"], r["host"], v.reason[:70]))

    # serialisation fidelity: can the sandbox reproduce Chromium's innerHTML?
    ser: dict[str, Any] = {"same": 0, "differ": [], "total": 0}
    for r in rows:
        want = r.get("serialized")
        if not want:
            continue
        ser["total"] += 1
        got = sandbox.serialize(sandbox.parse(r["document"]).root)
        if got == want:
            ser["same"] += 1
        else:
            ser["differ"].append((r["payload"], r["host"], got, want))

    return {"per_sink": per_sink, "mxss": mx, "serialize": ser,
            "cases": len(rows)}


def _detail_rows(rows: list[dict], bucket: dict) -> list[dict]:
    """Attach the browser's own view to each disagreement, so the *mechanism* is
    visible.  A (payload, host, reason) triple tells you the sandbox disagreed;
    only the browser's serialisation and live-node list tell you why.
    """
    by_key = {(r["payload"], r["host"]): r for r in rows}
    out = []
    for tag in ("MISSED", "OVER", "UNKNOWN"):
        for p, h, why in bucket[tag]:
            r = by_key.get((p, h), {})
            out.append({"tag": tag, "payload": p, "host": h, "why": why,
                        "document": r.get("document", ""),
                        "browser_serialized": r.get("serialized", ""),
                        "browser_live_nodes": r.get("live_after_parse", []),
                        "sandbox_serialized": sandbox.serialize(
                            sandbox.parse(r.get("document", "")).root)
                        if r.get("document") else ""})
    return out


def report(sc: dict, rows: Optional[list[dict]] = None,
           show: tuple = ()) -> int:
    """`show` selects disagreements to unpack: tag (MISSED/OVER/UNKNOWN),
    payload id, or host id.  Empty prints the summary only."""
    print(f"oracle cases: {sc['cases']}\n")
    bad = 0
    for sink, b in sc["per_sink"].items():
        tot = (b["ok_live"] + b["ok_inert"] + len(b["MISSED"]) + len(b["OVER"])
               + len(b["UNKNOWN"]) + b["activation_only"])
        answered = tot - len(b["UNKNOWN"])
        print(f"--- sink: {sink} ---")
        print(f"  answered {answered}/{tot}   "
              f"ok_live={b['ok_live']}  ok_inert={b['ok_inert']}  "
              f"activation-only={b['activation_only']}")
        print(f"  MISSED (real XSS the sandbox called inert) : {len(b['MISSED'])}")
        print(f"  OVER   (sandbox claimed execution, browser nil): {len(b['OVER'])}")
        print(f"  UNKNOWN(falls back to the browser)          : {len(b['UNKNOWN'])}")
        for tag in ("MISSED", "OVER", "UNKNOWN"):
            for p, h, why in b[tag][:14]:
                print(f"    {tag:8s} {p:24s} {h:12s} {why[:74]}")
            bad += len(b[tag]) if tag in ("MISSED", "OVER") else 0
        if rows and show:
            for d in _detail_rows(rows, b):
                if not any(s in (d["tag"], d["payload"], d["host"])
                           for s in show):
                    continue
                print(f"\n  [{d['tag']}] {d['payload']} x {d['host']}")
                print(f"     sandbox says : {d['why'][:110]}")
                print(f"     browser ser  : {d['browser_serialized'][:120]}")
                print(f"     sandbox ser  : {d['sandbox_serialized'][:120]}")
                print(f"     browser live : {d['browser_live_nodes'][:6]}")
        print()

    mx = sc["mxss"]
    print("--- mutation XSS ---")
    print(f"  browser mXSS caught by sandbox round-trip : {mx['caught']}")
    print(f"  browser mXSS missed                        : {len(mx['missed'])}")
    for p, h, st, why in mx["missed"][:12]:
        print(f"    MISS     {p:24s} {h:12s} {st:8s} {why}")
    print(f"  sandbox claimed mXSS the browser denied     : "
          f"{len(mx['false_claim'])}")
    for p, h, why in mx["false_claim"][:12]:
        print(f"    FALSE    {p:24s} {h:12s} {why}")
    print()
    # A missed mutation vector is a missed XSS. The first revision of this
    # verdict line counted only the first-parse axes and printed "safe to
    # consult" while the block directly above it listed four browser-confirmed
    # mXSS cases the sandbox did not see -- which is exactly the silent-green
    # shape every other part of this Phase has been hunting.
    bad += len(mx["missed"]) + len(mx["false_claim"])

    se = sc["serialize"]
    print("--- serialisation vs Chromium innerHTML ---")
    print(f"  byte-identical: {se['same']}/{se['total']}")
    for p, h, got, want in se["differ"][:8]:
        print(f"    DIFF {p:22s} {h:12s}")
        print(f"         sandbox : {got[:120]}")
        print(f"         chromium: {want[:120]}")
    print()
    print("VERDICT:", "sandbox is safe to consult" if bad == 0 else
          f"{bad} MISSED/OVER disagreements -- do NOT wire into scan decisions")
    return 1 if bad else 0


def main() -> int:
    rows = _load()
    sc = score(rows)
    show: tuple[str, ...] = ()
    if "--show" in sys.argv:
        k = sys.argv.index("--show") + 1
        show = tuple(a for a in sys.argv[k:] if not a.startswith("--"))
    rc = report(sc, rows, show)
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        slim = json.loads(json.dumps(sc, default=str))
        json.dump(slim, open(out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("written:", out)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
