# -*- coding: utf-8 -*-
"""Per-case diff of two benchmark runs.

The benchmark stores aggregate scores (recall/precision/FPR) but those
hide *which* cases moved.  A regression that swaps one vulnerable case for
another still scores identically, so audits need the case-level delta.

Usage::

    python benchmark/compare_runs.py BASELINE.json CANDIDATE.json [--strict]

Understands both on-disk shapes:

* ``benchmark/runner.py`` output -- flat dict with ``cases`` + ``recall`` etc.
* ``benchmark/run_benchmark_batched.py`` output -- ``{"meta": ..., "cases": ...}``

Exit code is 1 when ``--strict`` is given and any regression exists.
"""
from __future__ import annotations

import json
import sys
from collections import Counter


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    cases = doc.get("cases") or []
    by_id: dict[str, dict] = {}
    for c in cases:
        cid = c.get("case_id") or c.get("id")
        if cid:
            by_id[cid] = c
    meta = doc.get("meta") or {}
    return {
        "path": path,
        "by_id": by_id,
        "meta": meta,
        "engine": doc.get("engine") or meta.get("engine") or "?",
        "budget": {
            "max_payloads": meta.get("max_payloads"),
            "max_transforms": meta.get("max_transforms"),
            "timeout": meta.get("timeout"),
        },
    }


# Verdict ranking used to classify a move as better / worse / sideways.
# ERROR sorts worst: a case that could not be scored tells us nothing, and
# in the vulnerable half it is treated as a miss by the calibration.
_RANK = {"TP": 0, "TN": 0, "FP": 1, "FN": 1, "ERROR": 2, "?": 3}


def _verdict(c: dict | None) -> str:
    if not c:
        return "?"
    return str(c.get("verdict") or "?").upper()


def _is_vuln(c: dict | None) -> bool | None:
    if not c:
        return None
    gt = str(c.get("ground_truth") or "").lower()
    if gt.startswith("vuln") or gt in ("xss", "true", "yes"):
        return True
    if gt.startswith("safe") or gt in ("false", "no", "benign"):
        return False
    return None


def counts(by_id: dict[str, dict]) -> Counter:
    return Counter(_verdict(c) for c in by_id.values())


def scores(cnt: Counter) -> tuple[float, float, float, float]:
    tp, fp, tn, fn = cnt["TP"], cnt["FP"], cnt["TN"], cnt["FN"]
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    return recall, prec, fpr, f1


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv
    if len(args) != 2:
        sys.exit("usage: compare_runs.py BASELINE.json CANDIDATE.json "
                 "[--strict]")
    base, cand = load(args[0]), load(args[1])

    print("=" * 68)
    print("BENCHMARK RUN DIFF")
    print("=" * 68)
    for name, r in (("BASELINE", base), ("CANDIDATE", cand)):
        cnt = counts(r["by_id"])
        recall, prec, fpr, f1 = scores(cnt)
        b = r["budget"]
        print(f"{name:9s} {r['path']}")
        print(f"          engine={r['engine']} cases={len(r['by_id'])} "
              f"budget={b['max_payloads']}/{b['max_transforms']} "
              f"timeout={b['timeout']}")
        print(f"          TP{cnt['TP']} FP{cnt['FP']} TN{cnt['TN']} "
              f"FN{cnt['FN']} ERROR{cnt['ERROR']} | "
              f"recall={recall:.4f} precision={prec:.4f} "
              f"fpr={fpr:.4f} f1={f1:.4f}")
    if base["budget"] != cand["budget"]:
        print("\n[!] WARNING: budgets differ -- the delta below mixes a "
              "capability change with a budget change.")
    print()

    ids = sorted(set(base["by_id"]) | set(cand["by_id"]))
    regressions: list[tuple[str, str, str, str]] = []
    improvements: list[tuple[str, str, str, str]] = []
    unscored_good: list[tuple[str, str, str, str]] = []
    unscored_bad: list[tuple[str, str, str, str]] = []
    only_base: list[str] = []
    only_cand: list[str] = []

    for cid in ids:
        bc, cc = base["by_id"].get(cid), cand["by_id"].get(cid)
        if bc is None:
            only_cand.append(cid)
            continue
        if cc is None:
            only_base.append(cid)
            continue
        vb, vc = _verdict(bc), _verdict(cc)
        if vb == vc:
            continue
        ctx = str(bc.get("context") or cc.get("context") or "?")
        diff = str(bc.get("difficulty") or cc.get("difficulty") or "?")
        row = (cid, vb, vc, f"{ctx}/{diff}")
        if vb == "ERROR":
            # Baseline never scored this case (usually a killed loopback
            # connection).  Reporting that as a flat "improvement" hides
            # newly-revealed false positives, so it gets its own bucket.
            (unscored_good if vc in ("TP", "TN") else unscored_bad).append(row)
        elif _RANK.get(vc, 3) > _RANK.get(vb, 3):
            regressions.append(row)
        else:
            improvements.append(row)

    def _dump(title: str, rows: list[tuple[str, str, str, str]]) -> None:
        print(f"--- {title} ({len(rows)}) ---")
        if not rows:
            print("    (none)")
        for cid, vb, vc, where in rows:
            print(f"    {cid:28s} {vb:5s} -> {vc:5s}  [{where}]")
        print()

    _dump("IMPROVEMENTS (scored -> scored)", improvements)
    _dump("REGRESSIONS (scored -> worse)", regressions)
    _dump("BASELINE UNSCORED -> now TP/TN (environment recovered)",
          unscored_good)
    _dump("BASELINE UNSCORED -> now FP/FN (newly revealed failures)",
          unscored_bad)

    # The audit-relevant subset: a safe case that started firing.
    new_fp = [r for r in regressions if r[2] == "FP"]
    new_fn = [r for r in regressions if r[2] == "FN"]
    new_err = [r for r in regressions if r[2] == "ERROR"]
    print("--- AUDIT FOCUS ---")
    print(f"    new FALSE POSITIVES (safe case now detected): {len(new_fp)}")
    for r in new_fp:
        print(f"        {r[0]} [{r[3]}]")
    print(f"    new FALSE NEGATIVES (vuln case now missed):   {len(new_fn)}")
    for r in new_fn:
        print(f"        {r[0]} [{r[3]}]")
    print(f"    new ERRORS (case could not be scored):        {len(new_err)}")
    for r in new_err:
        print(f"        {r[0]} [{r[3]}]")

    if only_base or only_cand:
        print()
        print(f"    only in BASELINE ({len(only_base)}): "
              f"{', '.join(sorted(only_base)) or '-'}")
        print(f"    only in CANDIDATE ({len(only_cand)}): "
              f"{', '.join(sorted(only_cand)) or '-'}")

    # Timing: surface only a large shift, since wall time is noisy here.
    times = []
    for cid in ids:
        bc, cc = base["by_id"].get(cid), cand["by_id"].get(cid)
        if bc and cc and bc.get("scan_time_s") and cc.get("scan_time_s"):
            times.append((cc["scan_time_s"], bc["scan_time_s"]))
    if times:
        sb = sum(t[1] for t in times) / len(times)
        sc = sum(t[0] for t in times) / len(times)
        print()
        print(f"    mean scan_time: baseline {sb:.2f}s -> candidate {sc:.2f}s "
              f"({(sc - sb) / sb * 100:+.0f}%)")

    print()
    if strict and regressions:
        print(f"[FAIL] {len(regressions)} regression(s) with --strict")
        return 1
    print(f"[OK] {len(regressions)} regression(s), "
          f"{len(improvements)} improvement(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
