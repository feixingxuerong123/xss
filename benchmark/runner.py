#!/usr/bin/env python
"""XSSentinel Benchmark Runner — evaluates scanner accuracy against the manifest.

Starts the benchmark server, invokes XSSentinel CLI against every manifest case,
parses JSON reports, and computes TP/FP/TN/FN metrics.

Usage:
    python benchmark/runner.py [--port 8877] [--concurrency 1] [--timeout 60]
    python benchmark/runner.py --quick   # subset for fast iteration
"""
from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import quote

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
_MANIFEST_PATH = _HERE / "manifest.json"
_RESULTS_DIR = _HERE / "results"

sys.path.insert(0, str(_HERE))
from server import run_server, load_routes, DEFAULT_PORT


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CaseResult:
    """Result of evaluating one manifest case."""
    case_id: str
    path: str
    param: str
    mode: str
    ground_truth: str       # "vulnerable" | "safe"
    context: str
    difficulty: str
    detected: bool          # scanner reported a finding
    verdict: str            # TP | FP | TN | FN | ERROR
    scan_time_s: float = 0.0
    findings_count: int = 0
    requests: int = 0        # scanner's own request count (stable metric --
                             # scan_time_s is wall time incl. interpreter
                             # startup, noisy on degraded-loopback hosts)
    finding_details: list = field(default_factory=list)
    error: str = ""


@dataclass
class BenchmarkResult:
    """Aggregate benchmark results."""
    tool: str = "XSSentinel"
    engine: str = "sync"     # Phase 43: "sync" | "async" (which scanner ran)
    timestamp: str = ""
    total_cases: int = 0
    total_time_s: float = 0.0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0         # cases the scanner failed to complete
    recall: float = 0.0
    precision: float = 0.0
    fpr: float = 0.0
    f1: float = 0.0
    cases: list = field(default_factory=list)
    by_context: dict = field(default_factory=dict)
    by_difficulty: dict = field(default_factory=dict)
    false_positives: list = field(default_factory=list)
    false_negatives: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scanner invocation
# ---------------------------------------------------------------------------


def _case_extra_args(base_url: str, case: dict) -> list | None:
    """CLI arguments a case needs beyond -u (Phase 110).

    * ``method``: POST/PUT cases carry the parameter in -d.
    * ``upload_field``: enables the multipart filename probe.
    * ``view_path``: the GET endpoint that renders what this case stored
      -- drives the dedicated --stored-inject/--stored-view entry point.

    Returns None when a case needs nothing extra, so 117 existing cases
    build the exact same command line as before.
    """
    extra: list = []
    method = str(case.get("method", "GET")).upper()
    param = case.get("param", "q")
    if method != "GET":
        extra += ["--method", method, "-d", f"{param}=xssentinel_bench_probe"]
    if case.get("upload_field"):
        extra += ["--upload-field", str(case["upload_field"])]
    if case.get("view_path"):
        extra += [
            "--stored-inject", f"{base_url}{case['path']}",
            "--stored-view", f"{base_url}{case['view_path']}",
            "--stored-param", param,
        ]
    if case.get("stored_dom"):
        # Phase 152: verify persistence in the real browser (the view page
        # renders the stored value client-side; HTTP text matching can't).
        extra += ["--stored-dom"]
    if case.get("stored_extra"):
        # Phase 153: companion fields the write API demands (register/
        # profile shape -- POST without them is rejected, so the payload
        # can never be stored).
        for k, v in dict(case["stored_extra"]).items():
            extra += ["--stored-extra", f"{k}={v}"]
    # Phase 126: second-order cases drive the dedicated CLI flow -- inject at
    # A, then verify the EXPLICIT viewer B (no crawling, so the case is
    # deterministic).  The scanner still runs its normal scan of A; the
    # second-order finding is what this case is scored on.
    if case.get("second_order_view_path"):
        extra += [
            "--second-order-inject", f"{base_url}{case['path']}",
            "--second-order-viewers",
            f"{base_url}{case['second_order_view_path']}",
            "--second-order-param", param,
            "--second-order-method", method,
        ]
    # Phase 127: declarative multi-step scenarios (L9_scenario).  The path is
    # resolved against the project root: _invoke_scanner spawns the CLI
    # without cwd=, so a manifest-relative path would depend on wherever the
    # caller happened to be standing.
    if case.get("scenario_file"):
        extra += ["--scenarios",
                  os.path.join(_PROJECT_ROOT, str(case["scenario_file"]))]
    # Phase 120: verbatim CLI flags from the manifest (e.g. --crawl).
    extra += list(case.get("extra_args") or [])
    return extra or None

def _build_target_url(base: str, case: dict) -> str:
    """Construct the target URL for a manifest case."""
    path = case["path"]
    param = case.get("param", "q")
    url = f"{base}{path}"
    # Phase 110: body-carried cases (upload/stored) put the parameter in
    # -d instead, so the URL must stay clean.
    if param and case.get("method", "GET").upper() == "GET":
        # Phase 122: param_value overrides the default probe value -- the
        # pre-encoded family needs the ORIGINAL value to parse as a
        # container (base64-JSON / JWT) or detect_structure never fires.
        value = case.get("param_value") or "xssentinel_bench_probe"
        url += f"?{param}={value}"
    return url


# One reusable report file per worker thread.  Creating + unlinking a temp
# file per case meant ~200 filesystem deletions per run; reusing keeps it to
# one file per worker, removed once in _cleanup_report_tmps().
_TMP_TLS = threading.local()
_ALL_TMP: list[str] = []
_TMP_LOCK = threading.Lock()


def _report_tmp_path() -> str:
    path = getattr(_TMP_TLS, "path", None)
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".json", dir=str(_RESULTS_DIR))
        os.close(fd)
        _TMP_TLS.path = path
        with _TMP_LOCK:
            _ALL_TMP.append(path)
    return path


def _cleanup_report_tmps() -> None:
    with _TMP_LOCK:
        paths, _ALL_TMP[:] = _ALL_TMP[:], []
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass


# Belt-and-braces: a transient Windows file lock can defeat the in-run
# cleanup; atexit retries when the interpreter is definitely idle.
atexit.register(_cleanup_report_tmps)


def _invoke_scanner(url: str, timeout: int = 60,
                    max_payloads: int = 14, max_transforms: int = 12,
                    extra_args: list | None = None,
                    engine: str = "sync") -> tuple[dict | None, float, str]:
    """Invoke XSSentinel CLI and parse JSON report.

    Returns (report_dict_or_None, elapsed_seconds, error_string).
    """
    out_path = _report_tmp_path()

    cmd = [
        sys.executable, "-m", "xssentinel",
        "-u", url,
        "-f", "json",
        "-o", out_path,
        "--progress", "none",
        "--log-level", "error",
        "--max-payloads", str(max_payloads),
        "--max-transforms", str(max_transforms),
        "--threads", "2",
        "--timeout", "10",
    ]
    # Phase 43: engine selection.  --async drives the AsyncScanner path
    # (aiohttp); bump threads so its concurrency advantage is exercised.
    if engine == "async":
        cmd += ["--async", "--threads", "4"]
    if extra_args:
        cmd.extend(extra_args)

    start = time.perf_counter()
    error = ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(_PROJECT_ROOT),
        )
        if proc.returncode not in (0, 1):
            # Exit code 1 is acceptable (CI gate), others indicate errors
            error = f"exit={proc.returncode}: {proc.stderr[:300]}"
    except subprocess.TimeoutExpired:
        error = f"timeout after {timeout}s"
    except Exception as e:
        error = str(e)
    elapsed = time.perf_counter() - start

    # Parse the JSON report (the CLI writes in "w" mode, so the reused temp
    # file is fully truncated per invocation).
    report = None
    try:
        if os.path.isfile(out_path):
            with open(out_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                report = json.loads(content)
    except (json.JSONDecodeError, OSError) as e:
        if not error:
            error = f"report parse: {e}"

    return report, elapsed, error


def _is_detected(report: dict | None, case: dict) -> tuple[bool, int, list]:
    """Determine if the scanner detected XSS for this case.

    Returns (detected, findings_count, relevant_findings).
    """
    if report is None:
        return False, 0, []

    findings = report.get("findings", [])
    if not findings:
        return False, 0, []

    param = case.get("param", "q")
    path = case["path"]

    # Phase 109: vector families that do NOT inject through a query
    # parameter label their carrier instead -- "(cookie:lang)", "(path)",
    # "(error_path)" -- so param-name matching scored a real finding as
    # "not relevant" and the case read as a false negative.  A case may
    # declare the finding type(s) it is about; those count as relevant.
    # Cases without the field keep the exact old behaviour.
    want_types = case.get("finding_types") or []
    # Phase 146: a hash-routed case writes its payload behind a fragment
    # ("/dom/hash-route#/route"), which no HTTP request ever carries -- so no
    # finding's own ``url`` will contain it.  Strip it before matching, the
    # same way the server does when registering the route.
    path_key = path.split("#", 1)[0].rstrip("*") or "/"
    # Phase 120: a crawl case's finding lands on a DISCOVERED endpoint,
    # not on the landing page, so the case may name the paths that count.
    accept_paths = list(case.get("finding_paths") or [path_key])

    # Phase 160: on a SAFE case, any high/medium/critical finding is a false
    # positive -- of ANY type.  Narrowing to the declared ``finding_types``
    # hid a real one for good: neg-dom-08 (safe twin of pos-dom-08) carried a
    # high-severity trusted_types_policy_bypass while the benchmark scored it
    # TN, because the case only declares dom_dynamic.  Measured with
    # _p160_fp_scan.py: 5 of 75 safe cases carried a finding the scorer could
    # not see.
    #
    # Positives keep the narrowing -- an unrelated noisy finding must not be
    # credited as the vector the case is actually about.  low/info stay out:
    # a static DOM hint or an unused-policy note is hygiene, not an XSS claim
    # (verified: the 4 surviving `dom` findings are all low).
    if case.get("ground_truth") == "safe":
        relevant = [
            f for f in findings
            if f.get("severity", "") in ("high", "medium", "critical")
            and not str(f.get("type", "")).startswith("csp_")
            and f.get("type", "") != "fuzzer_triage"
            and any(p in f.get("url", "") for p in accept_paths)
        ]
        return len(relevant) > 0, len(relevant), relevant

    # Filter findings relevant to this case
    relevant = []
    for f in findings:
        f_param = f.get("param", "")
        f_url = f.get("url", "")
        if want_types:
            if (f.get("type", "") in want_types
                    and any(p in f_url for p in accept_paths)):
                relevant.append(f)
            continue
        # Match by param name (or accept any finding if param is empty for DOM)
        if not param:
            # DOM case: any finding on this path counts
            if path in f_url:
                relevant.append(f)
        elif f_param == param:
            relevant.append(f)

    # Exclude info-level fuzzer triage entries
    relevant = [f for f in relevant
                if f.get("severity", "") != "info"
                and f.get("type", "") != "fuzzer_triage"]

    return len(relevant) > 0, len(relevant), relevant


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------

def evaluate_case(base_url: str, case: dict, timeout: int,
                  max_payloads: int, max_transforms: int,
                  engine: str = "sync") -> CaseResult:
    """Evaluate a single manifest case."""
    # Phase 112: some vectors exist on one engine only (stored is
    # sync-only).  Such a case is SKIPPED, not scored as a miss -- an
    # engine cannot be credited with, or blamed for, a vector it does
    # not implement.
    supported = case.get("engines")
    if supported and engine not in supported:
        return CaseResult(
            case_id=case["id"], path=case["path"],
            param=case.get("param", "q"), mode=case["mode"],
            ground_truth=case["ground_truth"],
            context=case.get("context", ""),
            difficulty=case.get("difficulty", ""),
            detected=False, verdict="SKIP", scan_time_s=0.0,
            findings_count=0, requests=0, error="",
            finding_details=[],
        )
    url = _build_target_url(base_url, case)
    report, elapsed, error = _invoke_scanner(
        url, timeout=timeout,
        max_payloads=max_payloads, max_transforms=max_transforms,
        engine=engine,
        extra_args=_case_extra_args(base_url, case))

    detected, count, details = _is_detected(report, case)
    gt = case["ground_truth"]

    # A case the scanner could not complete (timeout, crash, unparseable
    # report) carries NO information about accuracy.  Previously such a case
    # fell through to "TN" whenever it was a negative case, quietly crediting
    # a hung scan as a correct non-detection and understating FPR.  Mark it
    # ERROR instead and exclude it from the rate metrics.
    #
    # Phase 69: EXCEPT for vulnerable cases -- dropping them silently let a
    # flaky host shrink the recall denominator (11 of 98 cases errored out on
    # a degraded-loopback run, i.e. "we never managed to scan it" was still
    # scored as if the case did not exist).  A vulnerability we failed to
    # evaluate is a MISS, not a free pass.  Safe cases stay ERROR (a hung
    # scan is not evidence of a correct non-detection).
    if error:
        verdict = "FN" if gt == "vulnerable" else "ERROR"
    elif gt == "vulnerable":
        verdict = "TP" if detected else "FN"
    else:
        verdict = "FP" if detected else "TN"

    # Slim down finding details for storage
    slim_details = []
    for d in details[:3]:  # keep max 3 findings per case
        slim_details.append({
            "type": d.get("type", ""),
            "payload": d.get("payload", "")[:120],
            "context": d.get("context", ""),
            "severity": d.get("severity", ""),
            "confidence": d.get("confidence", ""),
        })

    return CaseResult(
        case_id=case["id"],
        path=case["path"],
        param=case.get("param", "q"),
        mode=case["mode"],
        ground_truth=gt,
        context=case.get("context", ""),
        difficulty=case.get("difficulty", ""),
        detected=detected,
        verdict=verdict,
        scan_time_s=round(elapsed, 3),
        findings_count=count,
        # Top-level "requests" in the CLI report = scanner's own request
        # count (see cli_runner._write_report).  Wall time on this host
        # varies by >10x with security-agent interference; request counts
        # do not, so they are the metric to reason about.
        requests=int((report or {}).get("requests", 0) or 0),
        finding_details=slim_details,
        error=error,
    )


# Phase 69: retries for cases that error out (timeout / killed connection).
_ERROR_RETRIES = 2


def run_benchmark(port: int = DEFAULT_PORT, concurrency: int = 1,
                  timeout: int = 60, max_payloads: int = 14,
                  max_transforms: int = 12, quick: bool = False,
                  verbose: bool = False, engine: str = "sync") -> BenchmarkResult:
    """Run the full benchmark suite.

    Args:
        port: Benchmark server port.
        concurrency: Number of parallel scanner invocations.
        timeout: Per-case scanner timeout in seconds.
        max_payloads: Scanner payload budget.
        max_transforms: Scanner transform budget.
        quick: If True, run a subset (first 5 pos + first 5 neg) for fast iteration.
        verbose: Print per-case progress.

    Returns:
        BenchmarkResult with all metrics.
    """
    from datetime import datetime

    # Load manifest
    with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    cases = manifest["cases"]

    if quick:
        pos = [c for c in cases if c["ground_truth"] == "vulnerable"][:5]
        neg = [c for c in cases if c["ground_truth"] == "safe"][:5]
        cases = pos + neg
        print(f"[*] Quick mode: {len(cases)} cases")

    # Ensure results directory exists
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Start benchmark server
    base_url = f"http://127.0.0.1:{port}"
    started = threading.Event()
    server_instance = [None]

    def on_ready(srv):
        server_instance[0] = srv
        started.set()
        # serve_forever is run by run_server itself now; calling it here
        # would race a second accept loop on the same server object.

    server_thread = threading.Thread(
        target=run_server, args=(port,),
        kwargs={"ready_callback": on_ready}, daemon=True)
    server_thread.start()

    if not started.wait(timeout=10):
        print("[!] Benchmark server failed to start", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.2)
    print(f"[*] Benchmark server ready on {base_url}")
    print(f"[*] Evaluating {len(cases)} cases "
          f"(engine={engine}, concurrency={concurrency}, timeout={timeout}s)")

    # Run evaluation
    results: list[CaseResult] = []
    bench_start = time.perf_counter()

    if concurrency <= 1:
        for i, case in enumerate(cases):
            r = evaluate_case(base_url, case, timeout, max_payloads,
                              max_transforms, engine=engine)
            # Phase 69: retry cases the scanner could not complete.  This
            # host (and CI runners like it) intermittently kills loopback
            # connections, which otherwise masquerades as a miss.
            for _attempt in range(_ERROR_RETRIES):
                if r.verdict != "FN" or not r.error:
                    break
                if verbose:
                    print(f"    [retry {_attempt + 1}/{_ERROR_RETRIES}] "
                          f"{r.case_id} ({r.error})", file=sys.stderr)
                r = evaluate_case(base_url, case, timeout, max_payloads,
                                  max_transforms, engine=engine)
            results.append(r)
            if verbose or (i + 1) % 10 == 0:
                _print_progress(i + 1, len(cases), r)
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(evaluate_case, base_url, case, timeout,
                            max_payloads, max_transforms, engine): case
                for case in cases
            }
            done_count = 0
            for future in as_completed(futures):
                r = future.result()
                results.append(r)
                done_count += 1
                if verbose or done_count % 10 == 0:
                    _print_progress(done_count, len(cases), r)

    total_time = time.perf_counter() - bench_start

    # Shutdown server
    if server_instance[0]:
        server_instance[0].shutdown()

    # Remove the reusable per-worker report temp files
    _cleanup_report_tmps()

    # Compute metrics
    result = _compute_metrics(results, total_time)
    result.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result.engine = engine

    return result


def _print_progress(done: int, total: int, r: CaseResult):
    """Print a progress line."""
    icon = {"TP": "+", "TN": ".", "FP": "!", "FN": "x", "ERROR": "?"}[r.verdict]
    err = f" ERR:{r.error[:30]}" if r.error else ""
    print(f"  [{done:3d}/{total}] [{icon}] {r.case_id} "
          f"({r.scan_time_s:.1f}s){err}")


def _compute_metrics(results: list[CaseResult], total_time: float) -> BenchmarkResult:
    """Compute aggregate metrics from case results."""
    tp = sum(1 for r in results if r.verdict == "TP")
    fp = sum(1 for r in results if r.verdict == "FP")
    tn = sum(1 for r in results if r.verdict == "TN")
    fn = sum(1 for r in results if r.verdict == "FN")
    errors = sum(1 for r in results if r.verdict == "ERROR")

    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
           if (precision + recall) > 0 else 0.0)

    # Group by context
    by_context: dict[str, dict] = {}
    for r in results:
        ctx = r.context or "unknown"
        if ctx not in by_context:
            by_context[ctx] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0,
                               "error": 0, "total": 0}
        by_context[ctx][r.verdict.lower()] += 1
        by_context[ctx]["total"] += 1

    # Group by difficulty
    by_difficulty: dict[str, dict] = {}
    for r in results:
        diff = r.difficulty or "unknown"
        if diff not in by_difficulty:
            by_difficulty[diff] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0,
                                   "error": 0, "total": 0}
        by_difficulty[diff][r.verdict.lower()] += 1
        by_difficulty[diff]["total"] += 1

    # Extract FP/FN lists
    false_positives = [
        {"id": r.case_id, "path": r.path, "mode": r.mode,
         "context": r.context, "note": r.finding_details}
        for r in results if r.verdict == "FP"
    ]
    false_negatives = [
        {"id": r.case_id, "path": r.path, "mode": r.mode,
         "context": r.context, "difficulty": r.difficulty}
        for r in results if r.verdict == "FN"
    ]

    return BenchmarkResult(
        total_cases=len(results),
        total_time_s=round(total_time, 2),
        tp=tp, fp=fp, tn=tn, fn=fn, errors=errors,
        recall=round(recall, 4),
        precision=round(precision, 4),
        fpr=round(fpr, 4),
        f1=round(f1, 4),
        cases=[asdict(r) for r in results],
        by_context=by_context,
        by_difficulty=by_difficulty,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_result(result: BenchmarkResult, path: Path | None = None) -> Path:
    """Save benchmark result as JSON."""
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if path is None:
        ts = result.timestamp.replace(":", "").replace(" ", "_").replace("-", "")
        path = _RESULTS_DIR / f"benchmark_{ts}.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(result) if hasattr(result, '__dataclass_fields__')
                  else result.__dict__, f, ensure_ascii=False, indent=2)
    return path


def print_summary(result: BenchmarkResult):
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 64)
    print("  XSSentinel Accuracy Benchmark Results")
    print("=" * 64)
    print(f"  Cases:      {result.total_cases}")
    print(f"  Time:       {result.total_time_s:.1f}s")
    print(f"  TP/FP/TN/FN: {result.tp}/{result.fp}/{result.tn}/{result.fn}")
    if result.errors:
        print(f"  ERRORS:     {result.errors}  (excluded from rates below)")
    print(f"  Recall:     {result.recall:.2%}  (detection rate)")
    print(f"  Precision:  {result.precision:.2%}")
    print(f"  FPR:        {result.fpr:.2%}  (false positive rate)")
    print(f"  F1:         {result.f1:.4f}")
    print("-" * 64)

    if result.errors:
        print(f"\n  !! INCOMPLETE CASES ({result.errors}) — scanner did not "
              f"finish; these are NOT counted as correct:")
        for c in result.cases:
            if c.get("verdict") == "ERROR":
                print(f"    - {c['case_id']} [{c['context']}] "
                      f"truth={c['ground_truth']} :: {c['error'][:60]}")
        print("    Raise --timeout or investigate these before trusting "
              "the rates above.")

    if result.false_positives:
        print(f"\n  FALSE POSITIVES ({len(result.false_positives)}):")
        for fp in result.false_positives:
            print(f"    - {fp['id']} ({fp['mode']}) [{fp['context']}]")

    if result.false_negatives:
        print(f"\n  FALSE NEGATIVES ({len(result.false_negatives)}):")
        for fn in result.false_negatives:
            print(f"    - {fn['id']} ({fn['mode']}) [{fn['context']}] "
                  f"difficulty={fn['difficulty']}")

    # Context breakdown
    print(f"\n  BY CONTEXT:")
    for ctx, stats in sorted(result.by_context.items()):
        total = stats["total"]
        tp_s = stats["tp"]
        fp_s = stats["fp"]
        fn_s = stats["fn"]
        err_s = stats.get("error", 0)
        tail = f"  ERR={err_s}" if err_s else ""
        print(f"    {ctx:30s}  total={total:2d}  TP={tp_s}  FP={fp_s}  "
              f"FN={fn_s}{tail}")

    print("=" * 64)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="XSSentinel Accuracy Benchmark Runner")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="Benchmark server port")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="Parallel scanner invocations")
    ap.add_argument("--timeout", type=int, default=90,
                    help="Per-case scanner timeout (seconds)")
    ap.add_argument("--max-payloads", type=int, default=14,
                    help="Scanner payload budget")
    ap.add_argument("--max-transforms", type=int, default=12,
                    help="Scanner transform budget")
    ap.add_argument("--quick", action="store_true",
                    help="Quick mode: small subset for fast iteration")
    ap.add_argument("--engine", choices=["sync", "async"], default="sync",
                    help="Which scanner pipeline to benchmark (Phase 43: "
                         "async is calibrated with the same 98-case matrix)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print every case result")
    ap.add_argument("-o", "--output", default=None,
                    help="Output JSON path (default: auto-timestamped)")
    args = ap.parse_args()

    result = run_benchmark(
        port=args.port,
        concurrency=args.concurrency,
        timeout=args.timeout,
        max_payloads=args.max_payloads,
        max_transforms=args.max_transforms,
        quick=args.quick,
        verbose=args.verbose,
        engine=args.engine,
    )

    print_summary(result)
    out_path = save_result(result, Path(args.output) if args.output else None)
    print(f"\n[+] Results saved to: {out_path}")

    # Exit code: non-zero if FPR > 20% or Recall < 50% (sanity gate)
    if result.fpr > 0.20 or result.recall < 0.50:
        print("[!] Quality gate FAILED (FPR>20% or Recall<50%)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
