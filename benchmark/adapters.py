"""Unified adapters for横向对比 XSSentinel / dalfox / XSStrike.

Each adapter exposes:
  - name: str
  - available() -> bool
  - scan_case(base_url, case) -> {"detected": bool, "raw_output": str, "time_s": float}

Usage:
  from benchmark.adapters import get_adapters
  adapters = get_adapters()  # returns list of available adapters
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlencode

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _scan_case_dict(detected, raw_output, elapsed, error=None):
    """Normalize adapter result. `error` marks incomplete runs (timeout/crash),
    which must NOT be counted as TN/FN by the comparison runner."""
    return {"detected": detected, "raw_output": raw_output,
            "time_s": elapsed, "error": error}


def _parse_dalfox_findings(stdout: str) -> list:
    """Parse dalfox `--format json` output into a list of finding dicts.

    dalfox v2.x emits JSONL: one finding object per line, e.g.
        {"data":"...","poc":"...","type":"found","param":"q",...}
    It is NOT a JSON array, and single-finding output is a bare object
    (not wrapped in {"findings": [...]}) — handle all shapes defensively.
    Empty stdout means "no findings".
    """
    text = (stdout or "").strip()
    if not text:
        return []
    # Whole-output JSON first (array / wrapper dict / bare single object)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict)]
        if isinstance(data, dict):
            inner = data.get("findings")
            if isinstance(inner, list):
                return [f for f in inner if isinstance(f, dict)]
            return [data]
    except json.JSONDecodeError:
        pass
    # JSONL: accumulate finding objects line by line
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                findings.append(obj)
        except json.JSONDecodeError:
            continue
    return findings


# ---------------------------------------------------------------------------
# XSSentinel adapter
# ---------------------------------------------------------------------------

class XSSentinelAdapter:
    name = "XSSentinel"

    def available(self) -> bool:
        """XSSentinel is always available (we ARE xssentinel)."""
        return True

    def scan_case(self, base_url: str, case: dict) -> dict:
        """Invoke XSSentinel CLI against a single benchmark case."""
        path = case["path"]
        param = case.get("param", "q")
        url = f"{base_url}{path}?{param}=test"

        cmd = [
            sys.executable, "-m", "xssentinel",
            "-u", url,
            "--max-payloads", "10",
            "--max-transforms", "6",
            "-f", "json",
            "--no-color",
        ]

        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=90,
                cwd=_ROOT,
            )
            elapsed = time.time() - t0
            stdout = proc.stdout or ""
            detected = False
            error = None
            try:
                report = json.loads(stdout)
                findings = report.get("findings", [])
                # Filter to XSS findings (exclude CSP/info)
                xss = [f for f in findings
                       if f.get("severity") in ("high", "medium", "critical")
                       and not str(f.get("type", "")).startswith("csp_")]
                detected = len(xss) > 0
            except (json.JSONDecodeError, KeyError, TypeError):
                # CLI promised -f json but emitted garbage => crashed run,
                # must not be scored as a clean "not detected"
                error = f"bad-json-output (rc={proc.returncode})"
            return _scan_case_dict(detected, stdout[:500], elapsed, error)
        except subprocess.TimeoutExpired:
            return _scan_case_dict(False, "TIMEOUT", 90.0, "timeout")
        except Exception as e:  # noqa: BLE001
            return _scan_case_dict(False, str(e), 0.0, f"exception: {e}")


# ---------------------------------------------------------------------------
# dalfox adapter
# ---------------------------------------------------------------------------

class DalfoxAdapter:
    name = "dalfox"

    def __init__(self):
        self._binary = shutil.which("dalfox")

    def available(self) -> bool:
        return self._binary is not None

    def scan_case(self, base_url: str, case: dict) -> dict:
        """Invoke dalfox against a single benchmark case."""
        if not self._binary:
            return _scan_case_dict(False, "dalfox not installed", 0.0,
                                    "not-installed")

        path = case["path"]
        param = case.get("param", "q")
        url = f"{base_url}{path}?{param}=test"

        cmd = [
            self._binary, "url", url,
            "--format", "json",
            "--silence",
            "--timeout", "30",
            "--worker", "1",
        ]

        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            elapsed = time.time() - t0
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            findings = _parse_dalfox_findings(stdout)
            detected = len(findings) > 0
            # dalfox only emits a finding JSONL line for results it itself
            # considers confirmed; presence of any line == detected.
            error = None
            if not findings and stderr.strip():
                # With --silence, stderr chatter is fine (progress/reset), but
                # a non-zero exit with empty stdout means the run died early.
                if proc.returncode != 0:
                    error = f"dalfox rc={proc.returncode}"
            return _scan_case_dict(detected, stdout[:500], elapsed, error)
        except subprocess.TimeoutExpired:
            return _scan_case_dict(False, "TIMEOUT", 60.0, "timeout")
        except Exception as e:  # noqa: BLE001
            return _scan_case_dict(False, str(e), 0.0, f"exception: {e}")


# ---------------------------------------------------------------------------
# XSStrike adapter
# ---------------------------------------------------------------------------

class XSStrikeAdapter:
    name = "XSStrike"

    def __init__(self):
        # XSStrike is typically cloned into a directory
        self._path = os.environ.get("XSSTRIKE_PATH",
                                    os.path.join(_ROOT, "..", "XSStrike"))
        self._script = os.path.join(self._path, "xsstrike.py")

    def available(self) -> bool:
        return os.path.isfile(self._script)

    def scan_case(self, base_url: str, case: dict) -> dict:
        """Invoke XSStrike against a single benchmark case."""
        if not self.available():
            return _scan_case_dict(False, "XSStrike not installed", 0.0,
                                    "not-installed")

        path = case["path"]
        param = case.get("param", "q")
        url = f"{base_url}{path}?{param}=test"

        cmd = [
            sys.executable, self._script,
            "-u", url,
            "--json",
            "--seeds", "1",
            "--timeout", "30",
        ]

        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
                cwd=self._path,
            )
            elapsed = time.time() - t0
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            output = stdout + stderr
            detected = False
            error = None
            try:
                data = json.loads(stdout)
                if isinstance(data, list):
                    detected = len(data) > 0
                elif isinstance(data, dict):
                    detected = bool(data.get("vulnerable"))
            except json.JSONDecodeError:
                # XSStrike text output: only explicit confirmations count.
                # ("reflected" alone is NOT a confirmation — it appears in
                # benign output about plain reflection checks.)
                detected = bool(re.search(
                    r"confirmed|is vulnerable|vulnerable to", output, re.I))
            return _scan_case_dict(detected, output[:500], elapsed, error)
        except subprocess.TimeoutExpired:
            return _scan_case_dict(False, "TIMEOUT", 60.0, "timeout")
        except Exception as e:  # noqa: BLE001
            return _scan_case_dict(False, str(e), 0.0, f"exception: {e}")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_ALL_ADAPTERS = [XSSentinelAdapter(), DalfoxAdapter(), XSStrikeAdapter()]


def get_adapters(only_available: bool = True) -> list:
    """Return list of adapters. If only_available, filter to installed tools."""
    if only_available:
        return [a for a in _ALL_ADAPTERS if a.available()]
    return list(_ALL_ADAPTERS)


def run_comparison(base_url: str, cases: list, adapters: list | None = None,
                   verbose: bool = False) -> dict:
    """Run all adapters against all cases and compute comparative metrics.

    Returns:
        {
            "tool_name": {
                "tp": int, "fp": int, "tn": int, "fn": int, "errors": int,
                "recall": float, "precision": float, "fpr": float, "f1": float,
                "completed": int, "total_time_s": float,
                "details": [{"case_id": ..., "detected": bool, "ground_truth": ...}]
            }
        }
    """
    if adapters is None:
        adapters = get_adapters()

    results = {}
    for adapter in adapters:
        if verbose:
            print(f"\n[*] Running {adapter.name} against {len(cases)} cases...")
        tp = fp = tn = fn = errors = 0
        total_time = 0.0
        details = []

        for i, case in enumerate(cases):
            if verbose and (i + 1) % 10 == 0:
                print(f"  [{i+1}/{len(cases)}]")
            r = adapter.scan_case(base_url, case)
            total_time += r["time_s"]
            detected = r["detected"]
            gt = case["ground_truth"]

            # Incomplete runs (timeout / crash / bad output) are excluded
            # from the confusion matrix — never silently scored as TN/FN.
            if r.get("error"):
                verdict = "ERROR"
                errors += 1
            elif gt == "vulnerable" and detected:
                verdict = "TP"
                tp += 1
            elif gt == "vulnerable" and not detected:
                verdict = "FN"
                fn += 1
            elif gt == "safe" and detected:
                verdict = "FP"
                fp += 1
            else:
                verdict = "TN"
                tn += 1

            details.append({
                "case_id": case["id"],
                "ground_truth": gt,
                "detected": detected,
                "verdict": verdict,
                "error": r.get("error"),
                "time_s": r["time_s"],
            })

        # Compute metrics over completed cases only
        completed = tp + fp + tn + fn
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
               if (precision + recall) > 0 else 0.0)

        results[adapter.name] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "errors": errors,
            "completed": completed,
            "recall": recall, "precision": precision,
            "fpr": fpr, "f1": f1,
            "total_time_s": total_time,
            "details": details,
        }

        if verbose:
            err_note = f" ERR={errors}" if errors else ""
            print(f"  {adapter.name}: Recall={recall:.2%} FPR={fpr:.2%} "
                  f"F1={f1:.4f} Time={total_time:.1f}s{err_note}")
            if errors:
                failed = [d["case_id"] for d in details
                          if d["verdict"] == "ERROR"]
                print(f"    [!] {errors} case(s) did not complete: "
                      f"{failed}")

    return results
