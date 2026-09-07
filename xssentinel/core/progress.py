"""Progress reporting for XSSentinel scans.

Provides a callback-based progress system so the CLI (or any consumer) can
display real-time progress without coupling the scanner to a specific UI.

The scanner calls progress callbacks at key milestones:
  - on_start(total_endpoints)
  - on_endpoint_start(url, index, total)
  - on_endpoint_done(url, findings_count)
  - on_finding(finding_dict)
  - on_done(total_findings, total_requests)

Two built-in renderers:
  - ConsoleProgress: a lightweight text progress bar (no external deps).
  - NullProgress: no-op (for silent/programmatic use).
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Callable


# Type alias for a progress callback.
ProgressCallback = Callable[[str, dict], None]


class ProgressReporter:
    """Base class: dispatches progress events to a callback."""

    def __init__(self, callback: ProgressCallback | None = None):
        self._callback = callback
        self._lock = threading.Lock()
        self._start_time = 0.0
        self._endpoints_total = 0
        self._endpoints_done = 0
        self._findings_count = 0
        self._requests = 0

    def emit(self, event: str, data: dict | None = None) -> None:
        if self._callback:
            try:
                self._callback(event, data or {})
            except Exception:
                pass  # progress must never break the scan

    def on_start(self, total_endpoints: int) -> None:
        with self._lock:
            self._start_time = time.time()
            self._endpoints_total = total_endpoints
            self._endpoints_done = 0
        self.emit("start", {"total": total_endpoints})

    def on_endpoint_start(self, url: str, index: int, total: int) -> None:
        self.emit("endpoint_start", {"url": url, "index": index,
                                      "total": total})

    def on_endpoint_done(self, url: str, findings: int) -> None:
        with self._lock:
            self._endpoints_done += 1
            self._findings_count += findings
        self.emit("endpoint_done", {"url": url, "findings": findings,
                                     "done": self._endpoints_done,
                                     "total": self._endpoints_total})

    def on_finding(self, finding: dict) -> None:
        with self._lock:
            self._findings_count += 1
        self.emit("finding", finding)

    def on_request(self) -> None:
        with self._lock:
            self._requests += 1

    def on_done(self, total_findings: int, total_requests: int) -> None:
        elapsed = time.time() - self._start_time if self._start_time else 0
        self.emit("done", {"findings": total_findings,
                            "requests": total_requests,
                            "elapsed": round(elapsed, 2)})


class ConsoleProgress(ProgressReporter):
    """Lightweight console progress bar (no external dependencies).

    Renders a single-line progress bar that updates in-place using \\r.
    Falls back to plain prints when stdout is not a TTY (e.g. piped to a
    file).
    """

    def __init__(self, stream=None, show_bar: bool = True):
        super().__init__(callback=self._render)
        self._stream = stream or sys.stderr
        self._is_tty = hasattr(self._stream, "isatty") and self._stream.isatty()
        self._show_bar = show_bar and self._is_tty

    def _render(self, event: str, data: dict) -> None:
        if event == "start":
            if self._is_tty:
                self._stream.write(f"\r[*] Scanning {data['total']} endpoint(s)...\n")
        elif event == "endpoint_start":
            if self._show_bar:
                pct = int(data["index"] / max(data["total"], 1) * 100)
                bar_w = 30
                filled = int(bar_w * pct / 100)
                bar = "=" * filled + "-" * (bar_w - filled)
                url_short = data["url"][:50]
                self._stream.write(
                    f"\r[{bar}] {pct:3d}% ({data['index']}/{data['total']}) {url_short}")
                self._stream.flush()
        elif event == "endpoint_done":
            if self._show_bar:
                pct = int(data["done"] / max(data["total"], 1) * 100)
                bar_w = 30
                filled = int(bar_w * pct / 100)
                bar = "=" * filled + "-" * (bar_w - filled)
                self._stream.write(
                    f"\r[{bar}] {pct:3d}% ({data['done']}/{data['total']}) "
                    f"findings={data['findings']}    \n")
                self._stream.flush()
        elif event == "finding":
            sev = data.get("severity", "?")
            typ = data.get("type", "?")
            url = data.get("url", "")[:60]
            self._stream.write(f"  [+] {sev:6} {typ:20} {url}\n")
            self._stream.flush()
        elif event == "done":
            elapsed = data.get("elapsed", 0)
            self._stream.write(
                f"\n[+] Scan complete: {data['findings']} finding(s), "
                f"{data['requests']} request(s) in {elapsed}s\n")


class NullProgress(ProgressReporter):
    """No-op progress reporter (for silent/programmatic use)."""

    def __init__(self):
        super().__init__(callback=None)
