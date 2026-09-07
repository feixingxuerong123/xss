"""Checkpoint / resume support for XSSentinel.

Saves scan progress (scanned URLs + findings) to a JSON checkpoint file so
interrupted scans can be resumed without re-scanning already-processed
endpoints.

Checkpoint schema:

    {
      "version": 1,
      "target": "https://example.com",
      "started": "2026-07-28T12:00:00",
      "updated": "2026-07-28T12:05:30",
      "scanned_urls": ["https://example.com/a", "https://example.com/b"],
      "findings": [ {finding_dict}, ... ],
      "requests_made": 42,
      "waf_name": "Cloudflare"
    }

Usage:
    ckpt = Checkpoint("scan.ckpt.json")
    ckpt.mark_scanned(url)
    ckpt.add_findings(findings)
    ckpt.save()

    # On resume:
    ckpt = Checkpoint.load("scan.ckpt.json")
    if ckpt.is_scanned(url):
        skip  # already processed
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime


class Checkpoint:
    """Track scan progress for save/resume."""

    def __init__(self, path: str, target: str = ""):
        self.path = path
        self.target = target
        self.started = datetime.now().isoformat()
        self.updated = self.started
        self._scanned: set[str] = set()
        self._findings: list[dict] = []
        self.requests_made = 0
        self.waf_name: str | None = None
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str) -> "Checkpoint | None":
        """Load a checkpoint file.  Returns None if file doesn't exist or is
        corrupt."""
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ckpt = cls(path, data.get("target", ""))
            ckpt._scanned = set(data.get("scanned_urls", []))
            ckpt._findings = list(data.get("findings", []))
            ckpt.requests_made = data.get("requests_made", 0)
            ckpt.waf_name = data.get("waf_name")
            ckpt.started = data.get("started", ckpt.started)
            ckpt.updated = data.get("updated", ckpt.updated)
            return ckpt
        except (json.JSONDecodeError, OSError):
            return None

    def mark_scanned(self, url: str) -> None:
        """Mark a URL as scanned (skip on resume)."""
        with self._lock:
            self._scanned.add(url)

    def is_scanned(self, url: str) -> bool:
        """Check if a URL was already scanned in a previous run."""
        return url in self._scanned

    def add_findings(self, findings: list) -> None:
        """Append new findings to the checkpoint."""
        with self._lock:
            for f in findings:
                d = f.data if hasattr(f, "data") else f
                self._findings.append(d)

    def save(self) -> bool:
        """Persist the checkpoint to disk."""
        with self._lock:
            self.updated = datetime.now().isoformat()
            data = {
                "version": 1,
                "target": self.target,
                "started": self.started,
                "updated": self.updated,
                "scanned_urls": sorted(self._scanned),
                "findings": list(self._findings),
                "requests_made": self.requests_made,
                "waf_name": self.waf_name,
            }
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    @property
    def scanned_count(self) -> int:
        return len(self._scanned)

    @property
    def findings(self) -> list[dict]:
        return list(self._findings)
