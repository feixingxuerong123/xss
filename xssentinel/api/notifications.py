"""Webhook notifications for scan completion (Phase 28-2).

When a scan reaches a terminal state (completed/failed/cancelled), the
:class:`WebhookNotifier` POSTs a JSON payload to one or more configured
URLs.  This lets CI pipelines, Slack bots, or security dashboards react
to scan results without polling the API.

Design
------
* Delivery is **fire-and-forget** -- the scan worker is never blocked
  by a slow webhook endpoint.  Each delivery runs in its own daemon
  thread.
* **Retry with backoff**: a failed delivery (non-2xx status or network
  error) is retried up to 3 times with exponential backoff (1s, 2s, 4s).
* **Signature**: each delivery includes an ``X-XSSentinel-Signature``
  header containing ``sha256=<hex>`` of the JSON body HMAC'd with the
  configured secret (if any), so receivers can verify authenticity.
* **Idempotency**: the payload includes ``scan_id`` and ``finished_at``
  so receivers can deduplicate deliveries (e.g. if a scan is cancelled
  and then re-run with the same id -- which won't happen with our UUID
  scheme, but external systems may requeue).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any


class WebhookNotifier:
    """Deliver scan-completion webhooks to one or more endpoints.

    Parameters
    ----------
    urls:
        List of webhook endpoint URLs.  May be empty (no-op).
    secret:
        Optional shared secret for HMAC signing.  When set, each
        request includes ``X-XSSentinel-Signature: sha256=<hex>``.
    timeout:
        Per-request timeout in seconds (default 10).
    max_retries:
        Max delivery attempts on failure (default 3, with exponential
        backoff 1s/2s/4s).
    """

    def __init__(self, urls: list[str] | None = None, secret: str | None = None,
                 timeout: float = 10, max_retries: int = 3) -> None:
        self._urls = list(urls or [])
        self._secret = secret
        self._timeout = timeout
        self._max_retries = max(1, max_retries)
        self._lock = threading.Lock()
        # Track delivery stats for observability (not exposed yet, but
        # available for the /metrics endpoint in Phase 28-3).
        self._delivered = 0
        self._failed = 0

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def add_url(self, url: str) -> None:
        with self._lock:
            if url and url not in self._urls:
                self._urls.append(url)

    def notify_scan_complete(self, job_summary: dict[str, Any]) -> None:
        """Fire webhook deliveries for a completed scan.

        This method returns immediately -- each URL gets its own daemon
        thread so a slow endpoint never blocks the scan worker or other
        deliveries.

        ``job_summary`` should contain at least ``scan_id``, ``state``,
        ``target_url``, ``finding_count``, and ``finished_at``.  The
        full findings list is NOT included (it can be large); receivers
        should GET ``/api/v1/scans/{scan_id}/findings`` to fetch them.
        """
        if not self._urls:
            return
        payload = self._build_payload(job_summary)
        body = json.dumps(payload).encode("utf-8")
        signature = self._sign(body)
        for url in self._urls:
            t = threading.Thread(
                target=self._deliver_with_retry,
                args=(url, body, signature),
                name=f"xssentinel-webhook-{job_summary.get('scan_id', '?')}",
                daemon=True)
            t.start()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_payload(job_summary: dict[str, Any]) -> dict[str, Any]:
        """Construct the webhook JSON payload from a job summary."""
        return {
            "event": "scan.completed",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "scan_id": job_summary.get("scan_id"),
            "state": job_summary.get("state"),
            "target_url": job_summary.get("target_url"),
            "method": job_summary.get("method", "GET"),
            "finding_count": job_summary.get("finding_count", 0),
            "high_severity_count": job_summary.get("high_severity_count", 0),
            "requests_made": job_summary.get("requests_made", 0),
            "waf_name": job_summary.get("waf_name"),
            "error": job_summary.get("error"),
            "created_at": job_summary.get("created_at"),
            "finished_at": job_summary.get("finished_at"),
            # Hint for the receiver: where to fetch full findings.
            "findings_url": (f"/api/v1/scans/{job_summary.get('scan_id', '')}/findings"
                             if job_summary.get("scan_id") else None),
        }

    def _sign(self, body: bytes) -> str | None:
        if not self._secret:
            return None
        mac = hmac.new(self._secret.encode("utf-8"), body, hashlib.sha256)
        return "sha256=" + mac.hexdigest()

    def _deliver_with_retry(self, url: str, body: bytes,
                            signature: str | None) -> None:
        """Deliver to one URL with exponential-backoff retries."""
        last_err: str | None = None
        for attempt in range(self._max_retries):
            try:
                self._deliver(url, body, signature)
                with self._lock:
                    self._delivered += 1
                return
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt < self._max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s, ...
                    time.sleep(2 ** attempt)
        # All retries exhausted.
        with self._lock:
            self._failed += 1
        # Phase 29-3: use the project logger instead of raw stderr print
        # so webhook delivery failures are captured by the same logging
        # pipeline as the rest of the system.
        from xssentinel.core.logger import get_logger
        _log = get_logger("webhook")
        _log.error(
            "webhook delivery to %s failed after %d attempts: %s",
            url, self._max_retries, last_err,
        )

    def _deliver(self, url: str, body: bytes, signature: str | None) -> None:
        """Single delivery attempt.  Raises on non-2xx or network error."""
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "XSSentinel-Webhook/1.0",
            })
        if signature:
            req.add_header("X-XSSentinel-Signature", signature)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                status = resp.getcode()
                if not (200 <= status < 300):
                    raise urllib.error.HTTPError(
                        url, status, f"webhook returned {status}",
                        resp.headers, None)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            raise ConnectionError(f"webhook URL error: {e}")

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    def stats(self) -> dict[str, int]:
        """Return cumulative delivery counters (for /metrics)."""
        with self._lock:
            return {
                "webhook_delivered_total": self._delivered,
                "webhook_failed_total": self._failed,
                "webhook_urls_configured": len(self._urls),
            }
