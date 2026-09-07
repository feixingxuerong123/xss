"""Request budget guard (pentest-readiness, Phase 46).

The pentest audit flagged that the scanner has no global request budget:
on a large target the default policy (14 payloads x 12 transforms x N
params x crawled endpoints, unlimited rate) can hammer a production
application with tens of thousands of requests.  Authorization letters
usually cap the request rate / volume, and unbounded scanning is a
compliance -- and availability -- risk.

``Budget`` is a tiny thread-safe counter shared by every request path:

* ``Requester`` spends one unit per real network call (sync path, all
  worker clones), raising :class:`BudgetExhausted` when the total or
  per-endpoint cap is hit.  The exception propagates up to the per-target
  scan loop, which stops gracefully and still writes a report.
* ``AsyncScanner`` enforces the same caps inside ``_throttle()`` (aiohttp
  traffic never touches ``Requester``).

Cached GET responses do NOT spend budget (no wire traffic).
"""
from __future__ import annotations

import threading
from urllib.parse import urlparse


class BudgetExhausted(RuntimeError):
    """Raised when the request budget (total or per-endpoint) is spent."""


class CircuitOpen(RuntimeError):
    """Raised when the target looks down/protected: too many consecutive
    5xx/429 responses (or the breaker was tripped mid-scan).  The scan
    stops gracefully instead of hammering a dead or blocking target."""


class CircuitBreaker:
    """Consecutive-failure circuit breaker (5xx / 429).

    A run of ``threshold`` failures within ``window`` seconds trips the
    breaker; any success (2xx/3xx/4xx-other) resets the streak.  Once
    tripped, ``Requester`` raises :class:`CircuitOpen` before sending, so
    the scan stops instead of grinding against a target that is down,
    overloaded, or already blocking the source IP.
    """

    def __init__(self, threshold: int = 25, window: float = 120.0):
        self.threshold = max(1, int(threshold))
        self.window = float(window)
        self._fail_times: list[float] = []
        self._lock = threading.Lock()

    @staticmethod
    def _is_failure(status: int) -> bool:
        return 500 <= status <= 599 or status == 429

    def record(self, status: int) -> None:
        """Feed one response status into the breaker."""
        import time
        now = time.monotonic()
        with self._lock:
            if self._is_failure(status):
                self._fail_times = [t for t in self._fail_times
                                    if now - t <= self.window]
                self._fail_times.append(now)
            else:
                self._fail_times.clear()  # success resets the streak

    @property
    def tripped(self) -> bool:
        with self._lock:
            return len(self._fail_times) >= self.threshold

    @property
    def failure_streak(self) -> int:
        with self._lock:
            return len(self._fail_times)


class Budget:
    """Thread-safe request budget (total + per-endpoint caps).

    ``max_total`` / ``max_per_endpoint`` of ``None`` mean unlimited.
    The per-endpoint key is the request URL as given to :meth:`spend`
    (callers pass the target URL, so probe variations on the same
    endpoint share one counter).
    """

    def __init__(self, max_total: int | None = None,
                 max_per_endpoint: int | None = None):
        self.max_total = max_total if (max_total is None or max_total > 0) \
            else None
        self.max_per_endpoint = max_per_endpoint \
            if (max_per_endpoint is None or max_per_endpoint > 0) else None
        self.total = 0
        self._per_endpoint: dict[str, int] = {}
        self._lock = threading.Lock()

    def spend(self, url: str | None = None) -> None:
        """Record one outgoing request; raise BudgetExhausted when over."""
        with self._lock:
            self.total += 1
            if self.max_total is not None and self.total > self.max_total:
                raise BudgetExhausted(
                    f"total request budget exhausted "
                    f"(>{self.max_total} requests)")
            if self.max_per_endpoint is not None and url:
                key = self._endpoint_key(url)
                count = self._per_endpoint.get(key, 0) + 1
                self._per_endpoint[key] = count
                if count > self.max_per_endpoint:
                    raise BudgetExhausted(
                        f"per-endpoint request budget exhausted for "
                        f"{key} (>{self.max_per_endpoint} requests)")

    @property
    def exhausted(self) -> bool:
        with self._lock:
            if self.max_total is not None and self.total >= self.max_total:
                return True
            return False

    @staticmethod
    def _endpoint_key(url: str) -> str:
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return url or ""
