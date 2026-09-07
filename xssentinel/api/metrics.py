"""Prometheus-compatible metrics export (Phase 28-3).

Exposes scanner and API operational metrics in the Prometheus text
exposition format at ``/api/v1/metrics``.  No external dependency on
``prometheus_client`` -- the format is simple enough to emit by hand,
and keeping the dependency surface small matters for a security tool
that may run in air-gapped environments.

Tracked metrics
---------------
* ``xssentinel_scans_total`` (counter) -- total scans created, by state.
* ``xssentinel_findings_total`` (counter) -- total findings, by severity.
* ``xssentinel_scan_duration_seconds`` (histogram) -- scan wall-time.
* ``xssentinel_http_requests_total`` (counter) -- API requests, by route.
* ``xssentinel_active_jobs`` (gauge) -- currently active (pending/running).
* ``xssentinel_webhook_delivered_total`` (counter) -- webhook deliveries.
* ``xssentinel_webhook_failed_total`` (counter) -- failed deliveries.

All counters are cumulative since process start.  The registry is
thread-safe.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict


class MetricsRegistry:
    """Thread-safe metrics registry emitting Prometheus text format.

    The registry holds counters, gauges, and a simple histogram.  It is
    intentionally minimal -- enough for operational dashboards without
    pulling in a full metrics library.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Counters: name -> {label_tuple -> value}.  We use a tuple of
        # (label_name, label_value) pairs as the key so multi-label
        # counters (e.g. scans_total{state="completed"}) work.
        self._counters: dict[str, dict[tuple, float]] = defaultdict(dict)
        # Gauges: name -> {label_tuple -> value}.
        self._gauges: dict[str, dict[tuple, float]] = defaultdict(dict)
        # Histograms: name -> {label_tuple -> {bucket_le -> count, ...,
        # "_count": n, "_sum": total}}.  Buckets are fixed at init.
        self._histograms: dict[str, dict[tuple, dict[str, float]]] = defaultdict(dict)
        self._bucket_specs: dict[str, list[float]] = {}
        # Help text for each metric.
        self._help: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register_counter(self, name: str, help_text: str = "") -> None:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = {}
                self._help[name] = help_text

    def register_gauge(self, name: str, help_text: str = "") -> None:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = {}
                self._help[name] = help_text

    def register_histogram(self, name: str, buckets: list[float],
                           help_text: str = "") -> None:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {}
                self._bucket_specs[name] = sorted(buckets)
                self._help[name] = help_text

    # ------------------------------------------------------------------
    # Increment / set
    # ------------------------------------------------------------------
    def inc_counter(self, name: str, value: float = 1, **labels) -> None:
        key = self._labels_key(labels)
        with self._lock:
            buckets = self._counters.get(name)
            if buckets is None:
                # Auto-register if not explicitly registered.
                self._counters[name] = {}
                buckets = self._counters[name]
            buckets[key] = buckets.get(key, 0) + value

    def set_gauge(self, name: str, value: float, **labels) -> None:
        key = self._labels_key(labels)
        with self._lock:
            buckets = self._gauges.get(name)
            if buckets is None:
                self._gauges[name] = {}
                buckets = self._gauges[name]
            buckets[key] = value

    def observe(self, name: str, value: float, **labels) -> None:
        """Record a value in a histogram."""
        key = self._labels_key(labels)
        with self._lock:
            hist = self._histograms.get(name)
            if hist is None:
                # Auto-register with default buckets if not registered.
                default_buckets = [0.5, 1, 2.5, 5, 10, 30, 60, 120, 300]
                self._histograms[name] = {}
                self._bucket_specs[name] = default_buckets
                hist = self._histograms[name]
            entry = hist.get(key)
            if entry is None:
                entry = {"_count": 0, "_sum": 0.0}
                for le in self._bucket_specs[name]:
                    entry[f"le_{le}"] = 0
                hist[key] = entry
            entry["_count"] += 1
            entry["_sum"] += value
            for le in self._bucket_specs[name]:
                if value <= le:
                    entry[f"le_{le}"] += 1

    @staticmethod
    def _labels_key(labels: dict[str, str]) -> tuple:
        return tuple(sorted(labels.items()))

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def render(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            # Counters
            for name in sorted(self._counters):
                help_text = self._help.get(name, "")
                if help_text:
                    lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} counter")
                for label_tuple, value in sorted(self._counters[name].items()):
                    label_str = self._format_labels(label_tuple)
                    lines.append(f"{name}{label_str} {value}")
            # Gauges
            for name in sorted(self._gauges):
                help_text = self._help.get(name, "")
                if help_text:
                    lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} gauge")
                for label_tuple, value in sorted(self._gauges[name].items()):
                    label_str = self._format_labels(label_tuple)
                    lines.append(f"{name}{label_str} {value}")
            # Histograms
            for name in sorted(self._histograms):
                help_text = self._help.get(name, "")
                if help_text:
                    lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} histogram")
                buckets = self._bucket_specs.get(name, [])
                for label_tuple, entry in sorted(self._histograms[name].items()):
                    label_base = dict(label_tuple)
                    for le in buckets:
                        labels = dict(label_base)
                        labels["le"] = str(le)
                        lines.append(f"{name}_bucket{self._format_labels(self._labels_key(labels))} {int(entry.get(f'le_{le}', 0))}")
                    # +Inf bucket
                    labels = dict(label_base)
                    labels["le"] = "+Inf"
                    lines.append(f"{name}_bucket{self._format_labels(self._labels_key(labels))} {int(entry.get('_count', 0))}")
                    lines.append(f"{name}_count{self._format_labels(label_tuple)} {int(entry.get('_count', 0))}")
                    lines.append(f"{name}_sum{self._format_labels(label_tuple)} {entry.get('_sum', 0.0)}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _format_labels(label_tuple: tuple) -> str:
        if not label_tuple:
            return ""
        parts = [f'{k}="{v}"' for k, v in label_tuple]
        return "{" + ",".join(parts) + "}"


# ---------------------------------------------------------------------------
# Module-level singleton (shared by the API server)
# ---------------------------------------------------------------------------
_REGISTRY: MetricsRegistry | None = None
_REGISTRY_LOCK = threading.Lock()


def get_registry() -> MetricsRegistry:
    """Return the process-wide metrics registry (lazy singleton)."""
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            _REGISTRY = MetricsRegistry()
            _register_defaults(_REGISTRY)
        return _REGISTRY


def _register_defaults(reg: MetricsRegistry) -> None:
    """Register the standard XSSentinel metrics on first access."""
    reg.register_counter("xssentinel_scans_total",
                         "Total scans created, by final state")
    reg.register_counter("xssentinel_findings_total",
                         "Total findings emitted, by severity")
    reg.register_histogram("xssentinel_scan_duration_seconds",
                           [1, 5, 10, 30, 60, 120, 300, 600],
                           "Scan wall-time in seconds")
    reg.register_counter("xssentinel_http_requests_total",
                         "API HTTP requests served, by route and status")
    reg.register_gauge("xssentinel_active_jobs",
                       "Currently active (pending or running) scan jobs")
    reg.register_counter("xssentinel_webhook_delivered_total",
                         "Webhook deliveries successfully completed")
    reg.register_counter("xssentinel_webhook_failed_total",
                         "Webhook deliveries that failed after all retries")
