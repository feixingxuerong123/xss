"""XSSentinel REST API service (Phase 27-4).

Exposes the scanner as a microservice so it can be invoked over HTTP
from CI runners, security dashboards, orchat orchestration layers
without spawning a subprocess per scan.

Two implementations are provided:

  * :class:`xssentinel.api.server.StdlibServer`
      -- zero-dependency server built on ``http.server``.  Always
      available; suitable for single-process deployments.

  * :class:`xssentinel.api.server.FlaskServer`
      -- optional adapter that reuses the same routing/job layer but
      runs under Flask when it is installed.  Useful when XSSentinel
      must be mounted inside an existing Flask app.

Both servers share :class:`xssentinel.api.jobs.JobManager`, which tracks
scan lifecycle (pending/running/completed/failed/cancelled) in a
thread-safe in-memory store.

Endpoints (see ``server.py`` for the canonical routing table):

  GET    /api/v1/health                -- liveness probe
  GET    /api/v1/info                  -- version + detection-layer list
  POST   /api/v1/scans                 -- start a scan (returns scan_id)
  GET    /api/v1/scans                 -- list scans (status filter)
  GET    /api/v1/scans/{id}            -- scan status + summary
  GET    /api/v1/scans/{id}/findings   -- findings only (JSON)
  GET    /api/v1/scans/{id}/report     -- full report (?format=html|json|...
                                          &ai=1 to add the AI narrative)
  DELETE /api/v1/scans/{id}            -- cancel a running scan
  POST   /api/v1/verify-fix            -- one-shot verify-fix
  POST   /api/v1/diff                  -- one-shot diff of two reports

Authentication (optional): send ``X-API-Key: <key>`` header.  When the
server is started with ``--api-key``, every request must carry the same
key or it gets a 401.

AI narrative (Phase 176, off by default): pass ``"ai_report": true`` to
``POST /api/v1/scans`` and the scan's own worker thread writes the report's
narrative section (executive summary, risk rating, per-finding cause and
remediation, fix priority) as part of finishing the scan -- so no HTTP
request ever waits on a model, and the first report fetch already has it.
``?ai=1`` on the report endpoint generates it for a scan that did not ask,
which BLOCKS that request for as long as the provider pool takes;
``?ai=refresh`` rebuilds it.  Optional per-scan knobs: ``ai_lang`` (zh|en),
``ai_model`` (comma-separated allowlist), ``ai_timeout``, ``ai_max_findings``.

The findings themselves are never produced by a model: type, severity, URL,
parameter and payload all come from the deterministic engine, and every
URL/payload the model quotes is re-checked against the scan before it is
shown.  Enabling this sends the target URL, parameters and payloads to a
third-party provider.  The provider pool comes from the server's
``--ai-config`` (default: the pool shipped in the package); a request may
choose models, but never a filesystem path.  If no provider answers the
section degrades to the built-in remediation corpus rather than failing.

Usage from the CLI::

    python -m xssentinel --serve --host 0.0.0.0 --port 8000

Programmatic usage::

    from xssentinel.api.server import StdlibServer
    StdlibServer(host="127.0.0.1", port=8000).serve_forever()
"""
from __future__ import annotations

from .jobs import JobManager, JobState, JobNotFoundError
from .metrics import MetricsRegistry, get_registry
from .notifications import WebhookNotifier
from .persistence import SqliteJobStore
from .server import (
    StdlibServer,
    FlaskServer,
    run_stdio,  # convenience entry point used by the CLI
)

__all__ = [
    "JobManager",
    "JobState",
    "JobNotFoundError",
    "MetricsRegistry",
    "get_registry",
    "WebhookNotifier",
    "SqliteJobStore",
    "StdlibServer",
    "FlaskServer",
    "run_stdio",
]
