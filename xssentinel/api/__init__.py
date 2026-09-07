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
  GET    /api/v1/scans/{id}/report     -- full report (?format=html|json|...)
  DELETE /api/v1/scans/{id}            -- cancel a running scan
  POST   /api/v1/verify-fix            -- one-shot verify-fix
  POST   /api/v1/diff                  -- one-shot diff of two reports

Authentication (optional): send ``X-API-Key: <key>`` header.  When the
server is started with ``--api-key``, every request must carry the same
key or it gets a 401.

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
