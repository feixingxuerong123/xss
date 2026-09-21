"""SQLite persistence backend for the JobManager (Phase 28-1).

The default :class:`~xssentinel.api.jobs.JobManager` keeps everything in
memory -- once the process exits, all scan history is lost.  This module
provides an opt-in SQLite store that survives restarts, so a deployment
that crashes or is upgraded can resume serving historical scan results.

Design
------
* :class:`SqliteJobStore` implements the same surface the in-memory
  dict does (``save``, ``load``, ``load_all``, ``delete``), but backed
  by a single ``jobs`` table in a SQLite file.
* :class:`~xssentinel.api.jobs.JobManager` accepts an optional
  ``store`` argument.  When provided, every state transition is mirrored
  to the store in addition to the in-memory dict.  The in-memory dict
  remains the hot read path (no extra latency on ``get``/``list_jobs``);
  SQLite is write-through and used only for durability + reload.
* Findings can be large (hundreds of entries with PoC blobs), so they
  are stored as a JSON blob in a TEXT column rather than normalised
  across tables -- this keeps the schema simple and avoids N+1 queries
  on reload.
* The connection is opened with ``check_same_thread=False`` and guarded
  by a re-entrant lock, because the HTTP handler thread and the worker
  thread both write through it.  SQLite handles concurrent writes with
  its own file lock; the Python lock serialises access to the
  connection object itself.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    scan_id          TEXT PRIMARY KEY,
    target_url       TEXT NOT NULL,
    method           TEXT NOT NULL DEFAULT 'GET',
    params           TEXT NOT NULL DEFAULT '{}',
    data             TEXT NOT NULL DEFAULT '{}',
    options          TEXT NOT NULL DEFAULT '{}',
    state            TEXT NOT NULL DEFAULT 'pending',
    created_at       TEXT NOT NULL DEFAULT '',
    started_at       TEXT NOT NULL DEFAULT '',
    finished_at      TEXT NOT NULL DEFAULT '',
    error            TEXT,
    findings         TEXT NOT NULL DEFAULT '[]',
    finding_count    INTEGER NOT NULL DEFAULT 0,
    high_severity_count INTEGER NOT NULL DEFAULT 0,
    requests_made    INTEGER NOT NULL DEFAULT 0,
    waf_name         TEXT,
    coverage_summary TEXT,
    seq              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_jobs_seq   ON jobs(seq DESC);
"""


class SqliteJobStore:
    """Write-through SQLite mirror of the JobManager's job registry.

    The store is intentionally tolerant of missing optional fields so
    that future schema additions do not break reload of older rows --
    unknown columns are simply ignored by ``_row_to_dict``.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        # check_same_thread=False: the HTTP handler and worker threads
        # both call save() concurrently.  We serialise access with a
        # re-entrant lock to keep the connection object safe.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        # Decode JSON columns.
        for k in ("params", "data", "options", "findings",
                  "coverage_summary"):
            v = d.get(k)
            if k == "coverage_summary" and (v is None or v == ""):
                d[k] = None
                continue
            if isinstance(v, str) and v:
                try:
                    d[k] = json.loads(v)
                except (json.JSONDecodeError, TypeError):
                    d[k] = [] if k == "findings" else {}
            elif k == "findings" and v is None:
                d[k] = []
            elif k in ("params", "data", "options") and v is None:
                d[k] = {}
        return d

    # ------------------------------------------------------------------
    # Public API (mirrors what JobManager needs)
    # ------------------------------------------------------------------
    def save(self, job_dict: dict[str, Any]) -> None:
        """Upsert a job row.

        ``job_dict`` must contain at least ``scan_id``.  Optional fields
        default to sane empties so callers can pass a partial dict.
        """
        scan_id = job_dict["scan_id"]
        params = json.dumps(job_dict.get("params") or {})
        data = json.dumps(job_dict.get("data") or {})
        options = json.dumps(job_dict.get("options") or {})
        findings = json.dumps(job_dict.get("findings") or [])
        cov = job_dict.get("coverage_summary")
        cov_json = json.dumps(cov) if cov is not None else None
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO jobs
                   (scan_id, target_url, method, params, data, options,
                    state, created_at, started_at, finished_at, error,
                    findings, finding_count, high_severity_count,
                    requests_made, waf_name, coverage_summary, seq)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id,
                 job_dict.get("target_url", ""),
                 job_dict.get("method", "GET"),
                 params, data, options,
                 job_dict.get("state", "pending"),
                 job_dict.get("created_at", ""),
                 job_dict.get("started_at", ""),
                 job_dict.get("finished_at", ""),
                 job_dict.get("error"),
                 findings,
                 int(job_dict.get("finding_count", 0)),
                 int(job_dict.get("high_severity_count", 0)),
                 int(job_dict.get("requests_made", 0)),
                 job_dict.get("waf_name"),
                 cov_json,
                 int(job_dict.get("_seq", 0))),
            )

    def load(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM jobs WHERE scan_id = ?", (scan_id,))
            row = cur.fetchone()
        return self._row_to_dict(row) if row else None

    def load_all(self, state: str | None = None,
                 limit: int = 50) -> list[dict[str, Any]]:
        """Return jobs newest-first (by seq desc), optionally filtered."""
        if state:
            sql = ("SELECT * FROM jobs WHERE state = ? "
                   "ORDER BY seq DESC LIMIT ?")
            params: tuple = (state, limit)
        else:
            sql = "SELECT * FROM jobs ORDER BY seq DESC LIMIT ?"
            params = (limit,)
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM jobs WHERE scan_id = ?", (scan_id,))
            return cur.rowcount > 0

    def count(self, state: str | None = None) -> int:
        if state:
            sql = "SELECT COUNT(*) FROM jobs WHERE state = ?"
            params: tuple = (state,)
        else:
            sql = "SELECT COUNT(*) FROM jobs"
            params = ()
        with self._lock:
            cur = self._conn.execute(sql, params)
            return int(cur.fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Helpers to convert between Job dataclass and the dict the store expects
# ---------------------------------------------------------------------------
def job_to_store_dict(job) -> dict[str, Any]:
    """Serialise a Job dataclass instance into the dict shape SqliteJobStore.save expects."""
    return {
        "scan_id": job.scan_id,
        "target_url": job.target_url,
        "method": job.method,
        "params": job.params,
        "data": job.data,
        # Drop the _publish_fn / _fail_fn closures -- they are not
        # JSON-serialisable and are only meaningful for the current
        # process's worker.
        "options": {k: v for k, v in job.options.items()
                    if not k.startswith("_")},
        "state": job.state,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "findings": job.findings,
        "finding_count": job.finding_count,
        "high_severity_count": job.high_severity_count,
        "requests_made": job.requests_made,
        "waf_name": job.waf_name,
        "coverage_summary": job.coverage_summary,
        "_seq": job._seq,
    }


def store_dict_to_job(d: dict[str, Any]):
    """Reverse of :func:`job_to_store_dict` -- rebuild a Job dataclass.

    Used by :meth:`JobManager.load_from_store` on startup to hydrate the
    in-memory registry from SQLite.  The returned Job is terminal (its
    worker thread is None), so callers must not call ``start()`` on it.
    """
    from .jobs import Job
    return Job(
        scan_id=d["scan_id"],
        target_url=d.get("target_url", ""),
        method=d.get("method", "GET"),
        params=d.get("params") or {},
        data=d.get("data") or {},
        options=d.get("options") or {},
        state=d.get("state", "pending"),
        created_at=d.get("created_at", ""),
        started_at=d.get("started_at", ""),
        finished_at=d.get("finished_at", ""),
        error=d.get("error"),
        findings=d.get("findings") or [],
        finding_count=int(d.get("finding_count", 0)),
        high_severity_count=int(d.get("high_severity_count", 0)),
        requests_made=int(d.get("requests_made", 0)),
        waf_name=d.get("waf_name"),
        coverage_summary=d.get("coverage_summary"),
        _seq=int(d.get("seq", 0) or d.get("_seq", 0)),
    )
