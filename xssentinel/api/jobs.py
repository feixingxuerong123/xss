"""Thread-safe scan-job manager (Phase 27-4).

The :class:`JobManager` owns the lifecycle of every scan submitted to the
REST API.  Each scan runs in its own daemon thread (the scanner itself is
synchronous and blocking), while the manager exposes a thread-safe API
for querying status, fetching findings, and cancelling running scans.

State machine::

    pending -> running -> completed
                    |       |
                    |       `--> failed
                    `--> cancelled

The store is in-memory by design -- the REST service is intended for
single-process deployments.  Job history is bounded by ``max_jobs``;
oldest completed jobs are evicted first to keep memory predictable.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable


# ---------------------------------------------------------------------------
# State enum
# ---------------------------------------------------------------------------
class JobState:
    """String constants for job states (no enum.Enum to keep JSON-friendly)."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    TERMINAL = frozenset({COMPLETED, FAILED, CANCELLED})
    ACTIVE = frozenset({PENDING, RUNNING})


class JobNotFoundError(KeyError):
    """Raised when a scan_id is not present in the manager."""


@dataclass
class Job:
    """A single scan job."""

    scan_id: str
    target_url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)  # scanner options snapshot
    state: str = JobState.PENDING
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str | None = None
    findings: list[dict] = field(default_factory=list)
    finding_count: int = 0
    high_severity_count: int = 0
    requests_made: int = 0
    waf_name: str | None = None
    coverage_summary: dict | None = None
    # Internal: monotonic creation timestamp (seconds) -- kept for
    # backwards compatibility but no longer used as the primary sort
    # key (see ``_seq`` on JobManager, which is immune to clock
    # resolution issues that caused flaky ordering on Windows).
    _created_at_mono: float = field(default_factory=time.monotonic, repr=False)
    # Internal: creation sequence number assigned by the JobManager.
    # This is the authoritative sort key -- it strictly increases with
    # each create() call, regardless of clock resolution or system load.
    _seq: int = field(default=0, repr=False)
    # Internal: handle to the worker thread, so cancellation can join it.
    _thread: threading.Thread | None = field(default=None, repr=False)
    # Internal: cooperative cancel flag -- wired into Scanner.cancel_requested
    # by the scan worker (Phase 129): every real request checks it and the
    # scan aborts gracefully once it is set.
    _cancel_requested: threading.Event = field(default_factory=threading.Event, repr=False)
    # Phase 147 (G-05): stashed worker callable for PENDING jobs (the
    # reaper loop starts it when the concurrency gate frees up) and the
    # monotonic start timestamp used by the job-timeout reaper.
    _worker: Callable[[Job], None] | None = field(default=None, repr=False)
    _started_mono: float | None = field(default=None, repr=False)

    def to_summary(self) -> dict:
        """Return a JSON-serializable summary (no findings list)."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "method": self.method,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "finding_count": self.finding_count,
            "high_severity_count": self.high_severity_count,
            "requests_made": self.requests_made,
            "waf_name": self.waf_name,
        }

    def to_detail(self) -> dict:
        """Return summary + coverage + options (still no findings list)."""
        d = self.to_summary()
        d["params"] = self.params
        d["data"] = self.data
        # Phase 85: strip private keys -- runtime closures (_publish_fn /
        # _fail_fn) are not serialisable and leak memory addresses through
        # json.dumps(default=str).
        d["options"] = {k: v for k, v in self.options.items()
                        if not k.startswith("_")}
        d["coverage_summary"] = self.coverage_summary
        return d


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
class JobManager:
    """Thread-safe registry of scan jobs.

    The manager is the single source of truth for job state.  All mutations
    go through a ``threading.Lock`` so the HTTP handler thread and the
    worker thread cannot race on ``findings``/``state`` transitions.
    """

    def __init__(self, max_jobs: int = 200, store=None,
                 max_concurrent: int = 4, job_timeout_s: int = 1800) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs
        self._seq_counter: int = 0
        # Optional durable store (Phase 28-1).  When set, every state
        # transition is mirrored to SQLite so history survives restarts.
        self._store = store
        if store is not None:
            self._load_from_store_locked()
        # Phase 147 (G-05): global concurrency gate + per-job timeout.
        # The gate bounds how many scan jobs may execute simultaneously
        # (service-mode resource risk); excess jobs stay PENDING in the
        # registry and are picked up by the reaper loop below.
        self._max_concurrent = max(1, int(max_concurrent))
        self._gate = threading.Semaphore(self._max_concurrent)
        self._job_timeout_s = max(3, int(job_timeout_s))
        self._reaper_stop = threading.Event()
        self._reaper = threading.Thread(target=self._reaper_loop,
                                        name="xssentinel-job-reaper",
                                        daemon=True)
        self._reaper.start()

    def _reaper_loop(self) -> None:
        """Phase 147 (G-05): pending job dispatcher + job timeout reaper.

        Every 2s: 1) acquire the gate for PENDING jobs (FIFO) and start
        them; 2) mark RUNNING jobs that exceeded ``_job_timeout_s`` as
        FAILED with a timeout error, releasing their gate slot.
        """
        while not self._reaper_stop.wait(2.0):
            try:
                with self._lock:
                    pending = [j for j in self._jobs.values()
                               if j.state == JobState.PENDING]
                    pending.sort(key=lambda j: j._seq)
                    for job in pending:
                        if self._gate.acquire(blocking=False):
                            job.state = JobState.RUNNING
                            job.started_at = datetime.now().isoformat(
                                timespec="seconds")
                            self._persist_locked(job)
                            t = threading.Thread(
                                target=self._run_worker,
                                args=(job, self._worker_for(job)),
                                name=f"xssentinel-scan-{job.scan_id}",
                                daemon=True)
                            job._thread = t
                            t.start()
                    now_mono = time.monotonic()
                    for job in self._jobs.values():
                        if job.state != JobState.RUNNING or job._thread is None:
                            continue
                        started = getattr(job, "_started_mono", None)
                        if started is None:
                            continue
                        if now_mono - started > self._job_timeout_s:
                            # Phase 147 (G-05): mark failed AND fire the
                            # cooperative cancel flag so a well-behaved
                            # worker stops issuing requests; the terminal
                            # guard below keeps the FAILED state even if
                            # the worker thread finishes later.
                            job._cancel_requested.set()
                            job.state = JobState.FAILED
                            job.finished_at = datetime.now().isoformat(
                                timespec="seconds")
                            job.error = (f"job timeout after "
                                         f"{self._job_timeout_s}s")
                            self._persist_locked(job)
                            self._gate.release()
            except Exception:  # noqa: BLE001 - reaper never dies
                continue

    def _worker_for(self, job: Job):
        """Return the worker callable stashed on the PENDING job (Phase 147)."""
        return job._worker

    # -- create -----------------------------------------------------------
    def create(
        self,
        target_url: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        options: dict | None = None,
    ) -> Job:
        """Create a new job in PENDING state and return it.

        The caller is expected to call :meth:`start` to launch the worker
        thread.  Splitting create/start lets the HTTP handler return the
        job_id immediately even if the worker pool is saturated.
        """
        scan_id = self._new_id()
        with self._lock:
            self._seq_counter += 1
            seq = self._seq_counter
        job = Job(
            scan_id=scan_id,
            target_url=target_url,
            method=method,
            params=params or {},
            data=data or {},
            options=options or {},
            created_at=datetime.now().isoformat(timespec="seconds"),
            _seq=seq,
        )
        with self._lock:
            self._jobs[scan_id] = job
            self._evict_if_needed_locked()
            self._persist_locked(job)
        return job

    # -- persistence helpers (Phase 28-1) --------------------------------
    def _persist_locked(self, job: Job) -> None:
        """Mirror a job to the durable store (if configured).

        Caller must hold ``self._lock``.  Failures are swallowed --
        persistence is best-effort and must not break the scan pipeline.
        """
        if self._store is None:
            return
        try:
            from .persistence import job_to_store_dict
            self._store.save(job_to_store_dict(job))
        except Exception:
            pass

    def _load_from_store_locked(self) -> None:
        """Hydrate the in-memory registry from the durable store.

        Called once from ``__init__`` when a store is configured.  Only
        terminal jobs are reloaded -- any job that was RUNNING when the
        previous process died is marked FAILED (its worker is gone).
        """
        if self._store is None:
            return
        try:
            from .persistence import store_dict_to_job
            rows = self._store.load_all(limit=self._max_jobs)
            max_seq = 0
            for d in rows:
                state = d.get("state", "pending")
                if state in JobState.ACTIVE:
                    # The previous process died mid-scan.  Mark FAILED
                    # so the client knows to retry, rather than leaving
                    # the job stuck in RUNNING forever.
                    d["state"] = JobState.FAILED
                    d["error"] = ("scan interrupted by process restart "
                                  "(durable recovery)")
                    d["finished_at"] = datetime.now().isoformat(
                        timespec="seconds")
                job = store_dict_to_job(d)
                self._jobs[job.scan_id] = job
                if job._seq > max_seq:
                    max_seq = job._seq
            self._seq_counter = max_seq
        except Exception:
            pass

    def _new_id(self) -> str:
        # 16 hex chars = 64 bits of entropy -- ample for a single tenant.
        return "scan_" + secrets.token_hex(8)

    def _evict_if_needed_locked(self) -> None:
        """Evict oldest terminal jobs when over the cap.

        Caller must hold ``self._lock``.  Active jobs are never evicted.
        """
        if len(self._jobs) <= self._max_jobs:
            return
        # Collect terminal jobs sorted by creation sequence number
        # (oldest first).  Using the sequence counter avoids ambiguity
        # when multiple jobs share the same second-precision ISO string
        # and is immune to clock resolution issues on Windows.
        terminal = [
            (j._seq, sid)
            for sid, j in self._jobs.items()
            if j.state in JobState.TERMINAL
        ]
        terminal.sort()
        # Evict however many we need to get back under the cap.
        evict = len(self._jobs) - self._max_jobs
        for _, sid in terminal[:evict]:
            self._jobs.pop(sid, None)

    # -- start ------------------------------------------------------------
    def start(self, scan_id: str, worker: Callable[[Job], None]) -> None:
        """Launch the worker thread for a job.

        ``worker`` is called with the Job instance.  The worker is
        responsible for transitioning the job to a terminal state via
        :meth:`mark_completed` / :meth:`mark_failed`.
        """
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            if job.state != JobState.PENDING:
                raise RuntimeError(
                    f"job {scan_id} is not pending (state={job.state})")
            # Phase 147 (G-05): jobs no longer start immediately.  The
            # worker is stashed on the job and the reaper loop starts it
            # once the global concurrency gate has a free slot, so the
            # service never runs more than ``max_concurrent`` scans.
            job._worker = worker
            job._started_mono = None
            self._persist_locked(job)

    def _run_worker(self, job: Job, worker: Callable[[Job], None]) -> None:
        """Wrapper that ensures every job ends in a terminal state.

        The RUNNING transition is performed by the reaper before this
        thread starts (under the lock) so the state is observable
        immediately; this method only runs the worker body and catches
        any exception.
        """
        import time as _time
        job._started_mono = _time.monotonic()
        try:
            worker(job)
        except Exception as e:
            # Only transition to FAILED if the job is still active.
            # If the worker already marked itself COMPLETED/CANCELLED,
            # preserve that state.
            with self._lock:
                if job.state in JobState.ACTIVE:
                    job.state = JobState.FAILED
                    job.error = f"{type(e).__name__}: {e}"
                    job.finished_at = datetime.now().isoformat(timespec="seconds")
                    self._persist_locked(job)
        finally:
            # Phase 147 (G-05): terminal guard -- if the reaper timed this
            # job out while the worker was still running, the worker's
            # late ``mark_completed`` must NOT overwrite FAILED.
            with self._lock:
                if (job.state == JobState.COMPLETED
                        and job._cancel_requested.is_set()
                        and job.error and "timeout" in job.error):
                    job.state = JobState.FAILED
                    job.finished_at = datetime.now().isoformat(
                        timespec="seconds")
                    self._persist_locked(job)
            # Phase 147 (G-05): always release the concurrency gate slot
            # and clear the thread ref so the Job can be GC'd.
            try:
                self._gate.release()
            except ValueError:
                pass
            job._thread = None

    # -- state transitions ------------------------------------------------
    def mark_running(self, scan_id: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            if job.state != JobState.PENDING:
                return  # idempotent -- already started
            job.state = JobState.RUNNING
            job.started_at = datetime.now().isoformat(timespec="seconds")
            self._persist_locked(job)

    def mark_completed(
        self, scan_id: str, *, findings: list[dict],
        requests_made: int = 0, waf_name: str | None = None,
        coverage_summary: dict | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            job.findings = list(findings)
            job.finding_count = len(job.findings)
            job.high_severity_count = sum(
                1 for f in job.findings
                if (f.get("severity") or "").lower() in ("high", "critical")
            )
            job.requests_made = requests_made
            job.waf_name = waf_name
            job.coverage_summary = coverage_summary
            job.state = JobState.CANCELLED if job._cancel_requested.is_set() \
                else JobState.COMPLETED
            job.finished_at = datetime.now().isoformat(timespec="seconds")
            self._persist_locked(job)

    def mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            job.state = JobState.FAILED
            job.error = error
            job.finished_at = datetime.now().isoformat(timespec="seconds")
            self._persist_locked(job)

    def request_cancel(self, scan_id: str) -> bool:
        """Cooperatively request cancellation of a running scan.

        Returns True if the cancel flag was set, False if the job is
        already terminal (and thus cannot be cancelled).

        Phase 129: the scan worker wires ``job._cancel_requested`` into
        ``Scanner.cancel_requested``, so every real request checks the
        flag (Scanner._bump) and aborts the scan BudgetExhausted-style
        when it is set.  The job is reported CANCELLED with the findings
        gathered up to that point.
        """
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            if job.state in JobState.TERMINAL:
                return False
            job._cancel_requested.set()
            return True

    def is_cancel_requested(self, scan_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            return job._cancel_requested.is_set()

    # -- query ------------------------------------------------------------
    def get(self, scan_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise JobNotFoundError(scan_id)
            return job

    def list_jobs(
        self, state: str | None = None, limit: int = 50,
    ) -> list[Job]:
        """Return jobs newest-first, optionally filtered by state."""
        with self._lock:
            jobs = list(self._jobs.values())
        if state:
            jobs = [j for j in jobs if j.state == state]
        # Newest first by creation sequence number (strictly increasing,
        # immune to clock resolution issues that caused flaky ordering
        # on Windows when using time.monotonic under load).
        jobs.sort(key=lambda j: j._seq, reverse=True)
        return jobs[:limit]

    def delete(self, scan_id: str) -> bool:
        """Remove a terminal job from the registry.

        Returns True if removed, False if the job was active (cannot
        delete a running scan -- cancel it first).
        """
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return False
            if job.state in JobState.ACTIVE:
                return False
            self._jobs.pop(scan_id, None)
            if self._store is not None:
                try:
                    self._store.delete(scan_id)
                except Exception:
                    pass
            return True
