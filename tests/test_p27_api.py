"""Unit tests for the REST API service (Phase 27-4).

Covers:

  * :class:`xssentinel.api.jobs.JobManager` -- lifecycle, threading,
    cancellation, eviction, listing.
  * :class:`xssentinel.api.server.StdlibServer` -- HTTP routing, JSON
    request/response, API key authentication, CORS, error handling.
  * End-to-end scan via the API against the local vuln test server.

The HTTP tests use Python's stdlib ``urllib`` so they need no extra
dependencies.  Each test starts a fresh :class:`StdlibServer` on an
ephemeral port and tears it down in ``teardown``.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from io import BytesIO

import pytest

# Make the project importable when run directly from the tests/ dir.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from xssentinel.api.jobs import Job, JobManager, JobNotFoundError, JobState
from xssentinel.api.server import (
    StdlibServer, Response, _match_route, _version_info,
    _handle_health, _handle_info, _scan_worker,
)


# ---------------------------------------------------------------------------
# JobManager unit tests
# ---------------------------------------------------------------------------
class TestJobManagerCreate:
    def test_create_returns_pending_job_with_id(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        assert job.scan_id.startswith("scan_")
        assert job.state == JobState.PENDING
        assert job.target_url == "http://example.com"
        assert job.method == "GET"
        assert job.created_at != ""

    def test_create_with_params_and_options(self):
        mgr = JobManager()
        job = mgr.create(
            "http://example.com/search", method="POST",
            params={"q": "x"}, data={"name": "y"},
            options={"timeout": 30, "headless": True},
        )
        assert job.method == "POST"
        assert job.params == {"q": "x"}
        assert job.data == {"name": "y"}
        assert job.options["timeout"] == 30
        assert job.options["headless"] is True

    def test_get_returns_same_job(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        fetched = mgr.get(job.scan_id)
        assert fetched is job

    def test_get_raises_on_unknown_id(self):
        mgr = JobManager()
        with pytest.raises(JobNotFoundError):
            mgr.get("scan_does_not_exist")


class TestJobManagerStart:
    def test_start_runs_worker_and_marks_running(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        ran = threading.Event()

        def worker(j):
            ran.wait(timeout=2)
            mgr.mark_completed(j.scan_id, findings=[{"severity": "high"}])

        mgr.start(job.scan_id, worker)
        # Phase 147 (G-05) queued semantics: the job starts PENDING and
        # the reaper moves it to RUNNING once the gate frees a slot.
        assert job.state in (JobState.PENDING, JobState.RUNNING)
        ran.set()
        # Wait for completion.
        for _ in range(40):
            if job.state in JobState.TERMINAL:
                break
            time.sleep(0.05)
        assert job.state == JobState.COMPLETED
        assert job.finding_count == 1
        assert job.high_severity_count == 1

    def test_start_marks_failed_on_exception(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")

        def worker(j):
            raise ValueError("scan blew up")

        mgr.start(job.scan_id, worker)
        for _ in range(40):
            if job.state in JobState.TERMINAL:
                break
            time.sleep(0.05)
        assert job.state == JobState.FAILED
        assert "ValueError" in (job.error or "")
        assert "scan blew up" in (job.error or "")

    def test_start_rejects_non_pending_job(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        mgr.mark_running(job.scan_id)
        with pytest.raises(RuntimeError, match="not pending"):
            mgr.start(job.scan_id, lambda j: None)


class TestJobManagerCancel:
    def test_request_cancel_sets_flag(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        ok = mgr.request_cancel(job.scan_id)
        assert ok is True
        assert job._cancel_requested.is_set()

    def test_request_cancel_returns_false_for_terminal(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        mgr.mark_completed(job.scan_id, findings=[])
        ok = mgr.request_cancel(job.scan_id)
        assert ok is False

    def test_cancelled_job_marked_cancelled_on_completion(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        done = threading.Event()

        def worker(j):
            # Wait for cancel to be requested.
            for _ in range(40):
                if j._cancel_requested.is_set():
                    break
                time.sleep(0.02)
            mgr.mark_completed(j.scan_id, findings=[])
            done.set()

        mgr.start(job.scan_id, worker)
        mgr.request_cancel(job.scan_id)
        done.wait(timeout=3)
        assert job.state == JobState.CANCELLED


class TestJobManagerListAndDelete:
    def test_list_returns_newest_first(self):
        mgr = JobManager()
        j1 = mgr.create("http://a.com")
        time.sleep(0.01)
        j2 = mgr.create("http://b.com")
        jobs = mgr.list_jobs()
        assert jobs[0].scan_id == j2.scan_id
        assert jobs[1].scan_id == j1.scan_id

    def test_list_filters_by_state(self):
        mgr = JobManager()
        j1 = mgr.create("http://a.com")
        j2 = mgr.create("http://b.com")
        mgr.mark_completed(j1.scan_id, findings=[])
        running = mgr.list_jobs(state=JobState.PENDING)
        assert len(running) == 1
        assert running[0].scan_id == j2.scan_id

    def test_list_respects_limit(self):
        mgr = JobManager()
        for i in range(10):
            mgr.create(f"http://example.com/{i}")
        assert len(mgr.list_jobs(limit=5)) == 5

    def test_delete_terminal_job_succeeds(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        mgr.mark_completed(job.scan_id, findings=[])
        assert mgr.delete(job.scan_id) is True
        with pytest.raises(JobNotFoundError):
            mgr.get(job.scan_id)

    def test_delete_running_job_returns_false(self):
        mgr = JobManager()
        job = mgr.create("http://example.com")
        mgr.mark_running(job.scan_id)
        assert mgr.delete(job.scan_id) is False
        # Job still exists.
        assert mgr.get(job.scan_id) is job

    def test_delete_unknown_returns_false(self):
        mgr = JobManager()
        assert mgr.delete("scan_unknown") is False


class TestJobManagerEviction:
    def test_evicts_oldest_terminal_when_over_cap(self):
        mgr = JobManager(max_jobs=3)
        j1 = mgr.create("http://a.com")
        j2 = mgr.create("http://b.com")
        j3 = mgr.create("http://c.com")
        # Complete j1 so it's evictable.
        mgr.mark_completed(j1.scan_id, findings=[])
        # Adding j4 should evict j1 (oldest terminal).
        j4 = mgr.create("http://d.com")
        with pytest.raises(JobNotFoundError):
            mgr.get(j1.scan_id)
        # Active jobs are never evicted.
        assert mgr.get(j2.scan_id) is j2
        assert mgr.get(j3.scan_id) is j3
        assert mgr.get(j4.scan_id) is j4


class TestJobSerialization:
    def test_to_summary_excludes_findings(self):
        job = Job(scan_id="scan_x", target_url="http://t.com",
                  method="GET", state=JobState.COMPLETED)
        job.findings = [{"severity": "high"}]
        job.finding_count = 1
        summary = job.to_summary()
        assert "findings" not in summary
        assert summary["scan_id"] == "scan_x"
        assert summary["finding_count"] == 1

    def test_to_detail_includes_options_and_coverage(self):
        job = Job(scan_id="scan_x", target_url="http://t.com",
                  options={"timeout": 30})
        job.coverage_summary = {"layers_run": 5}
        detail = job.to_detail()
        assert detail["options"]["timeout"] == 30
        assert detail["coverage_summary"]["layers_run"] == 5


# ---------------------------------------------------------------------------
# Route table tests
# ---------------------------------------------------------------------------
class TestRouteTable:
    def test_health_route_matches(self):
        handler, m = _match_route("GET", "/api/v1/health")
        assert handler is _handle_health

    def test_health_route_matches_trailing_slash(self):
        handler, m = _match_route("GET", "/api/v1/health/")
        assert handler is _handle_health

    def test_info_route_matches(self):
        handler, m = _match_route("GET", "/api/v1/info")
        assert handler is _handle_info

    def test_create_scan_route_matches(self):
        handler, m = _match_route("POST", "/api/v1/scans")
        assert handler is not None

    def test_get_scan_route_extracts_id(self):
        handler, m = _match_route("GET", "/api/v1/scans/scan_abc123")
        assert m is not None
        assert m.group("id") == "scan_abc123"

    def test_get_findings_route_extracts_id(self):
        handler, m = _match_route("GET", "/api/v1/scans/scan_abc/findings")
        assert m is not None
        assert m.group("id") == "scan_abc"

    def test_delete_scan_route_matches(self):
        handler, m = _match_route("DELETE", "/api/v1/scans/scan_abc")
        assert handler is not None

    def test_cancel_route_matches(self):
        handler, m = _match_route("POST", "/api/v1/scans/scan_abc/cancel")
        assert handler is not None

    def test_verify_fix_route_matches(self):
        handler, m = _match_route("POST", "/api/v1/verify-fix")
        assert handler is not None

    def test_diff_route_matches(self):
        handler, m = _match_route("POST", "/api/v1/diff")
        assert handler is not None

    def test_unknown_route_returns_none(self):
        handler, m = _match_route("GET", "/api/v1/nonexistent")
        assert handler is None

    def test_wrong_method_returns_none(self):
        handler, m = _match_route("DELETE", "/api/v1/health")
        assert handler is None


# ---------------------------------------------------------------------------
# Response builder tests
# ---------------------------------------------------------------------------
class TestResponse:
    def test_json_response(self):
        r = Response.json(200, {"ok": True})
        assert r.status == 200
        assert r.content_type == "application/json"
        assert json.loads(r.body.decode()) == {"ok": True}

    def test_error_response(self):
        r = Response.error(404, "not_found", "no such scan")
        assert r.status == 404
        body = json.loads(r.body.decode())
        assert body["error"] == "not_found"
        assert body["detail"] == "no such scan"

    def test_text_response(self):
        r = Response.text(200, "<html></html>", content_type="text/html")
        assert r.status == 200
        assert r.content_type == "text/html"
        assert r.body == b"<html></html>"

    def test_bytes_response(self):
        r = Response(200, b"raw bytes", content_type="text/plain")
        assert r.body == b"raw bytes"


# ---------------------------------------------------------------------------
# Version info
# ---------------------------------------------------------------------------
class TestVersionInfo:
    def test_returns_dict_with_required_fields(self):
        info = _version_info()
        assert info["name"] == "XSSentinel"
        assert "version" in info
        assert isinstance(info["detection_layers"], list)
        assert len(info["detection_layers"]) > 0
        assert info["api_version"] == "v1"
        assert isinstance(info["endpoints"], list)


# ---------------------------------------------------------------------------
# HTTP server end-to-end tests
# ---------------------------------------------------------------------------
class _HttpClient:
    """Tiny HTTP client using urllib (no requests dependency)."""

    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _build_request(self, method: str, path: str, body=None,
                       extra_headers=None):
        url = self.base_url + path
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if extra_headers:
            headers.update(extra_headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers)
        return req

    def request(self, method: str, path: str, body=None, extra_headers=None):
        req = self._build_request(method, path, body, extra_headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)


@pytest.fixture
def api_server():
    """Start a StdlibServer on an ephemeral port for the test.

    Phase 29-1: CORS allowlist defaults to empty (deny-all).  The
    TestCorsAndOptions tests use the ``api_server_with_cors`` fixture
    instead, which pre-configures an allowlist.
    """
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    yield server
    server.shutdown()


@pytest.fixture
def api_server_with_cors():
    """StdlibServer with a CORS allowlist containing one test origin."""
    server = StdlibServer(
        host="127.0.0.1", port=0,
        cors_origins=["https://app.example.com"],
    )
    server.start_in_thread()
    yield server
    server.shutdown()


@pytest.fixture
def api_server_with_key():
    """StdlibServer with API key authentication enabled."""
    server = StdlibServer(host="127.0.0.1", port=0, api_key="secret123")
    server.start_in_thread()
    yield server
    server.shutdown()


class TestHealthEndpoint:
    def test_returns_ok_status(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/health")
        assert status == 200
        data = json.loads(body)
        assert data["status"] == "ok"
        assert "time" in data


class TestInfoEndpoint:
    def test_returns_version_and_layers(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/info")
        assert status == 200
        data = json.loads(body)
        assert data["name"] == "XSSentinel"
        assert "version" in data
        assert isinstance(data["detection_layers"], list)
        assert len(data["detection_layers"]) > 10


class TestScansEndpoint:
    def test_create_scan_rejects_missing_url(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST", "/api/v1/scans",
                                          body={"method": "GET"})
        assert status == 400
        data = json.loads(body)
        assert data["error"] == "invalid_request"

    def test_create_scan_rejects_invalid_method(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST", "/api/v1/scans",
                                          body={"url": "http://x.com",
                                                "method": "DELETE"})
        assert status == 400

    def test_create_scan_rejects_non_object_body(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST", "/api/v1/scans",
                                          body=[1, 2, 3])
        assert status == 400

    def test_create_scan_rejects_invalid_json(self, api_server):
        # Send raw invalid JSON via the lower-level urllib.
        req = urllib.request.Request(
            api_server.base_url + "/api/v1/scans",
            data=b"{not valid json",
            method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                body = resp.read().decode()
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode()
        assert status == 400
        assert "invalid_json" in body

    def test_list_scans_empty(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/scans")
        assert status == 200
        data = json.loads(body)
        assert data["count"] == 0
        assert data["scans"] == []

    def test_list_scans_after_create(self, api_server):
        client = _HttpClient(api_server.base_url)
        # Create a scan (it will fail because the URL is unreachable, but
        # the job is still recorded).
        client.request("POST", "/api/v1/scans",
                       body={"url": "http://127.0.0.1:1/no-such-port"})
        # Give the worker a moment to record the failure.
        for _ in range(40):
            status, body, _ = client.request("GET", "/api/v1/scans")
            data = json.loads(body)
            if data["count"] > 0:
                break
            time.sleep(0.05)
        assert data["count"] >= 1
        assert "scan_id" in data["scans"][0]

    def test_get_unknown_scan_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/scans/scan_unknown")
        assert status == 404

    def test_delete_unknown_scan_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("DELETE",
                                          "/api/v1/scans/scan_unknown")
        assert status == 404

    def test_get_findings_unknown_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET",
                                          "/api/v1/scans/scan_unknown/findings")
        assert status == 404

    def test_get_report_unknown_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET",
                                          "/api/v1/scans/scan_unknown/report")
        assert status == 404

    def test_get_report_returns_409_for_running_scan(self, api_server):
        # Manually insert a running job to test the not-ready path.
        mgr = api_server.job_manager
        job = mgr.create("http://example.com")
        mgr.mark_running(job.scan_id)
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET",
                                          f"/api/v1/scans/{job.scan_id}/report")
        assert status == 409
        assert "not_ready" in body

    def test_cancel_unknown_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST",
                                          "/api/v1/scans/scan_unknown/cancel")
        assert status == 404


class TestApiKeyAuth:
    def test_no_key_required_when_not_configured(self, api_server):
        # api_server fixture has no api_key -- all requests should pass.
        client = _HttpClient(api_server.base_url)
        status, _, _ = client.request("GET", "/api/v1/scans")
        assert status == 200

    def test_missing_key_returns_401(self, api_server_with_key):
        # Use a client with NO api_key against a server that requires one.
        client = _HttpClient(api_server_with_key.base_url, api_key=None)
        status, body, _ = client.request("GET", "/api/v1/scans")
        assert status == 401
        assert "unauthorized" in body

    def test_wrong_key_returns_401(self, api_server_with_key):
        client = _HttpClient(api_server_with_key.base_url,
                             api_key="wrong-key")
        status, body, _ = client.request("GET", "/api/v1/scans")
        assert status == 401

    def test_correct_key_succeeds(self, api_server_with_key):
        client = _HttpClient(api_server_with_key.base_url,
                             api_key="secret123")
        status, body, _ = client.request("GET", "/api/v1/scans")
        assert status == 200

    def test_health_endpoint_does_not_require_key(self, api_server_with_key):
        # Health is always open (liveness probe for orchestrators).
        client = _HttpClient(api_server_with_key.base_url, api_key=None)
        status, body, _ = client.request("GET", "/api/v1/health")
        assert status == 200

    def test_info_endpoint_does_not_require_key(self, api_server_with_key):
        client = _HttpClient(api_server_with_key.base_url, api_key=None)
        status, body, _ = client.request("GET", "/api/v1/info")
        assert status == 200


class TestCorsAndOptions:
    def test_options_returns_204(self, api_server):
        req = urllib.request.Request(api_server.base_url + "/api/v1/scans",
                                     method="OPTIONS")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 204

    def test_no_cors_header_when_allowlist_empty(self, api_server):
        # Phase 29-1: when cors_origins is not configured, no
        # Access-Control-Allow-Origin header should be emitted, even if
        # the request carries an Origin header (deny-by-default).
        req = urllib.request.Request(api_server.base_url + "/api/v1/health",
                                     headers={"Origin": "https://evil.example.com"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.headers.get("Access-Control-Allow-Origin") is None

    def test_get_response_includes_cors_headers(self, api_server_with_cors):
        # Phase 29-1: when the request Origin matches the configured
        # allowlist, the server reflects it back as the
        # Access-Control-Allow-Origin value.
        req = urllib.request.Request(api_server_with_cors.base_url + "/api/v1/health",
                                     headers={"Origin": "https://app.example.com"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.headers.get("Access-Control-Allow-Origin") == \
                "https://app.example.com"
            assert "GET" in resp.headers.get("Access-Control-Allow-Methods", "")

    def test_cors_rejects_unallowlisted_origin(self, api_server_with_cors):
        # Phase 29-1: an Origin not in the allowlist must NOT be echoed
        # back, preventing arbitrary third-party pages from issuing
        # authenticated cross-origin requests.
        req = urllib.request.Request(api_server_with_cors.base_url + "/api/v1/health",
                                     headers={"Origin": "https://evil.example.com"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.headers.get("Access-Control-Allow-Origin") is None

    def test_response_includes_nosniff_header(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, headers = client.request("GET", "/api/v1/health")
        assert headers.get("X-Content-Type-Options") == "nosniff"


class TestUnknownRoute:
    def test_unknown_path_returns_404(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/nonexistent")
        assert status == 404
        assert "not_found" in body

    def test_unsupported_method_returns_401_or_501(self, api_server):
        # BaseHTTPRequestHandler returns 501 for methods without a do_*
        # handler.  This is acceptable HTTP behaviour -- the API documents
        # its supported verbs in /api/v1/info.
        client = _HttpClient(api_server.base_url)
        try:
            status, _, _ = client.request("PUT", "/api/v1/health")
        except urllib.error.HTTPError as e:
            status = e.code
        assert status in (401, 501)


# ---------------------------------------------------------------------------
# End-to-end scan via the API against the local vuln server
# ---------------------------------------------------------------------------
@pytest.fixture
def vuln_server():
    """Start the local vuln test server on a known port."""
    import subprocess
    server_path = os.path.join(ROOT, "tests", "vuln_server.py")
    proc = subprocess.Popen(
        [sys.executable, server_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for ready.
    import http.client
    ready = False
    for _ in range(20):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 8899, timeout=1)
            conn.request("GET", "/safe?q=ping")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.5)
    if not ready:
        proc.terminate()
        proc.wait(timeout=5)
        pytest.skip("vuln_server did not start")
    yield "http://127.0.0.1:8899"
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


class TestEndToEndScan:
    def test_scan_completes_and_returns_findings(self, api_server, vuln_server):
        """Submit a scan via the API and poll until it completes."""
        client = _HttpClient(api_server.base_url)
        # Use /echo?q=test -- known to be detected by L1 reflected.
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 5, "max_transforms": 3})
        assert status == 202
        data = json.loads(body)
        scan_id = data["scan_id"]
        assert data["state"] in ("pending", "running")

        # Poll for completion (max ~30s).
        final_state = None
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            if status != 200:
                break
            data = json.loads(body)
            final_state = data["state"]
            if final_state in JobState.TERMINAL:
                break
            time.sleep(0.2)

        assert final_state == JobState.COMPLETED
        assert data["finding_count"] > 0

    def test_get_findings_returns_list(self, api_server, vuln_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 5, "max_transforms": 3})
        scan_id = json.loads(body)["scan_id"]
        # Poll for completion.
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            data = json.loads(body)
            if data["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)

        # Fetch findings.
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{scan_id}/findings")
        assert status == 200
        data = json.loads(body)
        assert data["count"] > 0
        assert isinstance(data["findings"], list)
        # Each finding should have a severity field.
        assert "severity" in data["findings"][0]

    def test_get_report_html(self, api_server, vuln_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 5, "max_transforms": 3})
        scan_id = json.loads(body)["scan_id"]
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            if json.loads(body)["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)

        status, body, headers = client.request(
            "GET", f"/api/v1/scans/{scan_id}/report?format=html")
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")
        assert "<html" in body.lower() or "<!doctype" in body.lower()

    def test_get_report_json(self, api_server, vuln_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 5, "max_transforms": 3})
        scan_id = json.loads(body)["scan_id"]
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            if json.loads(body)["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)

        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{scan_id}/report?format=json")
        assert status == 200
        data = json.loads(body)
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_get_report_invalid_format(self, api_server, vuln_server):
        client = _HttpClient(api_server.base_url)
        # First create and complete a scan.
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 3, "max_transforms": 2})
        scan_id = json.loads(body)["scan_id"]
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            if json.loads(body)["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)

        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{scan_id}/report?format=xml")
        assert status == 400
        assert "invalid_format" in body

    def test_cancel_running_scan(self, api_server, vuln_server):
        """Submit a scan and immediately cancel it."""
        client = _HttpClient(api_server.base_url)
        # Use a slow target -- the crawl flag will keep it busy.
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "crawl": True, "crawl_depth": 3,
                  "max_payloads": 50, "max_transforms": 12})
        scan_id = json.loads(body)["scan_id"]

        # Request cancellation.
        status, body, _ = client.request(
            "POST", f"/api/v1/scans/{scan_id}/cancel")
        assert status == 202

        # The scan should eventually reach CANCELLED (or COMPLETED if it
        # finished before the cancel flag was checked).
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            data = json.loads(body)
            if data["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)
        assert data["state"] in (JobState.CANCELLED, JobState.COMPLETED)

    def test_delete_completed_scan(self, api_server, vuln_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": f"{vuln_server}/echo?q=test",
                  "max_payloads": 3, "max_transforms": 2})
        scan_id = json.loads(body)["scan_id"]
        for _ in range(150):
            status, body, _ = client.request("GET",
                                              f"/api/v1/scans/{scan_id}")
            if json.loads(body)["state"] in JobState.TERMINAL:
                break
            time.sleep(0.2)

        status, body, _ = client.request("DELETE",
                                          f"/api/v1/scans/{scan_id}")
        assert status == 200
        # Confirm it's gone.
        status, body, _ = client.request("GET",
                                          f"/api/v1/scans/{scan_id}")
        assert status == 404


class TestVerifyFixAndDiffEndpoints:
    def test_verify_fix_rejects_missing_findings(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST", "/api/v1/verify-fix",
                                          body={"options": {}})
        assert status == 400

    def test_diff_rejects_non_list_baseline(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("POST", "/api/v1/diff",
                                          body={"baseline": "not a list",
                                                "current": []})
        assert status == 400

    def test_diff_returns_summary(self, api_server):
        client = _HttpClient(api_server.base_url)
        # Two empty lists -> all-zero summary.
        status, body, _ = client.request(
            "POST", "/api/v1/diff",
            body={"baseline": [], "current": [], "target": "http://t.com"})
        assert status == 200
        data = json.loads(body)
        assert data["target"] == "http://t.com"
        assert "summary" in data
        assert data["summary"]["new"] == 0
        assert data["summary"]["fixed"] == 0


class TestSameOriginGuard:
    """Phase 70: state-changing API methods defend against DNS rebinding
    and cross-site POSTs even when no API key is configured."""

    def test_cross_origin_post_blocked(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/jobs",
            body={"url": "http://example.com"},
            extra_headers={"Origin": "https://evil.test"})
        assert status == 403
        assert "cross_origin_blocked" in body

    def test_rebound_host_post_blocked(self, api_server):
        # DNS rebinding: Host carries the attacker domain (raw socket --
        # urllib always rewrites Host to the connect address).
        import socket as _s
        host, port = "127.0.0.1", api_server.port
        req = (f"POST /api/v1/jobs HTTP/1.1\r\n"
               f"Host: evil.example.com\r\n"
               f"Content-Type: application/json\r\n"
               f"Content-Length: 24\r\nConnection: close\r\n\r\n"
               f'{{"url": "http://example.com"}}')
        s = _s.create_connection((host, port), timeout=10)
        try:
            s.sendall(req.encode())
            resp = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
            resp = resp.decode("utf-8", "replace")
        finally:
            s.close()
        assert "403" in resp.split("\r\n")[0]
        assert "cross_origin_blocked" in resp

    def test_rebound_host_get_blocked(self, api_server):
        # Phase 71: a rebound GET reads scan data same-origin -- Host must
        # be validated on EVERY method, not just state-changing ones.
        import socket as _s
        host, port = "127.0.0.1", api_server.port
        s = _s.create_connection((host, port), timeout=10)
        try:
            s.sendall(b"GET /api/v1/scans HTTP/1.1\r\n"
                      b"Host: evil.example.com\r\n"
                      b"Connection: close\r\n\r\n")
            resp = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
            resp = resp.decode("utf-8", "replace")
        finally:
            s.close()
        assert "403" in resp.split("\r\n")[0]
        assert "cross_origin_blocked" in resp

    def test_local_host_get_allowed(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request("GET", "/api/v1/scans")
        assert status == 200

    def test_local_origin_post_allowed(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/jobs",
            body={"url": "http://example.com"},
            extra_headers={"Origin": f"http://127.0.0.1:{api_server.port}"})
        assert status != 403

    def test_plain_client_post_unaffected(self, api_server):
        client = _HttpClient(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/jobs", body={"url": "http://example.com"})
        assert status != 403
