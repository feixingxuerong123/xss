"""Phase 176: the AI narrative over the REST API.

Two ways a scan gets an AI section, both exercised here against local mocks
only (no test in this file touches the network or a real provider):

  * at scan time -- ``POST /api/v1/scans {"ai_report": true}`` makes the job's
    own worker thread generate it, so no HTTP request ever waits on a model;
  * on demand -- ``GET /api/v1/scans/{id}/report?ai=1`` for a scan that did
    not ask, which blocks that one request instead.

Both mocks speak HTTP/1.0 on purpose: this host's loopback is intermittently
killed by local security software, and keep-alive pooling turns that into a
socket reused after its server was shut down (WinError 10054).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xssentinel.api.jobs import Job, JobState
from xssentinel.api.server import StdlibServer, _generate_job_ai_report, _parse_ai_models


# ---------------------------------------------------------------------------
# Local OpenAI-compatible mock
# ---------------------------------------------------------------------------

#: Long enough to clear report_ai.MIN_REPORT_CHARS -- a stub reply would be
#: rejected as truncated_response and the pool would fail over (or degrade).
REPLY = ("## 执行摘要\n"
         + "本次扫描发现反射型 XSS，q 参数未编码直接回显，建议立即修复。\n" * 8
         + "## 风险评级\n| 严重度 | 数量 |\n|---|---|\n| high | 1 |\n")


class _MockLLM:
    """Counts calls so tests can assert the pool was (or was not) used."""

    def __init__(self, reply: str | None = None, status: int = 200):
        self.reply = reply if reply is not None else REPLY
        self.status = status
        self.calls: list[dict] = []
        self._srv = None

    def start(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_POST(self):
                try:
                    self._respond()
                except (ConnectionResetError, BrokenPipeError,
                        ConnectionAbortedError):
                    pass

            def _respond(self):
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}")
                outer.calls.append(req)
                if outer.status == 200:
                    payload = {"choices": [{"message": {
                        "role": "assistant", "content": outer.reply}}]}
                else:
                    payload = {"error": {"message":
                                         "Model 'x' is at its concurrency limit (8)"}}
                data = json.dumps(payload, ensure_ascii=False).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self._srv.server_address[1]}/v1"


# ---------------------------------------------------------------------------
# Local reflector lab (for the one end-to-end scan)
# ---------------------------------------------------------------------------

class _Lab:
    def start(self):
        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                q = ""
                if "?" in self.path:
                    for pair in self.path.split("?", 1)[1].split("&"):
                        if pair.startswith("q="):
                            q = pair[2:]
                body = ("<!doctype html><html><body><h1>Search</h1>"
                        f"<p>You searched for: {q}</p></body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._srv.server_address[1]}/?q=test"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_pool(tmp_path, mock) -> str:
    """A pool config pointing at the local mock, written next to the test."""
    cfg = {
        "timeout": 10,
        "cooldown": {"rate_limit": 0.1, "backoff_factor": 1, "max": 1},
        "generation": {"max_tokens": 512},
        "providers": [{
            "id": "mock", "base_url": mock.base_url,
            "keys": ["k1-aaaaaaaa"], "models": ["m1"],
        }],
    }
    path = tmp_path / "pool.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return str(path)


@pytest.fixture
def mock_llm():
    m = _MockLLM().start()
    yield m
    m.stop()


class _Client:
    """Minimal urllib client (mirrors tests/test_p27_api.py)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "*/*"}
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)


@pytest.fixture
def api_server():
    """Plain server, no AI pool configured."""
    server = StdlibServer(host="127.0.0.1", port=0)
    server.start_in_thread()
    yield server
    server.shutdown()


@pytest.fixture
def api_server_ai(tmp_path, mock_llm):
    """Server whose pool points at the local mock."""
    server = StdlibServer(host="127.0.0.1", port=0,
                          ai_config=_write_pool(tmp_path, mock_llm))
    server.start_in_thread()
    yield server
    server.shutdown()


def _a_finding(sev="high", url="http://t.local/search?q=x"):
    return {"type": "reflected", "severity": sev, "url": url, "method": "GET",
            "param": "q", "context": "html_body",
            "payload": "<script>alert(1)</script>",
            "detail": "reflected unencoded"}


def _completed_job(server, findings=None, options=None):
    """Create a finished job directly (no scan) for report-endpoint tests.

    NOTE: ``_ai_config`` is mirrored here on purpose.  ``_handle_create_scan``
    is what injects it on the HTTP path, so a test that calls the manager
    directly would otherwise leave it unset -- and ``LLMPool.from_file(None)``
    falls back to the pool *shipped inside the package*, i.e. a real vendor
    with real credentials.  Every test in this file must resolve an explicit
    pool path; a unit test that reaches a live provider is not a unit test.
    """
    mgr = server.job_manager
    opts = dict(options or {})
    opts.setdefault("_ai_config", getattr(server, "ai_config", None))
    job = mgr.create("http://t.local/search?q=x", options=opts)
    mgr.mark_completed(job.scan_id, findings=findings or [_a_finding()],
                       requests_made=42, waf_name=None, coverage_summary=None)
    return mgr.get(job.scan_id)


# ---------------------------------------------------------------------------
# Request-level options
# ---------------------------------------------------------------------------

class TestScanOptionsParsing:
    def test_ai_report_is_off_by_default(self, api_server):
        client = _Client(api_server.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans", body={"url": "http://127.0.0.1:1/x"})
        assert status == 202
        job = api_server.job_manager.get(json.loads(body)["scan_id"])
        assert job.options["ai_report"] is False
        assert job._ai_report is None

    def test_ai_report_flag_is_parsed(self, api_server_ai):
        # Uses the mock-pool server so the scan-triggered generation cannot
        # reach a live provider.  (A scan of an unreachable URL does NOT
        # raise -- it just finds nothing -- so the worker would happily go on
        # to generate a section.)
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": "http://127.0.0.1:1/x", "ai_report": True,
                  "ai_lang": "en", "ai_model": "m1,m2"})
        assert status == 202
        job = api_server_ai.job_manager.get(json.loads(body)["scan_id"])
        assert job.options["ai_report"] is True
        assert job.options["ai_lang"] == "en"
        assert job.options["ai_models"] == ["m1", "m2"]

    def test_ai_config_is_server_side_only(self, api_server_ai):
        """A client must not be able to point the pool loader at a path."""
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "POST", "/api/v1/scans",
            body={"url": "http://127.0.0.1:1/x",
                  "ai_config": "/etc/passwd"})
        assert status == 202
        job = api_server_ai.job_manager.get(json.loads(body)["scan_id"])
        assert job.options["_ai_config"] != "/etc/passwd"
        assert job.options["_ai_config"] == api_server_ai.ai_config

    def test_parse_ai_models_accepts_both_shapes(self):
        assert _parse_ai_models("a,b") == ["a", "b"]
        assert _parse_ai_models(["a", "b"]) == ["a", "b"]
        assert _parse_ai_models(None) is None
        assert _parse_ai_models("") is None
        assert _parse_ai_models("  ") is None
        assert _parse_ai_models(42) is None


# ---------------------------------------------------------------------------
# _generate_job_ai_report
# ---------------------------------------------------------------------------

class TestGenerateJobAiReport:
    def test_writes_a_llm_section_and_caches_it(self, tmp_path, mock_llm):
        job = Job("s1", "http://t.local/")
        cfg = _write_pool(tmp_path, mock_llm)
        meta = {"generated": "2026-09-22 16:00", "requests": 1}

        first = _generate_job_ai_report(job, [_a_finding()], meta,
                                        {"_ai_config": cfg})
        assert first is not None and first["used_llm"] is True
        assert first["provider"] == "mock"
        assert "## 执行摘要" in first["markdown"]
        assert first["html"]
        assert len(mock_llm.calls) == 1

        # Second call is served from the cache: no new model call.
        second = _generate_job_ai_report(job, [_a_finding()], meta,
                                         {"_ai_config": cfg})
        assert second is first
        assert len(mock_llm.calls) == 1

    def test_degrades_to_template_when_pool_is_unavailable(self, tmp_path):
        job = Job("s2", "http://t.local/")
        out = _generate_job_ai_report(
            job, [_a_finding()], {"generated": "x"},
            {"_ai_config": str(tmp_path / "missing.json")})
        assert out is not None
        assert out["used_llm"] is False and out["degraded"] is True
        assert "LLMConfigError" in out["error"]
        assert "## 执行摘要" in out["markdown"]     # still a usable section

    def test_degrades_when_providers_only_rate_limit(self, tmp_path):
        m = _MockLLM(status=429).start()
        try:
            job = Job("s3", "http://t.local/")
            out = _generate_job_ai_report(
                job, [_a_finding()], {"generated": "x"},
                {"_ai_config": _write_pool(tmp_path, m)})
        finally:
            m.stop()
        assert out["degraded"] is True
        assert "rate_limit" in out["error"]

    def test_returns_none_on_internal_error_and_leaves_job_alone(self):
        """A broken caller must not produce a half-written cache entry."""
        job = Job("s4", "http://t.local/")
        out = _generate_job_ai_report(job, None, {}, {"_ai_config": None})
        assert out is None
        assert job._ai_report is None

    def test_language_option_is_honoured(self, tmp_path, mock_llm):
        job = Job("s5", "http://t.local/")
        cfg = _write_pool(tmp_path, mock_llm)
        _generate_job_ai_report(job, [_a_finding()], {"generated": "x"},
                                {"_ai_config": cfg, "ai_lang": "en"})
        # The prompt carries the English system instruction.
        sent = json.dumps(mock_llm.calls[0], ensure_ascii=False)
        assert "Executive Summary" in sent

    def test_format_directive_follows_the_findings(self, tmp_path, mock_llm):
        job = Job("s6", "http://t.local/")
        cfg = _write_pool(tmp_path, mock_llm)
        _generate_job_ai_report(job, [_a_finding(url="http://t.local/a?q=1")],
                                {"generated": "x"}, {"_ai_config": cfg})
        prompt = json.dumps(mock_llm.calls[0], ensure_ascii=False)
        assert "http://t.local/a?q=1" in prompt
        assert "禁止编造" in prompt

    def test_model_filter_is_passed_through(self, tmp_path, mock_llm):
        job = Job("s7", "http://t.local/")
        cfg = _write_pool(tmp_path, mock_llm)
        out = _generate_job_ai_report(
            job, [_a_finding()], {"generated": "x"},
            {"_ai_config": cfg, "ai_models": ["nonexistent-model"]})
        # No candidate matches the filter -> template, and no call was made.
        assert out["degraded"] is True
        assert mock_llm.calls == []


# ---------------------------------------------------------------------------
# Status flag
# ---------------------------------------------------------------------------

class TestSummaryFlag:
    def test_status_reports_whether_a_section_exists(self, api_server_ai):
        """A client polling for completion can tell whether the report it is
        about to fetch already carries a narrative -- without fetching it."""
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)

        status, body, _ = client.request("GET", f"/api/v1/scans/{job.scan_id}")
        assert status == 200
        assert json.loads(body)["has_ai_report"] is False

        _generate_job_ai_report(job, job.findings, {"generated": "x"},
                                {"_ai_config": api_server_ai.ai_config})

        status, body, _ = client.request("GET", f"/api/v1/scans/{job.scan_id}")
        assert status == 200
        assert json.loads(body)["has_ai_report"] is True

    def test_flag_is_false_for_a_plain_job(self):
        assert Job("s9", "http://t.local/").to_summary()["has_ai_report"] is False


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
class TestConcurrency:
    def test_concurrent_callers_bill_only_one_model_call(self, tmp_path,
                                                         mock_llm):
        """Two report requests landing at once must not both pay for the same
        section -- guaranteed by job._ai_lock plus the cache."""
        job = Job("c1", "http://t.local/")
        cfg = _write_pool(tmp_path, mock_llm)
        results: list = []
        errors: list = []

        def worker():
            try:
                results.append(_generate_job_ai_report(
                    job, [_a_finding()], {"generated": "x"},
                    {"_ai_config": cfg}))
            except Exception as e:      # pragma: no cover - failure path
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors
        assert len(results) == 4
        assert len(mock_llm.calls) == 1
        assert all(r is results[0] for r in results)


# ---------------------------------------------------------------------------
# Report endpoint
# ---------------------------------------------------------------------------

class TestReportEndpointAiSection:
    def test_cached_section_is_rendered_into_html(self, api_server_ai):
        job = _completed_job(api_server_ai)
        _generate_job_ai_report(job, job.findings, {"generated": "x"},
                                {"_ai_config": api_server_ai.ai_config})
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=html")
        assert status == 200
        assert 'class="ai-report"' in body
        assert "执行摘要" in body

    def test_no_section_when_not_requested(self, api_server_ai):
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=html")
        assert status == 200
        assert '<section class="ai-report' not in body
        assert api_server_ai.job_manager.get(job.scan_id)._ai_report is None

    def test_on_demand_generation_via_query_flag(self, api_server_ai,
                                                 mock_llm):
        """A scan that did not ask at scan time can still get a section."""
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=html&ai=1")
        assert status == 200
        assert '<section class="ai-report"' in body
        assert len(mock_llm.calls) == 1
        assert api_server_ai.job_manager.get(job.scan_id)._ai_report is not None

    def test_repeat_requests_reuse_the_cached_section(self, api_server_ai,
                                                      mock_llm):
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        for _ in range(3):
            status, _, _ = client.request(
                "GET", f"/api/v1/scans/{job.scan_id}/report?ai=1")
            assert status == 200
        assert len(mock_llm.calls) == 1

    def test_markdown_format_carries_the_section(self, api_server_ai):
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=markdown&ai=1")
        assert status == 200
        assert "## AI 分析" in body
        # The narrative must sit above the raw evidence table.
        assert body.index("## AI 分析") < body.index("## Summary Table")

    def test_json_format_carries_metadata_without_duplicate_html(
            self, api_server_ai):
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=json&ai=1")
        assert status == 200
        data = json.loads(body)
        assert data["ai_report"]["used_llm"] is True
        assert data["ai_report"]["provider"] == "mock"
        assert "html" not in data["ai_report"]

    def test_unavailable_pool_still_serves_a_degraded_section(
            self, api_server, tmp_path):
        """A pool that cannot be loaded must yield the template, not a 500 --
        and must not reach for a live provider either.  A report is never
        allowed to fail just because a model is absent."""
        job = _completed_job(
            api_server,
            options={"_ai_config": str(tmp_path / "absent.json")})
        client = _Client(api_server.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?format=html&ai=1")
        assert status == 200
        assert '<section class="ai-report degraded"' in body
        assert "确定性模板" in body

    def test_pool_discovery_prefers_env_then_the_shipped_pool(self, monkeypatch):
        """Documents the fallback behind ``ai_config=None``.

        Discovery is env -> package -> home, so an API server started without
        ``--ai-config`` still has a usable (real) provider list.  That matches
        the CLI, and it also means ``--ai-config`` is not what *enables* AI --
        the per-scan ``ai_report`` flag is; the path only redirects which pool
        is used.  Locked here so neither half can drift silently.
        """
        import os
        from xssentinel.core import llm_pool as lp

        monkeypatch.setenv(lp.ENV_CONFIG, "/tmp/explicit.json")
        assert lp._default_config_path() == "/tmp/explicit.json"

        monkeypatch.delenv(lp.ENV_CONFIG, raising=False)
        resolved = lp._default_config_path()
        assert resolved.endswith(os.path.join("data", "llm_providers.json"))
        assert os.path.isfile(resolved)

    def test_ai_flag_values_are_lenient(self, api_server_ai):
        job = _completed_job(api_server_ai)
        client = _Client(api_server_ai.base_url)
        for flag in ("1", "true", "yes", "on"):
            api_server_ai.job_manager.get(job.scan_id)._ai_report = None
            status, body, _ = client.request(
                "GET", f"/api/v1/scans/{job.scan_id}/report?ai={flag}")
            assert status == 200, flag
            assert '<section class="ai-report"' in body, flag
        # Anything else means "do not generate".
        api_server_ai.job_manager.get(job.scan_id)._ai_report = None
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?ai=0")
        assert '<section class="ai-report' not in body

    def test_not_ready_scan_is_still_rejected(self, api_server_ai):
        """The AI hook must not bypass the state gate."""
        mgr = api_server_ai.job_manager
        job = mgr.create("http://t.local/", options={"ai_report": True})
        client = _Client(api_server_ai.base_url)
        status, body, _ = client.request(
            "GET", f"/api/v1/scans/{job.scan_id}/report?ai=1")
        assert status == 409


# ---------------------------------------------------------------------------
# End-to-end: a real scan through the API with ai_report on
# ---------------------------------------------------------------------------

class TestScanTimeGeneration:
    def test_scan_generates_the_section_on_its_worker_thread(
            self, tmp_path, mock_llm):
        lab = _Lab().start()
        pool = _write_pool(tmp_path, mock_llm)
        server = StdlibServer(host="127.0.0.1", port=0, ai_config=pool)
        server.start_in_thread()
        try:
            client = _Client(server.base_url)
            status, body, _ = client.request(
                "POST", "/api/v1/scans",
                body={"url": lab.url, "ai_report": True,
                      "max_payloads": 6, "max_transforms": 6})
            assert status == 202
            scan_id = json.loads(body)["scan_id"]

            deadline = time.time() + 120
            job = None
            while time.time() < deadline:
                job = server.job_manager.get(scan_id)
                if job.state in JobState.TERMINAL:
                    break
                time.sleep(0.2)
            assert job is not None and job.state == JobState.COMPLETED

            # The section was generated as part of the scan, so the very first
            # report fetch already carries it -- no extra round trip, no wait.
            assert job._ai_report is not None
            assert job._ai_report["used_llm"] is True
            status, page, _ = client.request(
                "GET", f"/api/v1/scans/{scan_id}/report?format=html")
            assert status == 200
            assert '<section class="ai-report"' in page
        finally:
            server.shutdown()
            lab.stop()

    def test_plain_scan_makes_no_model_call(self, tmp_path, mock_llm):
        """Without ai_report the pool must never be contacted at scan time."""
        lab = _Lab().start()
        server = StdlibServer(host="127.0.0.1", port=0,
                              ai_config=_write_pool(tmp_path, mock_llm))
        server.start_in_thread()
        try:
            client = _Client(server.base_url)
            status, body, _ = client.request(
                "POST", "/api/v1/scans",
                body={"url": lab.url, "max_payloads": 6, "max_transforms": 6})
            assert status == 202
            scan_id = json.loads(body)["scan_id"]
            deadline = time.time() + 120
            while time.time() < deadline:
                job = server.job_manager.get(scan_id)
                if job.state in JobState.TERMINAL:
                    break
                time.sleep(0.2)
            assert job.state == JobState.COMPLETED
            assert job._ai_report is None
            assert mock_llm.calls == []
        finally:
            server.shutdown()
            lab.stop()
