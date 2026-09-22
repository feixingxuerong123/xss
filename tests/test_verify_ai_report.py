"""Phase 176: the AI narrative over a verify-fix (re-test) report.

The verify task is a separate brief from the scan task: the model is writing
about whether remediation WORKED, so the digest carries statuses and the
prompt forbids re-grading them.  These tests pin that down, plus the rendering
wiring in ``verify_fix`` and the fact that the section is absent -- byte for
byte -- when ``--ai-report`` was not passed.

Mock providers only; nothing here touches the network.  Tests that need a pool
pass an explicit path, because conftest points the pool env var at a missing
file to keep the suite offline.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xssentinel.core import report_ai as ra
from xssentinel.core import verify_fix as vf

REPLY = ("## 修复验证摘要\n"
         + "本次复测覆盖全部历史条目，仍有一条可被利用，修复不完整。\n" * 8
         + "## 修复状态总览\n| 状态 | 数量 |\n|---|---|\n| 仍可利用 | 1 |\n")


class _MockLLM:
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


@pytest.fixture
def mock_llm():
    m = _MockLLM().start()
    yield m
    m.stop()


def _write_pool(tmp_path, mock) -> str:
    cfg = {
        "timeout": 10,
        "cooldown": {"rate_limit": 0.1, "backoff_factor": 1, "max": 1},
        "generation": {"max_tokens": 512},
        "providers": [{"id": "mock", "base_url": mock.base_url,
                       "keys": ["k1-aaaaaaaa"], "models": ["m1"]}],
    }
    path = tmp_path / "pool.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return str(path)


def _result(ftype="reflected", status="still_vuln", sev="high",
            url="http://t/a?q=1", detail="detail"):
    return {"type": ftype, "severity": sev, "url": url, "method": "GET",
            "param": "q", "payload": "<script>alert(1)</script>",
            "verify": {"status": status, "detail": detail}}


MIXED = [
    _result("reflected", "still_vuln", "high", "http://t/a?q=1"),
    _result("dom", "fixed", "medium", "http://t/b"),
    _result("stored", "skipped", "critical", "http://t/c",
            detail="needs a display page"),
    _result("jsonp_xss", "error", "low", "http://t/d", detail="request failed"),
]


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------

class TestVerifyDigest:
    def test_counts_every_status(self):
        rows, stats = ra.summarize_verify(MIXED)
        assert stats["total"] == 4
        assert stats["counts"] == {"fixed": 1, "still_vuln": 1,
                                   "error": 1, "skipped": 1}
        assert stats["fixed"] == 1 and stats["still_vuln"] == 1

    def test_still_vulnerable_sorts_first(self):
        """The narrative must lead with what is still exploitable."""
        rows, _ = ra.summarize_verify(MIXED)
        assert [r["status"] for r in rows] == ["still_vuln", "error",
                                               "skipped", "fixed"]

    def test_rows_carry_status_and_the_engine_detail(self):
        rows, _ = ra.summarize_verify(MIXED)
        first = rows[0]
        assert first["status"] == "still_vuln"
        assert first["type"] == "reflected"
        assert first["url"] == "http://t/a?q=1"
        assert first["detail"] == "detail"

    def test_does_not_truncate_by_default(self):
        """A client deliverable must account for every re-tested item."""
        many = [_result(url=f"http://t/{i}") for i in range(40)]
        rows, stats = ra.summarize_verify(many)
        assert len(rows) == 40 and stats["omitted"] == 0

    def test_unknown_status_falls_back_to_error(self):
        rows, stats = ra.summarize_verify([{"type": "reflected",
                                            "url": "http://t/x"}])
        assert rows[0]["status"] == "error"
        assert stats["counts"]["error"] == 1

    def test_handles_empty_input(self):
        rows, stats = ra.summarize_verify([])
        assert rows == [] and stats["total"] == 0


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------

class TestVerifyTemplate:
    def test_has_every_section(self):
        md = ra.template_report(MIXED, "http://t", {"source_report": "old.json"},
                                lang="zh", task="verify")
        for section in ("## 修复验证摘要", "## 修复状态总览", "## 仍可利用项",
                        "## 无法判定项", "## 修复建议与后续步骤"):
            assert section in md

    def test_names_the_source_report(self):
        md = ra.template_report(MIXED, "http://t", {"source_report": "old.json"},
                                lang="zh", task="verify")
        assert "old.json" in md

    def test_reports_still_exploitable_first_with_a_fix_hint(self):
        md = ra.template_report(MIXED, "http://t", {}, lang="zh", task="verify")
        still = md.index("## 仍可利用项")
        assert "http://t/a?q=1" in md[still:]
        # A remediation hint from the advice corpus must be present.
        assert "修复：" in md[still:]

    def test_skipped_and_error_are_never_counted_as_fixed(self):
        """The one way a verification report lies to a client is folding
        'unknown' into 'fixed'."""
        md = ra.template_report(MIXED, "http://t", {}, lang="zh", task="verify")
        assert "仍有 1 条可被利用" in md
        assert "状态**未知**" in md
        assert "未复测" in md

    def test_all_fixed_verdict(self):
        fixed = [_result("dom", "fixed"), _result("reflected", "fixed")]
        md = ra.template_report(fixed, "http://t", {}, lang="zh", task="verify")
        assert "全部条目均已修复" in md
        assert "无。" in md                      # nothing still exploitable

    def test_nothing_fixed_verdict_points_at_deployment(self):
        all_vuln = [_result("reflected", "still_vuln")]
        md = ra.template_report(all_vuln, "http://t", {}, lang="zh", task="verify")
        assert "仍有 1 条可被利用" in md

    def test_degradation_reason_is_shown(self):
        md = ra.template_report(MIXED, "http://t", {}, reason="pool down",
                                lang="zh", task="verify")
        assert "确定性模板" in md and "pool down" in md

    def test_english_variant(self):
        md = ra.template_report(MIXED, "http://t", {}, lang="en", task="verify")
        assert "## Verification Summary" in md
        assert "## Still Exploitable (fix first)" in md

    def test_empty_results(self):
        md = ra.template_report([], "http://t", {}, lang="zh", task="verify")
        assert "## 修复验证摘要" in md
        # A client deliverable keeps its structure and says "none" per section,
        # rather than dropping headings the reader expects to find.
        assert "## 仍可利用项" in md
        assert md.count("无。") >= 2          # still-exploitable + undetermined

    def test_findings_task_is_unaffected(self):
        """The default task must still produce the scan-report structure."""
        md = ra.template_report(
            [{"type": "reflected", "severity": "high", "url": "http://t/a?q=1",
              "param": "q", "method": "GET", "payload": "x"}],
            "http://t", {})
        assert "## 执行摘要" in md
        assert "## 风险评级" in md


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

class TestVerifyPrompt:
    def test_verify_brief_forbids_regrading_and_inventing(self):
        rows, stats = ra.summarize_verify(MIXED)
        msgs = ra.build_prompt(rows, stats, "http://t", {}, "zh", task="verify")
        system = msgs[0]["content"]
        assert "禁止修改任何一条的复测状态" in system
        assert "禁止编造" in system
        assert "未知" in system

    def test_verify_payload_carries_statuses_not_findings(self):
        rows, stats = ra.summarize_verify(MIXED)
        msgs = ra.build_prompt(rows, stats, "http://t",
                               {"source_report": "old.json"}, "zh",
                               task="verify")
        sent = json.loads(msgs[1]["content"].split("```json")[1].split("```")[0])
        assert sent["verification_stats"]["still_vuln"] == 1
        assert sent["source_report"] == "old.json"
        assert sent["items"][0]["status"] == "still_vuln"
        assert "findings" not in sent

    def test_scan_brief_is_unchanged_by_default(self):
        rows, stats = ra.summarize_findings(
            [{"type": "reflected", "severity": "high", "url": "http://t/a?q=1",
              "payload": "x"}])
        msgs = ra.build_prompt(rows, stats, "http://t", {})
        assert "资深 Web 安全工程师" in msgs[0]["content"]
        assert "执行摘要" in msgs[1]["content"] or "执行摘要" in msgs[0]["content"] \
            or "扫描" in msgs[1]["content"]

    def test_english_verify_brief(self):
        rows, stats = ra.summarize_verify(MIXED)
        msgs = ra.build_prompt(rows, stats, "http://t", {}, "en", task="verify")
        assert "remediation verification report" in msgs[0]["content"]
        assert "NEVER alter a status" in msgs[0]["content"]


# ---------------------------------------------------------------------------
# build_ai_report(task="verify")
# ---------------------------------------------------------------------------

class TestBuildAiReportVerify:
    def test_success_uses_the_verify_brief(self, tmp_path, mock_llm):
        rep = ra.build_ai_report(MIXED, "http://t", {"source_report": "old.json"},
                                 task="verify",
                                 pool=None,
                                 config_path=_write_pool(tmp_path, mock_llm))
        assert rep.used_llm and rep.ok and not rep.degraded
        assert rep.finding_count == 4
        system = mock_llm.calls[0]["messages"][0]["content"]
        assert "复测状态" in system
        assert "修复验证摘要" in rep.markdown

    def test_degrades_to_the_verify_template(self, tmp_path):
        rep = ra.build_ai_report(MIXED, "http://t", {}, task="verify",
                                 config_path=str(tmp_path / "absent.json"))
        assert rep.degraded
        assert "LLMConfigError" in rep.error
        assert "## 修复验证摘要" in rep.markdown
        assert "## 执行摘要" not in rep.markdown     # not the scan template

    def test_rate_limited_pool_degrades(self, tmp_path):
        m = _MockLLM(status=429).start()
        try:
            rep = ra.build_ai_report(MIXED, "http://t", {}, task="verify",
                                     config_path=_write_pool(tmp_path, m))
        finally:
            m.stop()
        assert rep.degraded
        assert "rate_limit" in rep.error
        assert "确定性模板" in rep.markdown

    def test_truncated_completion_is_rejected(self, tmp_path):
        m = _MockLLM(reply="## 修复验证摘要\n太短").start()
        try:
            rep = ra.build_ai_report(MIXED, "http://t", {}, task="verify",
                                     config_path=_write_pool(tmp_path, m))
        finally:
            m.stop()
        assert rep.degraded
        assert "truncated" in rep.error


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _ai_meta(**over):
    m = {"ok": True, "used_llm": True, "degraded": False, "provider": "mock",
         "model": "m1", "failovers": 0, "elapsed": 1.0, "error": "",
         "fact_warnings": [], "finding_count": 4, "attempts": [],
         "markdown": "## 修复验证摘要\n仍有一处可利用。",
         "html": "<h3>修复验证摘要</h3><p>仍有一处可利用。</p>"}
    m.update(over)
    return m


class TestVerifyReportRendering:
    def test_html_without_ai_is_unchanged(self):
        out = vf.build_html(MIXED, "old.json", "http://t")
        assert '<section class="ai-report' not in out
        assert "Verify-Fix Report" in out

    def test_html_includes_the_section_before_the_table(self):
        out = vf.build_html(MIXED, "old.json", "http://t",
                            ai_report=_ai_meta())
        assert '<section class="ai-report"' in out
        assert "仍有一处可利用" in out
        assert out.index('class="ai-report"') < out.index("<th>#</th>")

    def test_html_marks_a_degraded_section(self):
        out = vf.build_html(MIXED, "old.json", "http://t",
                            ai_report=_ai_meta(used_llm=False, degraded=True,
                                               error="all failed"))
        assert "ai-report degraded" in out

    def test_html_ignores_a_non_dict_ai_report(self):
        out = vf.build_html(MIXED, "old.json", "http://t", ai_report="nonsense")
        assert '<section class="ai-report' not in out

    def test_json_carries_metadata_without_the_html_duplicate(self):
        data = json.loads(vf.build_json(MIXED, "old.json", "http://t",
                                        ai_report=_ai_meta()))
        assert data["ai_report"]["used_llm"] is True
        assert "修复验证摘要" in data["ai_report"]["markdown"]
        assert "html" not in data["ai_report"]

    def test_json_without_ai_has_no_key(self):
        data = json.loads(vf.build_json(MIXED, "old.json", "http://t"))
        assert "ai_report" not in data

    def test_rendered_section_escapes_payloads(self):
        """The narrative is full of live payloads; it must not become a
        vector in the report itself."""
        rep = ra.AIReport(markdown="## 摘要\n`<script>alert(1)</script>`",
                          html=ra._md_to_html("## 摘要\n`<script>alert(1)</script>`"),
                          ok=True, used_llm=True, provider="m", model="m")
        out = vf.build_html(MIXED, "old.json", "http://t",
                            ai_report=rep.to_meta())
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

class TestCliWiring:
    def test_ai_report_flag_coexists_with_verify_fix(self):
        from xssentinel.__main__ import build_parser
        args = build_parser().parse_args(
            ["--verify-fix", "old.json", "--ai-report", "--ai-lang", "en"])
        assert args.verify_fix == "old.json"
        assert args.ai_report is True
        assert args.ai_lang == "en"

    def test_ai_opts_are_off_without_the_flag(self):
        from xssentinel.cli_runner import ai_opts_from_args
        from xssentinel.__main__ import build_parser
        args = build_parser().parse_args(["--verify-fix", "old.json"])
        assert ai_opts_from_args(args) == {}

    def test_ai_report_for_returns_none_when_disabled(self):
        from xssentinel.cli_runner import ai_report_for
        assert ai_report_for(MIXED, "http://t", {}, {}) is None
        assert ai_report_for(MIXED, "http://t", {}, None) is None

    def test_ai_report_for_never_raises_and_returns_meta(self):
        """Even an unusable pool yields a (degraded) section, not an error."""
        from xssentinel.cli_runner import ai_report_for
        meta = ai_report_for(MIXED, "http://t", {},
                             {"enabled": True, "config": "/nope/absent.json"},
                             task="verify")
        assert meta is not None
        assert meta["degraded"] is True
        assert "## 修复验证摘要" in meta["markdown"]
