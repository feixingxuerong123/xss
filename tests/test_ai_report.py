"""Phase 176: AI narrative report + deterministic fallback tests.

Includes the report-builder wiring (``meta['ai_report']`` -> html/markdown/json)
and the two behaviours that live probes forced into the design:

* an empty 200 body must not become an empty report section;
* a reasoning model that leaks its chain of thought must be cleaned up.

Self-contained: the one HTTP-dependent test uses a tiny local mock, so nothing
here touches a real provider.
"""
from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xssentinel.core import report as reportmod
from xssentinel.core import report_ai as ra
from xssentinel.core.llm_pool import LLMPool


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _finding(ftype="reflected", sev="high", url="http://t.local/search?q=x",
             payload="<script>alert(1)</script>", **kw):
    d = {"type": ftype, "severity": sev, "url": url, "method": "GET",
         "param": "q", "context": "html_body", "payload": payload,
         "transform": ["mixed_case"], "detail": "reflected unencoded",
         "poc": {"curl": f"curl -s '{url}'"}}
    d.update(kw)
    return d


FINDINGS = [
    _finding("reflected", "high", "http://t.local/search?q=x"),
    _finding("dom", "medium", "http://t.local/page#frag",
             payload="';alert(1)//", param="frag"),
    _finding("stored", "critical", "http://t.local/comment",
             payload="<img src=x onerror=alert(document.domain)>", method="POST"),
]

#: A reply long enough to clear ``report_ai.MIN_REPORT_CHARS`` -- the pool
#: rejects a stub as ``truncated_response``, so mock "success" replies must
#: look like a real report, not a one-liner.
_LONG_REPLY = ("## 执行摘要\n"
               + "本次扫描发现多处 XSS 缺陷，建议尽快修复。\n" * 12
               + "## 风险评级\n| 严重度 | 数量 |\n|---|---|\n| high | 1 |\n")


class _Mock:
    """Minimal OpenAI-compatible endpoint: one scripted reply per model."""

    def __init__(self, reply=None, status=200):
        self.reply = reply if reply is not None else _LONG_REPLY
        self.status = status
        self.calls = 0
        self._srv = None

    def start(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            # HTTP/1.0: one connection per request -- see the note in
            # tests/test_llm_pool.py (degraded local loopback + keep-alive
            # pooling is what produced the stray WinError 10054).
            protocol_version = "HTTP/1.0"

            def do_POST(self):
                try:
                    self._respond()
                except (ConnectionResetError, ConnectionAbortedError,
                        BrokenPipeError):
                    pass

            def _respond(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.calls += 1
                if outer.status == 200:
                    payload = {"choices": [{"message": {
                        "role": "assistant", "content": outer.reply}}]}
                else:
                    payload = {"error": {"message": "Model 'x' is at its "
                                                    "concurrency limit (8)"}}
                data = json.dumps(payload, ensure_ascii=False).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                assert body.get("model")

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


def _pool_for(tmp_path, mock) -> LLMPool:
    cfg = {
        "timeout": 10,
        "cooldown": {"rate_limit": 0.1, "backoff_factor": 1, "max": 1},
        "providers": [{"id": "mock", "base_url": mock.base_url,
                       "keys": ["k1-aaaaaaaa"], "models": ["m1"]}],
    }
    return LLMPool(cfg, source=str(tmp_path / "p.json"),
                   state_path=str(tmp_path / "s.json"))


# ---------------------------------------------------------------------------
# clean_completion -- reasoning leak (observed live with MiniCPM5-2B)
# ---------------------------------------------------------------------------

def test_clean_completion_strips_leaked_reasoning_with_close_tag():
    src = ("我们被要求根据提供的JSON数据撰写报告。报告必须遵循指定的结构。\n"
           " 注意：只能使用输入中提供的事实。\n</think>\n\n"
           "## 执行摘要\n本次扫描发现 3 个漏洞。")
    out = ra.clean_completion(src)
    assert out.startswith("## 执行摘要")
    assert "我们被要求" not in out
    assert "</think" not in out


def test_clean_completion_strips_paired_think_block():
    out = ra.clean_completion("<thinking>plan the report</thinking>\n## 执行摘要\nX")
    assert out == "## 执行摘要\nX"


def test_clean_completion_drops_untagged_preamble():
    out = ra.clean_completion("好的，我将根据数据撰写报告。\n\n## 执行摘要\nX")
    assert out == "## 执行摘要\nX"


def test_clean_completion_leaves_a_clean_report_untouched():
    src = "## 执行摘要\n内容\n\n## 风险评级\n| a | b |\n|---|---|\n| 1 | 2 |"
    assert ra.clean_completion(src) == src


def test_clean_completion_unwraps_a_whole_report_fence():
    assert ra.clean_completion("```markdown\n## 执行摘要\nX\n```") == \
        "## 执行摘要\nX"
    assert ra.clean_completion("```\n## 执行摘要\nX\n```") == "## 执行摘要\nX"


def test_clean_completion_keeps_payload_tags_in_the_body():
    """A narrow tag list matters: <output> is a plausible payload, not a
    reasoning channel, and must survive."""
    src = "## 执行摘要\n载荷为 <output>alert(1)</output> 形态。"
    assert ra.clean_completion(src) == src


def test_clean_completion_keeps_a_preamble_only_body():
    """No heading at all => nothing to anchor on, so do not destroy it."""
    assert ra.clean_completion("我们被要求撰写报告。") == "我们被要求撰写报告。"


def test_clean_completion_handles_empty():
    assert ra.clean_completion("") == ""
    assert ra.clean_completion(None) == ""


# ---------------------------------------------------------------------------
# Markdown -> HTML (escape-first: the report is full of live payloads)
# ---------------------------------------------------------------------------

def test_md_to_html_escapes_payloads_so_the_report_is_not_a_vector():
    md = "## 详情\n- 载荷：`<script>alert(1)</script>`\n- <img src=x onerror=alert(1)>"
    out = ra._md_to_html(md)
    assert "<script>alert(1)</script>" not in out
    assert "<img src=x" not in out
    assert "&lt;script&gt;" in out
    assert "&lt;img src=x" in out


def test_md_to_html_escapes_raw_html_block():
    out = ra._md_to_html("## X\n<iframe src=javascript:alert(1)></iframe>")
    assert "<iframe" not in out
    assert "&lt;iframe" in out


def test_md_to_html_renders_headings_lists_and_emphasis():
    out = ra._md_to_html("## 标题\n**粗** 与 `代码`\n- 一\n- 二\n1. 甲\n2. 乙")
    assert "<h3>标题</h3>" in out
    assert "<strong>粗</strong>" in out
    assert "<code>代码</code>" in out
    assert "<ul>" in out and "<li>一</li>" in out
    assert "<ol>" in out and "<li>甲</li>" in out


def test_md_to_html_renders_tables_and_skips_separator():
    out = ra._md_to_html("| 严重度 | 数量 |\n|---|---|\n| high | 2 |")
    assert out.count("<tr>") == 2          # header + one data row, not the rule
    assert "<td>high</td>" in out


def test_md_to_html_keeps_section_and_finding_headings_at_distinct_depths():
    """The section already carries an <h2>, so the model's '##' must land on
    h3 and its '###' on h4 -- collapsing both to h3 would make a section
    heading and a per-finding heading indistinguishable."""
    out = ra._md_to_html("## 执行摘要\n文字\n### 1. [high] reflected\n细节")
    assert "<h3>执行摘要</h3>" in out
    assert "<h4>1. [high] reflected</h4>" in out
    assert "<h1>" not in out


def test_md_to_html_renders_double_backtick_code_spans():
    """Models wrap commands in ``...``; leaving them literal mangles the one
    part of the report a reader copy-pastes (observed live with a curl PoC)."""
    out = ra._md_to_html("复现：``curl -i 'http://t.local/?q=1'`` 已确认")
    assert "``" not in out
    assert "<code>curl -i 'http://t.local/?q=1'</code>" in out


def test_md_to_html_demotes_h1_to_h2_inside_the_section():
    out = ra._md_to_html("# 不应该是一级标题")
    assert "<h2>" in out and "<h1>" not in out


def test_md_to_html_handles_empty():
    assert ra._md_to_html("") == ""


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------

def test_summarize_orders_by_severity_and_counts():
    rows, stats = ra.summarize_findings(FINDINGS)
    assert [r["severity"] for r in rows] == ["critical", "high", "medium"]
    assert stats["total"] == 3
    assert stats["by_severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert stats["omitted"] == 0


def test_summarize_caps_rows_and_reports_omissions():
    many = [_finding("reflected", "low", url=f"http://t.local/{i}?a=1")
            for i in range(40)]
    rows, stats = ra.summarize_findings(many, max_findings=10)
    assert len(rows) == 10
    assert stats["total"] == 40 and stats["omitted"] == 30


def test_summarize_clips_long_fields():
    rows, _ = ra.summarize_findings([
        _finding(payload="A" * 900, detail="B" * 900)])
    assert len(rows[0]["payload"]) <= ra._PAYLOAD_CAP + 1
    assert len(rows[0]["detail"]) <= ra._DETAIL_CAP + 1


def test_summarize_pulls_remediation_from_the_advice_corpus():
    rows, _ = ra.summarize_findings([_finding("reflected")])
    assert rows[0]["engine_fix_headline"]
    assert rows[0]["cwe"]


def test_summarize_handles_zero_findings():
    rows, stats = ra.summarize_findings([])
    assert rows == [] and stats["total"] == 0


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------

def test_template_report_contains_every_section():
    md = ra.template_report(FINDINGS, "http://t.local",
                            {"generated": "2026-09-22 13:00"})
    for section in ("## 执行摘要", "## 风险评级", "## 漏洞详情",
                    "## 修复优先级建议"):
        assert section in md
    assert "http://t.local/comment" in md
    assert "CWE-79" in md


def test_template_report_states_the_degradation_reason():
    md = ra.template_report(FINDINGS, "http://t.local", {},
                            reason="all candidates failed (rate_limit x3)")
    assert "确定性模板" in md
    assert "rate_limit x3" in md


def test_template_report_handles_no_findings():
    md = ra.template_report([], "http://t.local", {})
    assert "未发现 XSS 相关缺陷" in md
    assert "## 漏洞详情" not in md


def test_template_report_english():
    md = ra.template_report(FINDINGS, "http://t.local", {}, lang="en")
    assert "## Executive Summary" in md
    assert "## Finding Details" in md


def test_template_report_escapes_nothing_but_html_renderer_does():
    md = ra.template_report(FINDINGS, "http://t.local", {})
    html_out = ra._md_to_html(md)
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out


# ---------------------------------------------------------------------------
# build_ai_report: success path, degradation paths
# ---------------------------------------------------------------------------

def test_build_ai_report_success_marks_used_llm(tmp_path):
    mock = _Mock().start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.used_llm and rep.ok and not rep.degraded
    assert rep.provider == "mock" and rep.model == "m1"
    assert rep.failovers == 0
    assert "## 执行摘要" in rep.markdown
    # The provenance note must be present and name the model.
    assert "m1" in rep.markdown
    assert rep.html and "<h3>" in rep.html


def test_build_ai_report_cleans_reasoning_leak_from_the_model(tmp_path):
    mock = _Mock(reply="思考中……</think>\n\n" + _LONG_REPLY).start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.used_llm
    assert "思考中" not in rep.markdown
    assert rep.markdown.index("## 执行摘要") > 0


def test_build_ai_report_degrades_when_pool_is_exhausted(tmp_path):
    mock = _Mock(status=429).start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert not rep.used_llm and rep.degraded
    assert "rate_limit" in rep.error
    assert "确定性模板" in rep.markdown
    assert "## 执行摘要" in rep.markdown          # still a usable report
    assert rep.attempts and rep.attempts[0]["kind"] == "rate_limit"


def test_build_ai_report_degrades_on_empty_completion(tmp_path):
    mock = _Mock(reply="   ").start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.degraded
    assert "empty" in rep.error.lower()


def test_build_ai_report_rejects_a_truncated_completion(tmp_path):
    """A 200 whose answer is a stub must never reach the report: a
    reasoning-heavy model that spends its budget on thinking returns exactly
    that.  With one candidate this degrades; with more, it fails over."""
    mock = _Mock(reply="## 执行摘要\n太短").start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.degraded
    assert "truncated" in rep.error
    assert "确定性模板" in rep.markdown


def test_build_ai_report_accepts_a_short_but_real_report(tmp_path):
    """The floor must not be so high that a legitimately terse report (a scan
    with a single low finding) gets thrown away."""
    body = "## 执行摘要\n" + "本次扫描仅发现一处低危缺陷，风险可控。" * 12
    assert len(body) > ra.MIN_REPORT_CHARS
    mock = _Mock(reply=body).start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.used_llm


def test_build_ai_report_degrades_without_any_config(tmp_path):
    rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                             config_path=str(tmp_path / "missing.json"))
    assert rep.degraded
    assert "LLMConfigError" in rep.error
    assert "## 执行摘要" in rep.markdown


def test_build_ai_report_never_raises_on_pool_failure():
    """Whatever happens to the pool, a report section must come back."""
    rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                             pool=object())          # deliberately unusable
    assert rep.degraded
    assert rep.markdown


def test_build_ai_report_prompt_carries_the_facts_and_the_rules(tmp_path):
    mock = _Mock().start()
    try:
        ra.build_ai_report(FINDINGS, "http://t.local", {"requests": 42},
                           pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    prompt = ra.build_prompt(*ra.summarize_findings(FINDINGS),
                             target="http://t.local",
                             meta={"requests": 42})
    text = json.dumps(prompt, ensure_ascii=False)
    assert "禁止编造" in text
    assert "http://t.local/comment" in text
    assert "html_body" in text
    assert "42" in text


# ---------------------------------------------------------------------------
# Fact verification
# ---------------------------------------------------------------------------

def test_fact_check_flags_an_invented_url():
    rows, _ = ra.summarize_findings(FINDINGS)
    warnings = ra._verify_facts(
        "详见 http://evil.example.com/admin 与 http://t.local/comment", rows)
    assert any("evil.example.com" in w for w in warnings)
    assert not any("t.local/comment" in w for w in warnings)


def test_fact_check_accepts_a_shortened_known_url():
    rows, _ = ra.summarize_findings(FINDINGS)
    warnings = ra._verify_facts("复现：http://t.local/comment 已确认。", rows)
    assert warnings == []


def test_fact_check_flags_an_invented_payload():
    rows, _ = ra.summarize_findings(FINDINGS)
    warnings = ra._verify_facts("载荷 `<svg onload=alert(999)>`", rows)
    assert any("svg onload" in w for w in warnings)


def test_fact_check_passes_a_known_payload():
    rows, _ = ra.summarize_findings(FINDINGS)
    warnings = ra._verify_facts("载荷 `<script>alert(1)</script>`", rows)
    assert warnings == []


def test_fact_check_ignores_prose_without_urls_or_payloads():
    rows, _ = ra.summarize_findings(FINDINGS)
    assert ra._verify_facts("本次扫描风险较高，建议尽快修复。", rows) == []


def test_fact_check_accepts_the_scan_target_when_passed_as_context():
    """Regression: a clean scan has no finding URLs, so the target was the
    only URL in the model's summary and got flagged as invented.  Observed on
    a live API scan (0 findings)."""
    rows, _ = ra.summarize_findings([])
    warnings = ra._verify_facts(
        "目标 http://t.local/?q=test 扫描完成，未发现缺陷。", rows,
        extra_urls=["http://t.local/?q=test"])
    assert warnings == []


def test_fact_check_still_flags_a_foreign_host_alongside_the_target():
    rows, _ = ra.summarize_findings([])
    warnings = ra._verify_facts(
        "目标 http://t.local/ 与 http://elsewhere.example/x", rows,
        extra_urls=["http://t.local/"])
    assert any("elsewhere.example" in w for w in warnings)
    assert not any("t.local" in w for w in warnings)


def test_clean_scan_report_has_no_false_unverified_warning(tmp_path):
    """The whole path, not just the checker: a 0-finding run must not warn."""
    mock = _Mock(reply=_LONG_REPLY + "\n目标 http://clean.local/?q=1 未发现缺陷。").start()
    try:
        rep = ra.build_ai_report([], "http://clean.local/?q=1", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.used_llm
    assert rep.fact_warnings == []
    assert "未能与扫描结果核对" not in rep.markdown


def test_invented_url_surfaces_in_the_report_header(tmp_path):
    mock = _Mock(reply=_LONG_REPLY + "\n详见 http://made-up.example/x").start()
    try:
        rep = ra.build_ai_report(FINDINGS, "http://t.local", {},
                                 pool=_pool_for(tmp_path, mock))
    finally:
        mock.stop()
    assert rep.fact_warnings
    assert "made-up.example" in rep.markdown
    assert "未能与扫描结果核对" in rep.markdown


# ---------------------------------------------------------------------------
# Report-builder wiring (meta['ai_report'])
# ---------------------------------------------------------------------------

def _ai_meta(**over):
    m = {"ok": True, "used_llm": True, "degraded": False, "provider": "amd",
         "model": "DeepSeek-V4-Flash", "failovers": 1, "elapsed": 3.2,
         "error": "", "fact_warnings": [], "finding_count": 3,
         "attempts": [],
         "markdown": "## 执行摘要\n这是一段模型写的摘要。",
         "html": "<h2>执行摘要</h2><p>这是一段模型写的摘要。</p>"}
    m.update(over)
    return m


def test_html_report_includes_the_ai_section():
    out = reportmod.build_html(FINDINGS, "http://t.local",
                               {"ai_report": _ai_meta()})
    assert "这是一段模型写的摘要" in out
    assert 'class="ai-report"' in out


def test_html_report_marks_a_degraded_section():
    out = reportmod.build_html(FINDINGS, "http://t.local",
                               {"ai_report": _ai_meta(used_llm=False,
                                                      degraded=True,
                                                      error="all failed")})
    assert "ai-report degraded" in out


def test_html_report_without_ai_meta_is_unchanged():
    base = reportmod.build_html(FINDINGS, "http://t.local", {})
    # The stylesheet always defines .ai-report; what must be absent is the
    # rendered section itself.
    assert '<section class="ai-report' not in base
    # The h1 opens with the inline brand SVG, then the report title (the
    # shared report_theme header used by every HTML deliverable).
    assert "<h1>" in base and "XSSentinel &mdash; XSS Detection Report" in base


def test_markdown_report_includes_the_ai_section_before_the_table():
    out = reportmod.build_markdown(FINDINGS, "http://t.local",
                                   {"ai_report": _ai_meta()})
    assert "## AI 分析" in out
    assert out.index("## AI 分析") < out.index("## Summary Table")


def test_markdown_report_empty_findings_still_carries_the_ai_section():
    out = reportmod.build_markdown([], "http://t.local",
                                   {"ai_report": _ai_meta()})
    assert "No XSS vulnerabilities found" in out
    assert "## AI 分析" in out


def test_markdown_report_without_ai_meta_is_unchanged():
    out = reportmod.build_markdown(FINDINGS, "http://t.local", {})
    assert "AI 分析" not in out
    assert out.startswith("# XSSentinel Scan Report")


def test_json_report_carries_ai_meta_without_the_html_duplicate():
    raw = reportmod.build_json(FINDINGS, "http://t.local",
                               {"ai_report": _ai_meta()})
    data = json.loads(raw)
    assert data["ai_report"]["used_llm"] is True
    assert data["ai_report"]["model"] == "DeepSeek-V4-Flash"
    assert "## 执行摘要" in data["ai_report"]["markdown"]
    assert "html" not in data["ai_report"]      # do not double the report size


def test_json_report_without_ai_meta_has_no_key():
    assert "ai_report" not in json.loads(
        reportmod.build_json(FINDINGS, "http://t.local", {}))


def test_section_helpers_are_null_safe():
    assert ra.ai_section_html(None) == ""
    assert ra.ai_section_html({}) == ""
    assert ra.ai_section_html({"html": ""}) == ""
    assert ra.ai_section_markdown(None) == ""
    assert ra.ai_section_markdown({"markdown": ""}) == ""


def test_ai_report_to_meta_round_trips():
    rep = ra.AIReport(markdown="md", html="<p>h</p>", ok=True, used_llm=True,
                      provider="amd", model="m", failovers=2)
    meta = rep.to_meta()
    assert meta["provider"] == "amd" and meta["failovers"] == 2
    assert meta["used_llm"] is True and meta["degraded"] is False
    assert json.loads(json.dumps(meta))          # JSON serialisable
