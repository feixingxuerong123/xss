# -*- coding: utf-8 -*-
"""Cross-format invariants for the report generators under hostile input.

test_report.py pins each builder's happy path.  This file does what the
first real engagement does: hand the builders payloads that are TRYING
to break the report.  The deliverable formats must survive

  * a payload that contains ``|``, newlines, quotes and CJK text,
  * a payload containing ``` -- which used to close the markdown code
    fence and render the rest of the payload as live markdown in the
    client's PR comment (the report injected by what it reports),
  * a URL carrying a pipe (path/header findings ride payloads in URLs),
  * every severity in the SARIF level table.

Findings are plain dicts -- the builders shim ``f.data`` -- so no
Finding construction is needed.  No network.
"""
from __future__ import annotations
import csv
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import report

META = {"generated": "2026-09-26 00:00:00", "requests": 7, "waf": None}

HOSTILE_PAYLOAD = '<img src=x onerror=alert("中文|管道")>'
FENCE_BREAKER = " innocent\n```\n<script>free markdown</script>\n```"


def _f(payload=HOSTILE_PAYLOAD, sev="high", param="q|p", ctx="html_element",
       url="http://t/s|pipe?q=x", detail="token | confirmed"):
    return {
        "type": "reflected", "severity": sev, "param": param, "context": ctx,
        "payload": payload, "url": url, "method": "GET",
        "detail": detail, "confidence": "high", "transform": ["raw"],
        "poc": {"curl": "curl 'http://t/s?q=...'", "url": url},
    }


def _unescaped_pipes(cell_line: str) -> int:
    """Count pipe characters that actually delimit table cells."""
    return len(re.findall(r"(?<!\\)\|", cell_line))


class TestMarkdownSurvivesHostilePayloads:
    def test_summary_table_cells_survive_pipes_and_urls(self):
        out = report.build_markdown([_f()], "http://t", META)
        rows = [l for l in out.splitlines() if l.startswith("| 1 ")]
        assert rows, "the finding's summary row went missing entirely"
        # 6 columns -> 7 delimiters, payload/URL pipes must not add any.
        assert _unescaped_pipes(rows[0]) == 7, rows[0]
        assert "s\\|pipe" in rows[0], "URL pipe not escaped"

    def test_newline_in_url_cannot_spawn_table_rows(self):
        out = report.build_markdown(
            [_f(url="http://t/s?q=a\nb")], "http://t", META)
        # header + 1 finding row; the rule row is "|---|..." (no space)
        # and the URL's newline must not have spawned anything extra.
        rows = [l for l in out.splitlines() if l.startswith("| ")]
        assert len(rows) == 2, rows
        assert "a b" in rows[-1], "newline should collapse to a space"

    def test_payload_cannot_break_out_of_the_code_fence(self):
        out = report.build_markdown([_f(payload=FENCE_BREAKER)], "http://t",
                                    META)
        longest_run = max((len(m.group(0)) for m in
                           re.finditer(r"`+", FENCE_BREAKER)), default=0)
        fences = re.findall(r"^  (`+)", out, re.M)
        assert fences, "no code fences found"
        payload_fences = [f for f in fences if len(f) > 3]
        assert payload_fences, ("a ```-carrying payload must get a longer "
                                "fence, got fence lengths "
                                f"{[len(f) for f in fences]}")
        assert min(len(f) for f in payload_fences) > longest_run
        # ...and the payload is intact INSIDE the fence.
        assert FENCE_BREAKER in out

    def test_curl_poc_with_backticks_stays_fenced(self):
        # A curl command can carry backticks (command substitution) or
        # even a fence-breaking run -- the bash block must grow a fence
        # the content cannot close.
        f = _f()
        f["poc"] = {"curl": "curl 'x' $(echo `id`)\n```",
                    "url": f["url"]}
        out = report.build_markdown([f], "http://t", META)
        assert "bash" in out, "the bash PoC block went missing"
        fences = re.findall(r"^  (`+)bash", out, re.M)
        assert fences, "no bash fence found"
        assert min(len(x) for x in fences) > 3, (
            f"a ```-carrying curl must get a longer fence, got {fences}")
        assert "curl 'x' $(echo `id`)" in out

    def test_cjk_payload_survives_everywhere(self):
        out = report.build_markdown([_f()], "http://t", META)
        assert "中文" in out


class TestSarifLevelMatrix:
    def test_every_severity_maps_to_a_level(self):
        levels = {"critical": "error", "high": "error", "medium": "warning",
                  "low": "note", "info": "note"}
        for sev, want in levels.items():
            sarif = json.loads(
                report.build_sarif([_f(sev=sev)], "http://t", META))
            got = sarif["runs"][0]["results"][0]["level"]
            assert got == want, f"severity {sev} -> level {got}, want {want}"

    def test_detail_reaches_the_result_message(self):
        sarif = json.loads(report.build_sarif([_f()], "http://t", META))
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "token | confirmed" in msg
        assert sarif["runs"][0]["results"][0]["properties"]["severity"] \
            == "high"


class TestCsvRoundTrip:
    def test_hostile_payload_survives_quoting(self):
        text = report.build_csv([_f()], "http://t", META)
        rows = list(csv.reader(io.StringIO(text)))
        assert len(rows) == 2, f"expected header + 1 row, got {len(rows)}"
        flat = "\n".join("\x00".join(r) for r in rows)
        assert HOSTILE_PAYLOAD in flat, "payload mangled by CSV quoting"

    def test_payload_with_newline_stays_one_record(self):
        text = report.build_csv([_f(payload="a\nb,c\"d")], "http://t", META)
        rows = list(csv.reader(io.StringIO(text)))
        assert len(rows) == 2, "embedded newline split the CSV record"
        assert "a\nb,c\"d" in rows[1]


class TestJunitAndHtmlAndBurp:
    def test_critical_is_a_junit_failure_and_xml_still_parses(self):
        out = report.build_junit([_f(sev="critical")], "http://t", META)
        root = ET.fromstring(out)
        assert root.findall(".//failure"), "critical must be a failure"

    def test_low_is_skipped_not_failed(self):
        out = report.build_junit([_f(sev="low")], "http://t", META)
        root = ET.fromstring(out)
        assert root.findall(".//failure") == []
        assert root.findall(".//skipped"), "low must be skipped, not failed"

    def test_html_never_renders_the_payload_raw(self):
        out = report.build_html([_f(payload=HOSTILE_PAYLOAD)], "http://t",
                                META)
        assert "<img src=x onerror" not in out
        assert "中文" in out  # readable, just not executable

    def test_burp_xml_parses_with_hostile_payload(self):
        out = report.build_burp_xml([_f()], "http://t", META)
        root = ET.fromstring(out)
        assert root is not None


class TestOnePayloadEverywhere:
    """The triage invariant: whatever format a consumer opens, the
    confirmed payload text is findable -- compared through each format's
    canonical form (parsed JSON values, CSV cells, XML text), not the
    raw serialized bytes."""

    def test_payload_reaches_html_json_csv_markdown_burp(self):
        f = _f(payload=HOSTILE_PAYLOAD)

        def _json_values(out):
            def walk(o):
                if isinstance(o, dict):
                    return " ".join(walk(v) for v in o.values())
                if isinstance(o, list):
                    return " ".join(walk(v) for v in o)
                return str(o)
            return walk(json.loads(out))

        def _csv_cells(out):
            return "\x00".join(c for r in csv.reader(io.StringIO(out))
                               for c in r)

        def _xml_text(out):
            return "\x00".join(ET.fromstring(out).itertext())

        checks = {
            "json": lambda out: HOSTILE_PAYLOAD in _json_values(out),
            "csv": lambda out: HOSTILE_PAYLOAD in _csv_cells(out),
            "markdown": lambda out: HOSTILE_PAYLOAD in out,
            "html": lambda out: "&lt;img src=x onerror" in out,
            "sarif": lambda out: HOSTILE_PAYLOAD in _json_values(out),
            "junit": lambda out: HOSTILE_PAYLOAD in _xml_text(out),
        }
        builders = {
            "json": report.build_json, "csv": report.build_csv,
            "markdown": report.build_markdown, "html": report.build_html,
            "sarif": report.build_sarif, "junit": report.build_junit,
        }
        missing = [name for name, check in checks.items()
                   if not check(builders[name]([f], "http://t", META))]
        assert not missing, f"payload lost in format(s): {missing}"
