"""Tests for the report generators (Phase 43).

report.py was at 45% coverage despite being the user-facing output layer.
All six builders (html/json/csv/sarif/junit/markdown) are pure functions of
(findings, target, meta); findings can be plain dicts (the builders use the
``f.data if hasattr(f, "data") else f`` shim), so no Finding construction is
needed.  Tests assert format-specific contracts: SARIF rule-id mapping and
severity levels, JUnit failure/skipped split, Markdown empty-state, and HTML
escaping (a payload must never break out of the report page itself).
"""
from __future__ import annotations
import base64
import email
import json
import os
import sys
import xml.etree.ElementTree as ET

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import report


def _f(ftype="reflected", sev="high", param="q", ctx="html_element",
       payload="<script>alert(1)</script>", url="http://t/s?q=x",
       detail="token confirmed", poc=None, method="GET",
       evidence="", csrf_fields=None):
    d = {
        "type": ftype, "severity": sev, "param": param, "context": ctx,
        "payload": payload, "url": url, "method": method,
        "detail": detail, "confidence": "high", "transform": ["raw"],
        "poc": poc or {"curl": "curl 'http://t/s?q=...'", "url": url},
    }
    if evidence:
        d["evidence"] = evidence
    if csrf_fields:
        d["csrf_fields"] = csrf_fields
    return d


META = {"generated": "2026-08-30 00:00:00", "requests": 42, "waf": None}


class TestEscAndSafeUrl:
    def test_esc_html_entities(self):
        assert report._esc("<script>") == "&lt;script&gt;"
        assert report._esc('"a" & \'b\'') == "&quot;a&quot; &amp; &#x27;b&#x27;"

    def test_safe_url_strips_javascript(self):
        # javascript: must never survive into a clickable href in the report.
        out = report._safe_url("javascript:alert(1)")
        assert "javascript:" not in out.lower()

    def test_safe_url_keeps_http(self):
        assert report._safe_url("http://t/x?a=1") == "http://t/x?a=1"


class TestBuildJson:
    def test_structure_and_findings(self):
        out = json.loads(report.build_json([_f()], "http://t/s", META))
        assert out["tool"] == "XSSentinel"
        assert out["target"] == "http://t/s"
        assert out["requests"] == 42
        assert len(out["findings"]) == 1
        assert out["findings"][0]["type"] == "reflected"

    def test_coverage_attached_when_present(self):
        class _Cov:
            def to_json_dict(self):
                return {"endpoints": 3}

        out = json.loads(report.build_json([_f()], "http://t/s",
                                           {**META, "coverage": _Cov()}))
        assert out["coverage"]["endpoints"] == 3

    def test_broken_coverage_does_not_crash(self):
        class _BadCov:
            def to_json_dict(self):
                raise RuntimeError("boom")

        out = json.loads(report.build_json([_f()], "http://t/s",
                                           {**META, "coverage": _BadCov()}))
        assert "coverage" not in out  # gracefully omitted


class TestBuildCsv:
    def test_header_and_row(self):
        csv_text = report.build_csv([_f()], "http://t/s", META)
        lines = [l for l in csv_text.splitlines() if l.strip()]
        assert lines[0].startswith("type,url,method,param")
        assert len(lines) == 2  # header + 1 finding
        assert "reflected" in lines[1] and "http://t/s?q=x" in lines[1]

    def test_transform_joined(self):
        f = _f()
        f["transform"] = ["raw", "url_encode"]
        csv_text = report.build_csv([f], "http://t/s", META)
        assert "raw,url_encode" in csv_text or '"raw,url_encode"' in csv_text


class TestBuildSarif:
    def test_schema_and_version(self):
        doc = json.loads(report.build_sarif([_f()], "http://t/s", META))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "XSSentinel"

    def test_rule_id_mapping_and_level(self):
        doc = json.loads(report.build_sarif(
            [_f("reflected", "high"), _f("stored", "medium"),
             _f("blind", "low")], "http://t/s", META))
        results = doc["runs"][0]["results"]
        assert results[0]["ruleId"] == "XSSENTINEL-XSS-REFLECTED"
        assert results[0]["level"] == "error"      # high
        assert results[1]["ruleId"] == "XSSENTINEL-XSS-STORED"
        assert results[1]["level"] == "warning"    # medium
        assert results[2]["level"] == "note"       # low

    def test_framework_prefix_maps_to_generic_rule(self):
        doc = json.loads(report.build_sarif(
            [_f("framework_vue_xss", "high")], "http://t/s", META))
        assert doc["runs"][0]["results"][0]["ruleId"] == "XSSENTINEL-XSS-FRAMEWORK"

    def test_cors_misconfig_has_dedicated_rule(self):
        # Phase 51: CORS audit findings carry their own SARIF rule id.
        doc = json.loads(report.build_sarif(
            [_f("cors_misconfig", "high")], "http://t/s", META))
        assert doc["runs"][0]["results"][0]["ruleId"] == \
            "XSSENTINEL-CORS-MISCONFIG"
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_xs_leak_surface_has_dedicated_rule(self):
        # Phase 53: XS-Leaks surface audit findings get their own rule.
        doc = json.loads(report.build_sarif(
            [_f("xs_leak_surface", "low")], "http://t/s", META))
        assert doc["runs"][0]["results"][0]["ruleId"] == \
            "XSSENTINEL-XSLEAK-SURFACE"
        assert doc["runs"][0]["results"][0]["level"] == "note"  # low

    def test_empty_findings_emits_default_rule(self):
        doc = json.loads(report.build_sarif([], "http://t/s", META))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1 and rules[0]["id"] == "XSSENTINEL-XSS"
        assert doc["runs"][0]["results"] == []


class TestBuildJunit:
    def test_high_is_failure_medium_is_skipped(self):
        xml = report.build_junit(
            [_f("reflected", "high"), _f("dom", "medium")], "http://t/s", META)
        root = ET.fromstring(xml.replace(
            '<?xml version="1.0" encoding="UTF-8"?>', ''))
        suite = root.find("testsuite")
        assert suite.get("tests") == "2"
        assert suite.get("failures") == "1"
        # high -> <failure>, medium -> <skipped>
        assert xml.count("<failure") == 1
        assert xml.count("<skipped") == 1

    def test_payload_xml_escaped(self):
        xml = report.build_junit([_f(payload="<script>alert(1)</script>")],
                                 "http://t/s", META)
        # Raw <script> inside a testcase would corrupt the XML.
        assert "<script>alert(1)</script>" not in xml
        assert "&lt;script&gt;" in xml


class TestBuildMarkdown:
    def test_empty_state(self):
        md = report.build_markdown([], "http://t/s", META)
        assert "No XSS vulnerabilities found" in md
        assert "http://t/s" in md

    def test_summary_table_and_details(self):
        md = report.build_markdown(
            [_f("reflected", "high"), _f("stored", "medium", param="bio")],
            "http://t/s", META)
        assert "## Summary Table" in md
        assert "| 1 | high | reflected |" in md
        assert "## Details" in md
        assert "### 2. [MEDIUM] stored on `bio`" in md
        assert "PoC (curl)" in md  # poc.curl rendered

    def test_counts_by_severity(self):
        md = report.build_markdown(
            [_f("reflected", "high"), _f("reflected", "high"),
             _f("dom", "low")], "http://t/s", META)
        assert "**high**: 2" in md
        assert "**low**: 1" in md


class TestBuildHtml:
    def test_html_contains_target_and_escapes_payload(self):
        html = report.build_html([_f()], "http://t/s", META)
        assert "http://t/s" in html
        # The finding payload must be HTML-escaped so the REPORT page itself
        # doesn't execute the very XSS it reports.
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_findings_html(self):
        html = report.build_html([], "http://t/s", META)
        assert "http://t/s" in html  # still a valid report shell


# ---------------------------------------------------------------------------
# Phase 49: ecosystem interop -- Burp Suite "export issue data" XML
# ---------------------------------------------------------------------------
class TestBuildBurpXml:
    def test_root_and_one_issue_per_finding(self):
        xml = report.build_burp_xml(
            [_f("reflected", "high"), _f("stored", "medium", param="bio")],
            "http://t/s", META)
        root = ET.fromstring(xml)
        assert root.tag == "issues"
        issues = root.findall("issue")
        assert len(issues) == 2
        # Importers (Dradis & co) key on <name>, not the type integer.
        assert issues[0].findtext("name") == \
            "Cross-site scripting (reflected)"
        assert issues[1].findtext("name") == \
            "Cross-site scripting (stored)"
        assert issues[0].findtext("type") == "134217728"

    def test_host_path_location_split_burp_style(self):
        # host keeps the scheme; path drops the query; location marks the
        # injectable entry point (no payload) -- Burp's own split.
        xml = report.build_burp_xml(
            [_f(url="http://t/s?q=x", param="q")], "http://t/s", META)
        issue = ET.fromstring(xml).findall("issue")[0]
        assert issue.findtext("host") == "http://t"
        assert issue.findtext("path") == "/s"
        assert issue.findtext("location") == "/s?q="

    def test_severity_confidence_vocabulary(self):
        xml = report.build_burp_xml(
            [_f("reflected", "high"), _f("dom", "low")], "http://t/s", META)
        issues = ET.fromstring(xml).findall("issue")
        assert issues[0].findtext("severity") == "High"
        assert issues[0].findtext("confidence") == "Certain"
        assert issues[1].findtext("severity") == "Low"

    def test_serial_stable_per_finding(self):
        a = report.build_burp_xml([_f(url="http://t/s?q=x")], "http://t/s", META)
        b = report.build_burp_xml([_f(url="http://t/s?q=x")], "http://t/s", META)
        ser_a = ET.fromstring(a).findall("issue")[0].findtext("serialNumber")
        ser_b = ET.fromstring(b).findall("issue")[0].findtext("serialNumber")
        assert ser_a == ser_b  # dedup on re-import

    def test_request_base64_replays_confirmed_payload(self):
        xml = report.build_burp_xml([_f()], "http://t/s", META)
        issue = ET.fromstring(xml).findall("issue")[0]
        raw = base64.b64decode(issue.find("request").text).decode()
        assert raw.startswith("GET /s?q=") and " HTTP/1.1" in raw
        # Payload is urlencoded in the line; decoding must recover it.
        from urllib.parse import unquote
        assert "<script>alert(1)</script>" in unquote(raw)

    def test_evidence_becomes_base64_response(self):
        xml = report.build_burp_xml(
            [_f(ftype="stored_upload", evidence="<a href='/up/x'>ok</a>")],
            "http://t/s", META)
        issue = ET.fromstring(xml).findall("issue")[0]
        resp = base64.b64decode(issue.find("response").text).decode()
        assert "/up/x" in resp

    def test_payload_cannot_break_cdata(self):
        # A payload containing the CDATA terminator must not corrupt the XML.
        xml = report.build_burp_xml(
            [_f(payload="x]]><script>alert(1)</script>")], "http://t/s", META)
        root = ET.fromstring(xml)  # still well-formed
        detail = root.findall("issue")[0].findtext("issueDetail")
        assert "x]]><script>alert(1)</script>" in detail

    def test_header_finding_request_carries_the_header(self):
        # Phase 56: a (header:X) finding's embedded request must place the
        # payload on that header -- not in a bogus query parameter -- so the
        # finding replays in Burp Repeater exactly as it was confirmed.
        f = _f(ftype="header_xss", param="(header:User-Agent)",
               url="http://t/s?x=1", payload="<svg/onload=alert('xsshd_a1')>")
        xml = report.build_burp_xml([f], "http://t/s", META)
        issue = ET.fromstring(xml).findall("issue")[0]
        raw = base64.b64decode(issue.find("request").text).decode()
        assert raw.startswith("GET /s?x=1 HTTP/1.1")
        assert "User-Agent: <svg/onload=alert('xsshd_a1')>" in raw
        assert "(header" not in raw  # carrier never leaks into the query
        assert raw.count("xsshd_a1") == 1  # payload only on the header line

    def test_cookie_finding_request_carries_the_cookie(self):
        f = _f(ftype="cookie_xss", param="(cookie:sid)",
               url="http://t/a", payload="<svg/onload=alert('xsck_77')>")
        xml = report.build_burp_xml([f], "http://t/a", META)
        issue = ET.fromstring(xml).findall("issue")[0]
        raw = base64.b64decode(issue.find("request").text).decode()
        assert raw.startswith("GET /a HTTP/1.1")
        assert "Cookie: sid=<svg/onload=alert('xsck_77')>" in raw
        assert "(cookie" not in raw

    def test_empty_findings_is_valid_shell(self):
        xml = report.build_burp_xml([], "http://t/s", META)
        root = ET.fromstring(xml)
        assert root.tag == "issues" and root.findall("issue") == []


# ---------------------------------------------------------------------------
# Phase 49: ecosystem interop -- nuclei YAML templates
# ---------------------------------------------------------------------------
def _raw_block(yaml_text):
    """Pull the literal raw HTTP block out of a generated template."""
    lines = yaml_text.splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() == "- |":
            out = []
            for sub in lines[i + 1:]:
                if sub and not sub.startswith("        "):
                    break
                out.append(sub[8:] if sub.startswith("        ") else "")
            return "\r\n".join(out)
    return ""


class TestNucleiHelpers:
    def test_matcher_skeleton_normalizes_marker_tokens(self):
        assert report._matcher_skeleton(
            "<svg/onload=alert('xssm_1a2b3c')>") == \
            "<svg/onload=alert('XSSENTINEL')>"
        assert report._matcher_skeleton(
            "<img src=x onerror=alert('xssup_9e8d7c')>") == \
            "<img src=x onerror=alert('XSSENTINEL')>"
        assert "xssm_" not in report._matcher_skeleton(
            "<script>fetch('http://oob/xssm_deadbeef')</script>")
        # stable across runs with different tokens
        a = report._matcher_skeleton("<svg/onload=alert('xssm_1a2b')>")
        b = report._matcher_skeleton("<svg/onload=alert('xssm_cc00')>")
        assert a == b

    def test_write_poc_dir_accepts_finding_objects_and_dicts(self, tmp_path):
        # Phase 183 CLI-matrix catch: --poc-dir was handed Finding OBJECTS
        # by the CLI but the writer only unpacked plain dicts, so every
        # real run silently produced an INDEX.md with zero artifacts.
        # Both shapes must land the .html/.sh artifacts + the index row.
        import tempfile

        from xssentinel.core.findings import Finding

        def _poc_data():
            return {"type": "reflected", "url": "http://t/s", "param": "q",
                    "severity": "high", "poc_verified": True,
                    "poc": {"curl": "curl 'http://t/s?q=1'",
                            "html": "<html><body>x</body></html>"}}

        # Third caller shape: {"data": {...}} wrappers (test_poc_dir's
        # to_dict-mimicking fixture) must keep working too.
        for label, payload in (("dicts", [_poc_data()]),
                               ("findings", [Finding(**_poc_data())]),
                               ("wrapped", [{"data": _poc_data()}])):
            out = tmp_path / label
            written = report.write_poc_dir(payload, "http://t/s",
                                           {"generated": "g"}, str(out))
            names = sorted(os.path.basename(w) for w in written)
            assert "INDEX.md" in names, (label, names)
            assert any(n.endswith(".html") for n in names), (label, names)
            assert any(n.endswith(".sh") for n in names), (label, names)
            idx = (out / "INDEX.md").read_text(encoding="utf-8")
            assert "with PoC: 1" in idx, (label, idx)
            assert "[`reflected.html`](reflected.html)" in idx, (label, idx)

    def test_slug_is_safe(self):
        assert report._nuclei_slug("upload_xss") == "upload-xss"
        assert report._nuclei_slug("Template_SSTI_Vue!!") == "template-ssti-vue"
        assert report._nuclei_slug("...") == "xss"  # fallback

    def test_obscure_type_name_falls_back_to_slug(self):
        assert "weird thing" in report._interop_type_name("weird_thing")
        assert "(XSS)" in report._interop_type_name("weird_thing")


class TestNucleiExport:
    def test_get_template_marks_confirmed_param(self):
        y = report.build_nuclei_yaml([_f()], "http://t/s", META)
        assert "id: xssentinel-reflected-" in y
        assert '"{{BaseURL}}/s?q=' in y  # payload rides in the confirmed param
        assert "words:" in y
        assert "- \"<script>alert(1)</script>\"" in y  # matcher word present

    def test_get_matcher_word_replays_exact_payload(self):
        # The template replays the STORED payload (request and matcher share
        # its marker token), so the matcher word is that payload verbatim --
        # an early draft normalised the token to "XSSENTINEL", which can
        # never match the target's actual echo.
        f = _f(payload="<svg/onload=alert('xssm_1a2b3c')>")
        y = report.build_nuclei_yaml([f], "http://t/s", META)
        matcher = y.split("words:")[1].split("matchers")[0]
        assert "alert('xssm_1a2b3c')" in matcher
        assert "XSSENTINEL" not in matcher

    def test_post_template_keeps_csrf_fields_in_body(self):
        f = _f(param="comment", method="POST", url="http://t/p",
               payload="<img src=x onerror=alert('xssm_2f4d')>")
        f["csrf_fields"] = {"csrf_token": "abc123", "comment": "x"}
        y = report.build_nuclei_yaml([f], "http://t/p", META)
        assert "method: POST" in y
        assert "csrf_token=abc123&comment=" in y
        assert "<img src=x onerror=alert('xssm_2f4d')>" in y

    def test_upload_raw_multipart_is_server_parseable(self):
        # A raw template that a real app cannot parse would silently do
        # nothing on replay.  Parse it with Python's email multipart engine
        # (same semantics as werkzeug/cgi) and require the filename + body
        # to come back intact.
        f = _f(ftype="upload_xss", param="file[filename]", method="POST",
               url="http://t/up",
               payload="<svg/onload=alert('xssup_9e8d7c')>")
        y = report.build_nuclei_yaml([f], "http://t/up", META)
        assert 'name="file"' in y  # file[filename] collapses to the field
        assert "filename=\"<svg/onload=alert('xssup_9e8d7c')>\"" in y
        raw = _raw_block(y)
        assert raw.startswith("POST /up HTTP/1.1")
        ctype = [ln for ln in raw.split("\r\n")
                 if ln.lower().startswith("content-type")]
        boundary = ctype[0].split("boundary=")[1]
        # header boundary and body delimiters must agree (--<boundary>)
        first = raw.split("\r\n\r\n", 1)[1].split("\r\n", 1)[0]
        assert first == "--" + boundary
        body = raw.split("\r\n\r\n", 1)[1].encode("utf-8")
        # The email engine applies the same delimiter semantics as
        # werkzeug/cgi: the part content must come back intact.  (The
        # weaponised filename is asserted verbatim on the raw header line
        # below -- email's header decoder drops a leading '<'.)
        mime = email.message_from_bytes(
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/form-data; boundary="
            + boundary.encode() + b"\r\n\r\n" + body)
        parts = [p for p in mime.walk() if p.get_filename()]
        assert len(parts) == 1
        assert parts[0].get_payload(decode=True) == b"xssentinel upload probe"
        disp = [ln for ln in raw.split("\r\n")
                if ln.lower().startswith("content-disposition")][0]
        assert 'name="file"' in disp
        assert "filename=\"<svg/onload=alert('xssup_9e8d7c')>\"" in disp

    def test_upload_content_length_matches_body_bytes(self):
        f = _f(ftype="upload_xss", param="file[filename]", method="POST",
               url="http://t/up",
               payload="<svg/onload=alert('xssup_9e8d7c')>")
        raw = _raw_block(report.build_nuclei_yaml([f], "http://t/up", META))
        body = raw.split("\r\n\r\n", 1)[1].encode("utf-8")
        cl = [ln for ln in raw.split("\r\n")
              if ln.lower().startswith("content-length:")][0]
        assert cl == f"Content-Length: {len(body)}"

    def test_blind_finding_is_documentation_only(self):
        # Blind XSS cannot be re-verified with an in-band HTTP matcher, so
        # the template carries full info metadata (incl. the oob tag) but NO
        # request block -- it can never produce a false positive when run.
        f = _f(ftype="blind", url="http://t/b?q=x")
        y = report.build_nuclei_yaml([f], "http://t/b", META)
        assert "tags: xss,xssentinel,oob" in y
        assert "http:" not in y
        assert "matchers" not in y

    def test_cors_finding_is_documentation_only(self):
        # Phase 51: the CORS confirmation lives in response HEADERS, which a
        # body-word matcher cannot re-verify -- the template is doc-only and
        # tagged cors so a re-run never false-positives.
        f = _f(ftype="cors_misconfig", url="http://t/api?x=1")
        y = report.build_nuclei_yaml([f], "http://t/api", META)
        assert "tags: xss,xssentinel,cors" in y
        assert "http:" not in y
        assert "matchers" not in y

    def test_xs_leak_finding_is_documentation_only(self):
        # Phase 53: the XS-Leaks surface is a header-audit finding -- no body
        # matcher can re-verify it; the template is doc-only tagged xsleak.
        f = _f(ftype="xs_leak_surface", url="http://t/page")
        y = report.build_nuclei_yaml([f], "http://t/page", META)
        assert "tags: xss,xssentinel,xsleak" in y
        assert "http:" not in y
        assert "matchers" not in y

    # -- Phase 55: non-query replays (header/cookie/path findings) ---------
    def test_header_xss_replayed_via_request_header(self):
        # Phase 55: a (header:X) finding must carry the payload in that
        # header on the raw request -- NOT injected into a query parameter
        # (the old export could never match a header echo).
        f = _f(ftype="header_xss", url="http://t/s?x=1", param="(header:User-Agent)",
               payload="<svg/onload=alert('xsshd_a1b2c3')>")
        y = report.build_nuclei_yaml([f], "http://t/s", META)
        assert "User-Agent: <svg/onload=alert('xsshd_a1b2c3')>" in y
        assert "raw:" in y and "Host: {{Hostname}}" in y
        # request target keeps the real path/query, payload is NOT in query
        assert "/s?x=1" in y
        assert "xsshd_a1b2c3" in y.split("words:")[1]  # matcher exact payload
        assert "?%28header" not in y and "(header" not in y.split("raw")[1].split("matchers")[0]

    def test_cookie_xss_replayed_via_cookie(self):
        f = _f(ftype="cookie_xss", url="http://t/a", param="(cookie:sid)",
               payload="<svg/onload=alert('xsck_9f8e')>")
        y = report.build_nuclei_yaml([f], "http://t/a", META)
        assert "Cookie: sid=<svg/onload=alert('xsck_9f8e')>" in y
        assert "xsck_9f8e" in y.split("words:")[1]

    def test_path_xss_uses_percent_encoded_path(self):
        # Path replay percent-encodes the payload segment the way the wire
        # did (RFC sub-delims stay raw); the matcher still looks for the
        # decoded payload the server echoes back.
        f = _f(ftype="path_xss", param="(path)",
               url="http://t/p/<svg/onload=alert('xspath_bb')>",
               payload="<svg/onload=alert('xspath_bb')>")
        y = report.build_nuclei_yaml([f], "http://t", META)
        assert "GET /p/%3Csvg/onload=alert('xspath_bb')%3E HTTP/1.1" in y
        assert "xspath_bb" in y.split("words:")[1]
        assert "http:" in y  # runnable, not doc-only
        assert "matchers" in y

    def test_deterministic_output(self):
        a = report.build_nuclei_yaml([_f(), _f(ftype="stored")], "http://t", META)
        b = report.build_nuclei_yaml([_f(), _f(ftype="stored")], "http://t", META)
        assert a == b

    def test_empty_findings_empty_text(self):
        assert report.build_nuclei_yaml([], "http://t", META) == ""


class TestWriteNucleiDir:
    def test_one_file_per_finding(self, tmp_path):
        out = str(tmp_path / "templates")
        paths = report.write_nuclei_dir(
            [_f(), _f(ftype="stored", url="http://t/x")], "http://t", META, out)
        assert len(paths) == 2 and os.path.isdir(out)
        assert all(os.path.isfile(p) for p in paths)
        assert all(open(p, encoding="utf-8").read().startswith("id: ")
                   for p in paths)

    def test_identical_findings_dedup_filenames(self, tmp_path):
        out = str(tmp_path / "t")
        f = _f()
        paths = report.write_nuclei_dir([f, f], "http://t", META, out)
        names = sorted(os.path.basename(p) for p in paths)
        # same template id -> second file gets a -2 suffix so neither
        # template silently overwrites the other
        assert len(names) == 2 and names[0] != names[1]
        assert "-2" in names[1]

    def test_empty_findings_writes_nothing(self, tmp_path):
        out = str(tmp_path / "empty")
        assert report.write_nuclei_dir([], "http://t", META, out) == []
        assert os.path.isdir(out)
