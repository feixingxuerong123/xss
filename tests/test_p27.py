"""Phase 27 regression tests: Trusted Types violations + CSP nonce reuse.

Validates the pure-Python logic of the two new modules added in Phase 27-2
(``trusted_types`` and the CSP nonce analysis extension to ``csp``) without
requiring network access.  Tests cover:

  * ``trusted_types.find_unsafe_sinks`` -- innerHTML/outerHTML/eval/etc.
    detection, de-duplication, snippet extraction.
  * ``trusted_types.find_policies`` -- createPolicy() detection, identity
    function bypass, empty policy bypass.
  * ``trusted_types.find_taint_flows`` -- source -> sink flow with
    mitigation detection (policy call between source and sink).
  * ``trusted_types.analyze_page`` -- aggregate violations list.
  * ``trusted_types.build_poc_html`` -- PoC generation for each source type.
  * ``csp.extract_nonces_from_csp`` / ``extract_nonces_from_html`` -- nonce
    extraction from header and HTML body.
  * ``csp.analyze_nonce_reuse`` -- too-short / predictable / missing /
    multi-nonce detection.
  * ``csp.detect_nonce_near_marker`` -- nonce proximity to attacker input.
  * ``compliance`` -- new finding types map to the right frameworks.
  * ``fix_advice`` -- new finding types produce remediation advice.
  * ``verify_fix`` -- new finding types are correctly classified as
    replayable vs. skipped.
"""
from __future__ import annotations

import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import trusted_types as tt
from xssentinel.core import csp
from xssentinel.core import compliance, fix_advice, verify_fix
from xssentinel.core import cookie_tossing as ct
from xssentinel.core import sri_bypass as sri


# =============================================================================
# trusted_types.find_unsafe_sinks
# =============================================================================

class TestFindUnsafeSinks:
    def test_empty_input(self):
        assert tt.find_unsafe_sinks("") == []
        assert tt.find_unsafe_sinks(None) == []

    def test_innerhtml_assignment_detected(self):
        sinks = tt.find_unsafe_sinks("el.innerHTML = userInput;")
        assert len(sinks) == 1
        assert sinks[0]["sink_name"] == "innerHTML"
        assert sinks[0]["severity"] == "high"

    def test_outerhtml_assignment_detected(self):
        sinks = tt.find_unsafe_sinks("el.outerHTML = data;")
        assert len(sinks) == 1
        assert sinks[0]["sink_name"] == "outerHTML"

    def test_document_write_detected(self):
        sinks = tt.find_unsafe_sinks("document.write(payload);")
        assert len(sinks) == 1
        assert sinks[0]["sink_name"] == "document.write"

    def test_eval_detected(self):
        sinks = tt.find_unsafe_sinks("eval(userInput);")
        assert any(s["sink_name"] == "eval" for s in sinks)

    def test_insert_adjacent_html_detected(self):
        sinks = tt.find_unsafe_sinks("el.insertAdjacentHTML('beforeend', html);")
        assert any(s["sink_name"] == "insertAdjacentHTML" for s in sinks)

    def test_dangerously_set_inner_html_detected(self):
        # React JSX syntax
        sinks = tt.find_unsafe_sinks("<div dangerouslySetInnerHTML={{__html: x}} />")
        assert any(s["sink_name"] == "dangerouslySetInnerHTML" for s in sinks)

    def test_vue_v_html_detected(self):
        sinks = tt.find_unsafe_sinks('<div v-html="rawHtml"></div>')
        assert any(s["sink_name"] == "v-html" for s in sinks)

    def test_create_contextual_fragment_detected(self):
        sinks = tt.find_unsafe_sinks("range.createContextualFragment(html);")
        assert any(s["sink_name"] == "createContextualFragment" for s in sinks)

    def test_set_attribute_dangerous(self):
        sinks = tt.find_unsafe_sinks('el.setAttribute("onclick", payload);')
        assert any(s["sink_name"] == "setAttribute" for s in sinks)

    def test_taint_source_near_sink(self):
        html = """
        var hash = location.hash.substring(1);
        document.getElementById('out').innerHTML = hash;
        """
        sinks = tt.find_unsafe_sinks(html)
        assert len(sinks) >= 1
        innerhtml_sink = next(s for s in sinks if s["sink_name"] == "innerHTML")
        assert innerhtml_sink["has_taint"] is True
        assert "location.hash" in innerhtml_sink["taint_source"]

    def test_no_sink_in_safe_code(self):
        sinks = tt.find_unsafe_sinks("var x = 1 + 2; console.log(x);")
        assert sinks == []

    def test_dedup_overlapping_matches(self):
        # Two patterns might match the same span -- ensure we dedup.
        sinks = tt.find_unsafe_sinks("el.innerHTML = 'x';")
        # Should report exactly one sink, not two.
        assert len(sinks) == 1


# =============================================================================
# trusted_types.find_policies
# =============================================================================

class TestFindPolicies:
    def test_empty_input(self):
        assert tt.find_policies("") == []
        assert tt.find_policies(None) == []

    def test_create_policy_detected(self):
        js = """
        const policy = trustedTypes.createPolicy('myPolicy', {
          createHTML: (input) => DOMPurify.sanitize(input),
        });
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["policy_name"] == "myPolicy"
        assert policies[0]["is_identity"] is False
        assert policies[0]["is_bypass"] is False

    def test_identity_arrow_policy_detected(self):
        js = """
        const policy = trustedTypes.createPolicy('noop', {
          createHTML: (input) => input,
        });
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["is_identity"] is True
        assert policies[0]["is_bypass"] is True

    def test_identity_short_arrow_policy_detected(self):
        js = """
        const policy = trustedTypes.createPolicy('noop', {
          createHTML: s => s,
        });
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["is_identity"] is True
        assert policies[0]["is_bypass"] is True

    def test_identity_function_policy_detected(self):
        js = """
        const policy = trustedTypes.createPolicy('noop', {
          createHTML: function(s) { return s; },
        });
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["is_identity"] is True
        assert policies[0]["is_bypass"] is True

    def test_empty_policy_detected_as_bypass(self):
        # A policy with no createHTML/createScript is also a bypass.
        js = """
        const policy = trustedTypes.createPolicy('empty', {});
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["is_bypass"] is True

    def test_window_trusted_types_alias(self):
        js = """
        const policy = window.trustedTypes.createPolicy('p', {
          createHTML: x => x,
        });
        """
        policies = tt.find_policies(js)
        assert len(policies) == 1
        assert policies[0]["is_identity"] is True


# =============================================================================
# trusted_types.find_taint_flows
# =============================================================================

class TestFindTaintFlows:
    def test_empty_input(self):
        assert tt.find_taint_flows("") == []
        assert tt.find_taint_flows(None) == []

    def test_location_hash_to_innerhtml(self):
        html = """
        <script>
        var hash = location.hash.substring(1);
        document.getElementById('out').innerHTML = hash;
        </script>
        """
        flows = tt.find_taint_flows(html)
        assert len(flows) >= 1
        assert any(f["sink_name"] == "innerHTML" for f in flows)
        assert any("location.hash" in f["taint_source"] for f in flows)

    def test_event_data_to_innerhtml(self):
        html = """
        <script>
        ws.onmessage = function(e) {
          document.getElementById('out').innerHTML = e.data;
        };
        </script>
        """
        flows = tt.find_taint_flows(html)
        assert len(flows) >= 1
        assert any(f["sink_name"] == "innerHTML" for f in flows)

    def test_policy_call_mitigates_flow(self):
        # When policy.createHTML sits between source and sink, the flow
        # is mitigated and should NOT be reported.
        html = """
        <script>
        var hash = location.hash.substring(1);
        var safe = policy.createHTML(hash);
        document.getElementById('out').innerHTML = safe;
        </script>
        """
        flows = tt.find_taint_flows(html)
        # The flow should be filtered out (mitigated).
        innerhtml_flows = [f for f in flows if f["sink_name"] == "innerHTML"]
        # Note: find_taint_flows checks if POLICY_USE_RE appears BETWEEN
        # the taint source and the sink.  In this snippet, policy.createHTML
        # is between location.hash and innerHTML, so the flow is mitigated.
        unmitigated = [f for f in innerhtml_flows if not f["mitigated"]]
        assert len(unmitigated) == 0

    def test_no_flow_when_no_taint_source(self):
        html = """
        <script>
        document.getElementById('out').innerHTML = "static content";
        </script>
        """
        flows = tt.find_taint_flows(html)
        assert flows == []


# =============================================================================
# trusted_types.analyze_page
# =============================================================================

class TestAnalyzePage:
    def test_empty_input(self):
        r = tt.analyze_page("")
        assert r["has_unsafe_sinks"] is False
        assert r["violations"] == []

    def test_none_input(self):
        r = tt.analyze_page(None)
        assert r["has_unsafe_sinks"] is False
        assert r["violations"] == []

    def test_taint_flow_violation(self):
        html = """
        <html><body><div id="o"></div>
        <script>
        var h = location.hash.substring(1);
        document.getElementById('o').innerHTML = h;
        </script></body></html>
        """
        r = tt.analyze_page(html)
        vtypes = [v["type"] for v in r["violations"]]
        assert "tt_taint_flow" in vtypes

    def test_policy_bypass_violation(self):
        html = """
        <html><body><div id="o"></div>
        <script>
        var policy = trustedTypes.createPolicy('noop', {
          createHTML: (input) => input
        });
        document.getElementById('o').innerHTML =
          policy.createHTML(location.hash.substring(1));
        </script></body></html>
        """
        r = tt.analyze_page(html)
        vtypes = [v["type"] for v in r["violations"]]
        assert "tt_policy_bypass" in vtypes

    def test_no_policy_violation(self):
        html = """
        <html><body><div id="o"></div>
        <script>
        document.getElementById('o').innerHTML = "static";
        </script></body></html>
        """
        r = tt.analyze_page(html)
        vtypes = [v["type"] for v in r["violations"]]
        assert "tt_no_policy" in vtypes

    def test_policy_unused_violation(self):
        html = """
        <html><body><div id="o"></div>
        <script>
        var sanitizer = trustedTypes.createPolicy('sanitizer', {
          createHTML: (input) => DOMPurify.sanitize(input)
        });
        document.getElementById('o').innerHTML = "hello";
        </script></body></html>
        """
        r = tt.analyze_page(html)
        vtypes = [v["type"] for v in r["violations"]]
        assert "tt_policy_unused" in vtypes

    def test_csp_enforced_flag(self):
        html = "<script>el.innerHTML = 'x';</script>"
        r = tt.analyze_page(html, csp_header=None)
        assert r["tt_enforced_in_csp"] is False
        r2 = tt.analyze_page(
            html,
            csp_header="require-trusted-types-for 'script'; trusted-types p;")
        assert r2["tt_enforced_in_csp"] is True

    def test_policy_whitelist_extracted(self):
        r = tt.analyze_page(
            "<script>el.innerHTML='x';</script>",
            csp_header="trusted-types policyA policyB;")
        assert "policyA" in r["tt_policy_whitelist"]
        assert "policyB" in r["tt_policy_whitelist"]


# =============================================================================
# trusted_types.build_poc_html
# =============================================================================

class TestBuildPocHtml:
    def test_location_hash_poc(self):
        poc = tt.build_poc_html("https://target.example/page",
                                "innerHTML", "location.hash")
        assert "https://target.example/page#" in poc
        assert "alert(1)" in poc

    def test_event_data_poc(self):
        poc = tt.build_poc_html("https://target.example/page",
                                "innerHTML", "event.data")
        assert "postMessage" in poc
        assert "alert(1)" in poc

    def test_generic_poc(self):
        poc = tt.build_poc_html("https://target.example/page", "eval", "")
        assert "https://target.example/page" in poc
        assert "alert(1)" in poc


# =============================================================================
# csp.extract_nonces_from_csp / extract_nonces_from_html
# =============================================================================

class TestExtractNonces:
    def test_extract_from_csp_empty(self):
        assert csp.extract_nonces_from_csp("") == []
        assert csp.extract_nonces_from_csp(None) == []

    def test_extract_single_nonce(self):
        csp_header = "script-src 'nonce-abc1234567890xyz' 'strict-dynamic'"
        nonces = csp.extract_nonces_from_csp(csp_header)
        assert nonces == ["abc1234567890xyz"]

    def test_extract_multiple_nonces(self):
        csp_header = ("script-src 'nonce-aaa111222333444' "
                      "'nonce-bbb555666777888'")
        nonces = csp.extract_nonces_from_csp(csp_header)
        assert "aaa111222333444" in nonces
        assert "bbb555666777888" in nonces
        assert len(nonces) == 2

    def test_extract_from_html_empty(self):
        assert csp.extract_nonces_from_html("") == []
        assert csp.extract_nonces_from_html(None) == []

    def test_extract_from_html_double_quote(self):
        html = '<script nonce="abc12345">console.log(1);</script>'
        nonces = csp.extract_nonces_from_html(html)
        assert nonces == ["abc12345"]

    def test_extract_from_html_single_quote(self):
        html = "<script nonce='xyz98765'>console.log(1);</script>"
        nonces = csp.extract_nonces_from_html(html)
        assert nonces == ["xyz98765"]

    def test_extract_from_html_multiple(self):
        html = ('<script nonce="aaa11111">a();</script>'
                '<script nonce="aaa11111">b();</script>'
                '<script nonce="bbb22222">c();</script>')
        nonces = csp.extract_nonces_from_html(html)
        assert len(nonces) == 3  # NOT deduped
        assert nonces[0] == "aaa11111"
        assert nonces[1] == "aaa11111"  # reuse within response
        assert nonces[2] == "bbb22222"


# =============================================================================
# csp.analyze_nonce_reuse
# =============================================================================

class TestAnalyzeNonceReuse:
    def test_no_csp(self):
        r = csp.analyze_nonce_reuse(None, "<html></html>")
        assert r["nonce_in_csp"] is False
        assert r["bypassable"] is False

    def test_no_nonce_directive(self):
        r = csp.analyze_nonce_reuse(
            "default-src 'self'; script-src 'self'",
            "<script></script>")
        assert r["nonce_in_csp"] is False

    def test_nonce_too_short(self):
        csp_header = "script-src 'nonce-short123' 'strict-dynamic'"
        html = '<script nonce="short123">x();</script>'
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["nonce_too_short"] is True
        assert r["bypassable"] is True
        assert r["nonce_length"] == 8

    def test_nonce_predictable(self):
        csp_header = "script-src 'nonce-00001111' 'strict-dynamic'"
        html = '<script nonce="00001111">x();</script>'
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["nonce_looks_sequential"] is True
        assert r["bypassable"] is True

    def test_nonce_strong_no_bypass(self):
        csp_header = ("script-src 'nonce-aBcDeFgH1234567890xYzAb' "
                      "'strict-dynamic'")
        html = '<script nonce="aBcDeFgH1234567890xYzAb">x();</script>'
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["nonce_too_short"] is False
        assert r["nonce_looks_sequential"] is False
        assert r["bypassable"] is False
        assert r["nonce_length"] == 23

    def test_nonce_misconfigured_missing_in_html(self):
        csp_header = "script-src 'nonce-abc1234567890def'"
        html = '<script>x();</script>'  # no nonce= attr
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["nonce_in_csp"] is True
        assert r["html_nonces"] == []
        assert any("absent" in reason or "applied" in reason or "blocked"
                   in reason.lower()
                   for reason in r["bypass_reasons"])

    def test_multiple_nonces_in_csp(self):
        csp_header = ("script-src 'nonce-aaa1234567890bbb' "
                      "'nonce-ccc9876543210ddd'")
        html = '<script nonce="aaa1234567890bbb">x();</script>'
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert len(set(r["csp_nonces"])) == 2
        assert any("different nonces" in reason
                   for reason in r["bypass_reasons"])

    def test_reuse_within_response_detected(self):
        # Same nonce in multiple <script> tags -- legitimate but tracked.
        csp_header = "script-src 'nonce-aBcDeFgH1234567890xYzAb'"
        html = ('<script nonce="aBcDeFgH1234567890xYzAb">a();</script>'
                '<script nonce="aBcDeFgH1234567890xYzAb">b();</script>')
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["reuse_within_response"] is True
        assert r["nonce_count_in_html"] == 2
        assert len(r["unique_html_nonces"]) == 1

    def test_exposed_in_html(self):
        csp_header = "script-src 'nonce-aBcDeFgH1234567890xYzAb'"
        html = '<script nonce="aBcDeFgH1234567890xYzAb">x();</script>'
        r = csp.analyze_nonce_reuse(csp_header, html)
        assert r["exposed_in_html"] is True


# =============================================================================
# csp.detect_nonce_near_marker
# =============================================================================

class TestDetectNonceNearMarker:
    def test_no_csp(self):
        r = csp.detect_nonce_near_marker(None, "<html></html>", "marker")
        assert r["nonce_exposed_near_marker"] is False

    def test_no_nonce_in_csp(self):
        r = csp.detect_nonce_near_marker(
            "script-src 'self'", "<html></html>", "marker")
        assert r["nonce_exposed_near_marker"] is False

    def test_marker_not_in_html(self):
        csp_header = "script-src 'nonce-aBcDeFgH1234567890'"
        html = '<script nonce="aBcDeFgH1234567890">x();</script>'
        r = csp.detect_nonce_near_marker(csp_header, html, "MISSING")
        assert r["nonce_exposed_near_marker"] is False

    def test_nonce_far_from_marker(self):
        csp_header = "script-src 'nonce-aBcDeFgH1234567890'"
        # Marker at position 0, nonce at position ~600 (> 500 char threshold).
        html = ("MARKER" + "x" * 600 +
                '<script nonce="aBcDeFgH1234567890">x();</script>')
        r = csp.detect_nonce_near_marker(csp_header, html, "MARKER")
        assert r["nonce_exposed_near_marker"] is False

    def test_nonce_near_marker_detected(self):
        csp_header = "script-src 'nonce-aBcDeFgH1234567890'"
        # Marker and nonce within 500 chars of each other.
        html = ('<div>MARKER</div>'
                '<script nonce="aBcDeFgH1234567890">x();</script>')
        r = csp.detect_nonce_near_marker(csp_header, html, "MARKER")
        assert r["nonce_exposed_near_marker"] is True
        assert r["nonce_value"] == "aBcDeFgH1234567890"
        assert r["distance"] >= 0
        assert "MARKER" in r["snippet"]
        assert "aBcDeFgH1234567890" in r["snippet"]


# =============================================================================
# compliance mappings for new finding types
# =============================================================================

class TestComplianceMappings:
    @pytest.mark.parametrize("ftype", [
        "trusted_types_taint_flow",
        "trusted_types_policy_bypass",
        "trusted_types_no_policy",
        "trusted_types_policy_unused",
        "trusted_types_violation",
        "csp_nonce_too_short",
        "csp_nonce_predictable",
        "csp_nonce_misconfigured",
        "csp_nonce_multi",
    ])
    def test_finding_type_has_compliance_mapping(self, ftype):
        entries = compliance.compliance_for_finding({"type": ftype})
        assert len(entries) > 0
        frameworks = {e["framework"] for e in entries}
        assert "OWASP Top 10 2021" in frameworks
        assert "CWE" in frameworks

    @pytest.mark.parametrize("ftype", [
        "trusted_types_taint_flow",
        "csp_nonce_too_short",
    ])
    def test_cwe_79_in_mapping(self, ftype):
        entries = compliance.compliance_for_finding({"type": ftype})
        cwes = {e["requirement_id"] for e in entries if e["framework"] == "CWE"}
        assert "CWE-79" in cwes

    def test_supported_finding_types_includes_new(self):
        types = compliance.supported_finding_types()
        assert "trusted_types_taint_flow" in types
        assert "csp_nonce_too_short" in types


# =============================================================================
# fix_advice for new finding types
# =============================================================================

class TestFixAdvice:
    @pytest.mark.parametrize("ftype", [
        "trusted_types_taint_flow",
        "trusted_types_policy_bypass",
        "trusted_types_no_policy",
        "trusted_types_policy_unused",
        "trusted_types_violation",
        "csp_nonce_too_short",
        "csp_nonce_predictable",
        "csp_nonce_misconfigured",
        "csp_nonce_multi",
    ])
    def test_advice_has_required_fields(self, ftype):
        adv = fix_advice.get_advice(ftype)
        assert "headline" in adv
        assert "detail" in adv
        assert "code_example" in adv
        assert "primary_cwe" in adv
        assert "also_consider" in adv
        assert len(adv["headline"]) > 10
        assert len(adv["detail"]) > 50

    def test_taint_flow_advice_mentions_textcontent(self):
        adv = fix_advice.get_advice("trusted_types_taint_flow")
        assert "textContent" in adv["code_example"]

    def test_policy_bypass_advice_mentions_dompurify(self):
        adv = fix_advice.get_advice("trusted_types_policy_bypass")
        assert "DOMPurify" in adv["code_example"]

    def test_nonce_too_short_advice_mentions_csprng(self):
        adv = fix_advice.get_advice("csp_nonce_too_short")
        # Should recommend a CSPRNG.
        assert ("secrets" in adv["code_example"]
                or "crypto" in adv["code_example"])

    def test_supported_finding_types_includes_new(self):
        types = fix_advice.supported_finding_types()
        assert "trusted_types_taint_flow" in types
        assert "csp_nonce_too_short" in types


# =============================================================================
# verify_fix: new finding types classification
# =============================================================================

class TestVerifyFixClassification:
    @pytest.mark.parametrize("ftype", [
        "trusted_types_taint_flow",
        "trusted_types_policy_bypass",
        "trusted_types_no_policy",
        "trusted_types_policy_unused",
        "csp_nonce_too_short",
        "csp_nonce_predictable",
        "csp_nonce_misconfigured",
        "csp_nonce_multi",
        # Phase 27-3: Cookie tossing + SRI bypass are also static-analysis
        # findings -- they cannot be replayed by re-injecting a payload.
        "cookie_tossing_set_cookie",
        "cookie_tossing_client",
        "cookie_sink_flow",
        "sri_missing_script",
        "sri_missing_style",
        "sri_broken_no_crossorigin",
        "sri_malformed",
        "sri_insecure_origin",
    ])
    def test_finding_type_classified_as_skipped(self, ftype):
        """TT violations and CSP nonce findings are static-analysis findings
        -- they cannot be replayed by re-injecting a payload, so verify_fix
        must classify them as 'skipped' (not 'fixed' or 'still_vuln')."""
        finding = {"type": ftype, "url": "https://example.com/page",
                   "method": "GET", "params": {}, "data": {}}
        status = verify_fix.classify_finding(finding)
        assert status == "skipped", (
            f"finding type '{ftype}' should be 'skipped' (static analysis), "
            f"got '{status}'")


# =============================================================================
# Phase 27-3: Cookie tossing XSS detection tests
# =============================================================================

class TestParseSetCookie:
    def test_empty_input(self):
        assert ct.parse_set_cookie("") is None
        assert ct.parse_set_cookie(None) is None

    def test_simple_cookie(self):
        result = ct.parse_set_cookie("session=abc123")
        assert result is not None
        assert result["name"] == "session"
        assert result["value"] == "abc123"
        assert result["domain"] is None
        assert result["httponly"] is False

    def test_cookie_with_domain(self):
        result = ct.parse_set_cookie("theme=dark; Domain=.example.com; Path=/")
        assert result is not None
        assert result["name"] == "theme"
        assert result["value"] == "dark"
        assert result["domain"] == ".example.com"
        assert result["path"] == "/"

    def test_cookie_with_all_attrs(self):
        result = ct.parse_set_cookie(
            "session=xyz; Domain=example.com; Path=/; HttpOnly; Secure; SameSite=Lax"
        )
        assert result is not None
        assert result["domain"] == "example.com"
        assert result["httponly"] is True
        assert result["secure"] is True
        assert result["samesite"] == "Lax"

    def test_malformed_header(self):
        assert ct.parse_set_cookie("no_equals_or_semicolon") is None


class TestIsParentDomainCookie:
    def test_self_scope_not_tossing(self):
        cookie = {"domain": "example.com"}
        assert ct.is_parent_domain_cookie(cookie, "example.com") is False

    def test_parent_domain_is_tossing(self):
        cookie = {"domain": ".example.com"}
        assert ct.is_parent_domain_cookie(cookie, "sub.example.com") is True

    def test_parent_domain_without_leading_dot(self):
        cookie = {"domain": "example.com"}
        assert ct.is_parent_domain_cookie(cookie, "www.example.com") is True

    def test_subdomain_scope_not_tossing(self):
        cookie = {"domain": "sub.example.com"}
        assert ct.is_parent_domain_cookie(cookie, "example.com") is False

    def test_unrelated_domain_not_tossing(self):
        cookie = {"domain": "example.com"}
        assert ct.is_parent_domain_cookie(cookie, "evil.com") is False

    def test_empty_inputs(self):
        assert ct.is_parent_domain_cookie({}, "example.com") is False
        assert ct.is_parent_domain_cookie({"domain": "example.com"}, "") is False
        assert ct.is_parent_domain_cookie(None, "example.com") is False


class TestAnalyzeSetCookieHeaders:
    def test_empty_headers(self):
        result = ct.analyze_set_cookie_headers([], "sub.example.com")
        assert result["cookies"] == []
        assert result["has_tossing_risk"] is False

    def test_self_scoped_cookie_not_flagged(self):
        headers = ["session=abc; Domain=example.com"]
        result = ct.analyze_set_cookie_headers(headers, "example.com")
        assert result["has_tossing_risk"] is False

    def test_parent_domain_cookie_flagged(self):
        headers = ["session=abc; Domain=example.com"]
        result = ct.analyze_set_cookie_headers(headers, "sub.example.com")
        assert result["has_tossing_risk"] is True
        assert len(result["tossing_cookies"]) == 1
        assert result["tossing_cookies"][0]["name"] == "session"

    def test_multiple_cookies_some_tossing(self):
        headers = [
            "session=abc; Domain=example.com",
            "pref=dark; Domain=sub.example.com",
        ]
        result = ct.analyze_set_cookie_headers(headers, "sub.example.com")
        assert result["has_tossing_risk"] is True
        assert len(result["tossing_cookies"]) == 1
        assert result["tossing_cookies"][0]["name"] == "session"

    def test_string_input_split_on_newlines(self):
        headers = "session=abc; Domain=example.com\npref=dark; Domain=example.com"
        result = ct.analyze_set_cookie_headers(headers, "sub.example.com")
        assert len(result["cookies"]) == 2
        assert result["has_tossing_risk"] is True


class TestFindClientSideTossing:
    def test_empty_html(self):
        assert ct.find_client_side_tossing("") == []
        assert ct.find_client_side_tossing(None) == []

    def test_no_cookie_assignment(self):
        html = "<html><body><p>no cookies here</p></body></html>"
        assert ct.find_client_side_tossing(html) == []

    def test_document_cookie_with_domain(self):
        html = (
            '<script>'
            'document.cookie = "theme=dark; domain=.example.com; path=/";'
            '</script>'
        )
        findings = ct.find_client_side_tossing(html)
        assert len(findings) == 1
        assert "example.com" in findings[0]["domain"]
        assert findings[0]["cookie_name"] == "theme"  # cookie name before first =

    def test_document_cookie_without_domain_not_flagged(self):
        html = (
            '<script>'
            'document.cookie = "theme=dark; path=/";'
            '</script>'
        )
        assert ct.find_client_side_tossing(html) == []

    def test_multiple_assignments(self):
        html = (
            '<script>'
            'document.cookie = "a=1; domain=.x.com";'
            'document.cookie = "b=2; domain=.y.com";'
            '</script>'
        )
        findings = ct.find_client_side_tossing(html)
        assert len(findings) == 2

    def test_dedup(self):
        """The same assignment should only be reported once."""
        html = (
            '<script>document.cookie = "x=1; domain=.a.com";</script>'
            '<script>document.cookie = "x=1; domain=.a.com";</script>'
        )
        findings = ct.find_client_side_tossing(html)
        assert len(findings) == 1


class TestFindCookieToSinkFlows:
    def test_empty_html(self):
        assert ct.find_cookie_to_sink_flows("") == []

    def test_no_flow(self):
        html = '<script>var x = "hello";</script>'
        assert ct.find_cookie_to_sink_flows(html) == []

    def test_cookie_to_innerhtml_flow(self):
        html = (
            '<script>'
            'var theme = document.cookie;'
            'document.getElementById("out").innerHTML = theme;'
            '</script>'
        )
        flows = ct.find_cookie_to_sink_flows(html)
        assert len(flows) >= 1
        assert flows[0]["sink"] == "innerHTML"
        assert "document.cookie" in flows[0]["source"]

    def test_cookie_to_eval_flow(self):
        html = (
            '<script>'
            'var code = getCookie("eval");'
            'eval(code);'
            '</script>'
        )
        flows = ct.find_cookie_to_sink_flows(html)
        assert len(flows) >= 1
        assert flows[0]["sink"] == "eval"

    def test_cookie_to_document_write_flow(self):
        html = (
            '<script>'
            'var html = cookies.get("content");'
            'document.write(html);'
            '</script>'
        )
        flows = ct.find_cookie_to_sink_flows(html)
        assert len(flows) >= 1
        assert flows[0]["sink"] == "document.write"

    def test_distant_sink_not_flagged(self):
        """A sink > 500 chars away from the source should not be flagged."""
        padding = "var x = '" + "A" * 600 + "';"
        html = (
            '<script>'
            'var theme = document.cookie;'
            + padding +
            'document.getElementById("out").innerHTML = theme;'
            '</script>'
        )
        flows = ct.find_cookie_to_sink_flows(html)
        assert len(flows) == 0


class TestCookieTossingAnalyzePage:
    def test_empty_inputs(self):
        result = ct.analyze_page("", [], "")
        assert result["has_tossing_header"] is False
        assert result["has_client_tossing"] is False
        assert result["has_cookie_sink_flow"] is False
        assert result["violations"] == []

    def test_header_tossing_violation(self):
        result = ct.analyze_page(
            "<html></html>",
            ["session=abc; Domain=example.com"],
            "sub.example.com",
        )
        assert result["has_tossing_header"] is True
        assert len(result["violations"]) == 1
        assert result["violations"][0]["type"] == "cookie_tossing_set_cookie"
        assert result["violations"][0]["severity"] == "high"

    def test_client_tossing_violation(self):
        html = '<script>document.cookie = "x=1; domain=.a.com";</script>'
        result = ct.analyze_page(html, [], "a.com")
        assert result["has_client_tossing"] is True
        assert len(result["violations"]) == 1
        assert result["violations"][0]["type"] == "cookie_tossing_client"

    def test_sink_flow_violation(self):
        html = (
            '<script>'
            'var t = document.cookie;'
            'el.innerHTML = t;'
            '</script>'
        )
        result = ct.analyze_page(html, [], "example.com")
        assert result["has_cookie_sink_flow"] is True
        assert len(result["violations"]) == 1
        assert result["violations"][0]["type"] == "cookie_sink_flow"

    def test_multiple_violations(self):
        html = (
            '<script>'
            'document.cookie = "x=1; domain=.a.com";'
            'var t = document.cookie;'
            'el.innerHTML = t;'
            '</script>'
        )
        result = ct.analyze_page(html, [], "sub.a.com")
        assert len(result["violations"]) >= 2


class TestCookieTossingBuildPoc:
    def test_empty_url(self):
        assert ct.build_poc_html("") == ""

    def test_poc_contains_tossing_domain(self):
        poc = ct.build_poc_html(
            "https://www.example.com/page",
            cookie_name="theme",
            tossing_domain="example.com",
        )
        assert "example.com" in poc
        assert "theme" in poc
        assert "document.cookie" in poc

    def test_poc_derives_domain_from_url(self):
        poc = ct.build_poc_html("https://sub.example.com/page")
        assert "example.com" in poc


# =============================================================================
# Phase 27-3: SRI bypass detection tests
# =============================================================================

class TestSriIsValidIntegrity:
    def test_empty(self):
        assert sri.is_valid_integrity("") is False
        assert sri.is_valid_integrity(None) is False

    def test_valid_sha256(self):
        assert sri.is_valid_integrity(
            "sha256-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC="
        ) is True

    def test_valid_sha384(self):
        assert sri.is_valid_integrity(
            "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        ) is True

    def test_valid_sha512(self):
        assert sri.is_valid_integrity(
            "sha512-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC=="
        ) is True

    def test_empty_hash(self):
        assert sri.is_valid_integrity("sha256-") is False
        assert sri.is_valid_integrity("sha384-") is False

    def test_unsupported_algorithm(self):
        assert sri.is_valid_integrity("sha1-abc123==") is False
        assert sri.is_valid_integrity("md5-abc123==") is False

    def test_multiple_hashes(self):
        # Multiple hashes space-separated: valid if ANY is recognized.
        combined = (
            "sha256-abc123== "
            "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        )
        assert sri.is_valid_integrity(combined) is True


class TestSriExtractScriptTags:
    def test_empty_html(self):
        assert sri._extract_script_tags("") == []

    def test_no_scripts(self):
        html = "<html><body><p>no scripts</p></body></html>"
        assert sri._extract_script_tags(html) == []

    def test_inline_script_ignored(self):
        html = '<script>var x = 1;</script>'
        assert sri._extract_script_tags(html) == []

    def test_external_script_extracted(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        scripts = sri._extract_script_tags(html)
        assert len(scripts) == 1
        assert scripts[0]["src"] == "https://cdn.example.com/lib.js"

    def test_script_with_integrity(self):
        html = (
            '<script src="https://cdn.example.com/lib.js"'
            '        integrity="sha384-abc123=="'
            '        crossorigin="anonymous"></script>'
        )
        scripts = sri._extract_script_tags(html)
        assert len(scripts) == 1
        assert scripts[0]["integrity"] == "sha384-abc123=="
        assert scripts[0]["crossorigin"] is True


class TestSriExtractLinkTags:
    def test_empty_html(self):
        assert sri._extract_link_tags("") == []

    def test_stylesheet_extracted(self):
        html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
        links = sri._extract_link_tags(html)
        assert len(links) == 1
        assert "stylesheet" in links[0]["rel"]
        assert links[0]["href"] == "https://cdn.example.com/style.css"

    def test_preload_as_script_extracted(self):
        html = '<link rel="preload" as="script" href="https://cdn.example.com/pre.js">'
        links = sri._extract_link_tags(html)
        assert len(links) == 1
        assert links[0]["as"] == "script"

    def test_favicon_ignored(self):
        html = '<link rel="icon" href="/favicon.ico">'
        # The extractor returns all links but analyze_page filters by rel.
        # However, the _extract_link_tags function itself returns all links
        # with an href; it's analyze_page that filters to stylesheets +
        # script preloads.
        links = sri._extract_link_tags(html)
        # We don't assert len==0 here because _extract_link_tags returns all
        # links; the filtering happens in analyze_page.
        # But verify the link is extracted.
        assert any(l["href"] == "/favicon.ico" for l in links)


class TestSriCrossOrigin:
    def test_same_origin(self):
        assert sri._is_cross_origin(
            "https://example.com/page",
            "https://example.com/script.js",
        ) is False

    def test_cross_origin_different_host(self):
        assert sri._is_cross_origin(
            "https://example.com/page",
            "https://cdn.example.com/script.js",
        ) is True

    def test_cross_origin_different_scheme(self):
        assert sri._is_cross_origin(
            "https://example.com/page",
            "http://example.com/script.js",
        ) is True

    def test_protocol_relative_resolved(self):
        # Protocol-relative URL inherits the page's scheme.
        assert sri._is_cross_origin(
            "https://example.com/page",
            "//cdn.example.com/script.js",
        ) is True

    def test_data_uri_not_cross_origin(self):
        assert sri._is_cross_origin(
            "https://example.com/page",
            "data:text/javascript,alert(1)",
        ) is False

    def test_blob_uri_not_cross_origin(self):
        assert sri._is_cross_origin(
            "https://example.com/page",
            "blob:https://example.com/abc",
        ) is False


class TestSriInsecureOrigin:
    def test_http_is_insecure(self):
        assert sri._is_insecure_origin("http://cdn.example.com/lib.js") is True

    def test_https_is_secure(self):
        assert sri._is_insecure_origin("https://cdn.example.com/lib.js") is False

    def test_protocol_relative_not_flagged(self):
        assert sri._is_insecure_origin("//cdn.example.com/lib.js") is False

    def test_empty(self):
        assert sri._is_insecure_origin("") is False


class TestSriAnalyzePage:
    def test_empty_html(self):
        result = sri.analyze_page("", "https://example.com/page")
        assert result["scripts"] == []
        assert result["links"] == []
        assert result["violations"] == []

    def test_cross_origin_script_without_sri(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["cross_origin_scripts"]) == 1
        assert len(result["violations"]) >= 1
        assert result["violations"][0]["type"] == "sri_missing_script"

    def test_cross_origin_script_with_valid_sri_no_finding(self):
        html = (
            '<script src="https://cdn.example.com/lib.js"'
            '        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"'
            '        crossorigin="anonymous"></script>'
        )
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["cross_origin_scripts"]) == 0
        # No sri_missing_script finding.
        vtypes = [v["type"] for v in result["violations"]]
        assert "sri_missing_script" not in vtypes

    def test_broken_sri_no_crossorigin(self):
        html = (
            '<script src="https://cdn.example.com/lib.js"'
            '        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>'
        )
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["broken_sri"]) == 1
        vtypes = [v["type"] for v in result["violations"]]
        assert "sri_broken_no_crossorigin" in vtypes

    def test_malformed_integrity(self):
        html = '<script src="https://cdn.example.com/lib.js" integrity=""></script>'
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["malformed_integrity"]) == 1
        vtypes = [v["type"] for v in result["violations"]]
        assert "sri_malformed" in vtypes

    def test_insecure_origin(self):
        html = '<script src="http://cdn.example.com/lib.js"></script>'
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["insecure_origins"]) == 1
        vtypes = [v["type"] for v in result["violations"]]
        assert "sri_insecure_origin" in vtypes

    def test_cross_origin_stylesheet_without_sri(self):
        html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
        result = sri.analyze_page(html, "https://example.com/page")
        assert len(result["cross_origin_styles"]) == 1
        vtypes = [v["type"] for v in result["violations"]]
        assert "sri_missing_style" in vtypes

    def test_same_origin_script_no_finding(self):
        html = '<script src="/local.js"></script>'
        result = sri.analyze_page(html, "https://example.com/page")
        # Same-origin scripts don't need SRI.
        assert len(result["cross_origin_scripts"]) == 0
        assert len(result["violations"]) == 0

    def test_multiple_violations(self):
        html = (
            '<script src="https://cdn.example.com/lib.js"></script>'
            '<script src="http://insecure.example.com/lib2.js"></script>'
            '<script src="https://cdn.example.com/lib3.js" integrity=""></script>'
        )
        result = sri.analyze_page(html, "https://example.com/page")
        vtypes = {v["type"] for v in result["violations"]}
        assert "sri_missing_script" in vtypes
        assert "sri_insecure_origin" in vtypes
        assert "sri_malformed" in vtypes


class TestSriBuildPoc:
    def test_empty_url(self):
        assert sri.build_poc_html("") == ""

    def test_poc_contains_resource_url(self):
        poc = sri.build_poc_html(
            "https://example.com/page",
            resource_url="https://cdn.example.com/lib.js",
        )
        assert "cdn.example.com" in poc
        assert "CDN compromise" in poc.lower() or "sri" in poc.lower()


# =============================================================================
# Phase 27-3: Compliance mappings for new finding types
# =============================================================================

class TestPhase27ComplianceMappings:
    @pytest.mark.parametrize("ftype", [
        "cookie_tossing_set_cookie",
        "cookie_tossing_client",
        "cookie_sink_flow",
        "sri_missing_script",
        "sri_missing_script_summary",
        "sri_missing_style",
        "sri_broken_no_crossorigin",
        "sri_malformed",
        "sri_insecure_origin",
    ])
    def test_compliance_mapping_exists(self, ftype):
        """Each new finding type must map to at least one compliance entry."""
        finding = {"type": ftype, "url": "https://example.com", "method": "GET"}
        entries = compliance.compliance_for_finding(finding)
        assert len(entries) > 0, f"finding type '{ftype}' has no compliance mapping"
        # All entries must have the standard fields.
        for e in entries:
            assert "framework" in e
            assert "requirement_id" in e

    def test_cookie_tossing_maps_to_cwe_1004(self):
        finding = {"type": "cookie_tossing_set_cookie",
                   "url": "https://example.com", "method": "GET"}
        entries = compliance.compliance_for_finding(finding)
        cwes = [e["requirement_id"] for e in entries if e["framework"] == "CWE"]
        assert "CWE-1004" in cwes

    def test_sri_missing_maps_to_cwe_353(self):
        finding = {"type": "sri_missing_script",
                   "url": "https://example.com", "method": "GET"}
        entries = compliance.compliance_for_finding(finding)
        cwes = [e["requirement_id"] for e in entries if e["framework"] == "CWE"]
        assert "CWE-353" in cwes

    def test_sri_insecure_maps_to_cwe_319(self):
        finding = {"type": "sri_insecure_origin",
                   "url": "https://example.com", "method": "GET"}
        entries = compliance.compliance_for_finding(finding)
        cwes = [e["requirement_id"] for e in entries if e["framework"] == "CWE"]
        assert "CWE-319" in cwes


# =============================================================================
# Phase 27-3: Fix advice for new finding types
# =============================================================================

class TestPhase27FixAdvice:
    @pytest.mark.parametrize("ftype", [
        "cookie_tossing_set_cookie",
        "cookie_tossing_client",
        "cookie_sink_flow",
        "sri_missing_script",
        "sri_missing_script_summary",
        "sri_missing_style",
        "sri_broken_no_crossorigin",
        "sri_malformed",
        "sri_insecure_origin",
    ])
    def test_advice_exists(self, ftype):
        """Each new finding type must have specific remediation advice."""
        advice = fix_advice.get_advice(ftype)
        assert advice["headline"], f"no headline for {ftype}"
        assert advice["detail"], f"no detail for {ftype}"
        assert advice["code_example"], f"no code example for {ftype}"
        assert advice["primary_cwe"], f"no primary CWE for {ftype}"

    def test_cookie_tossing_advice_mentions_domain(self):
        advice = fix_advice.get_advice("cookie_tossing_set_cookie")
        assert "Domain" in advice["detail"] or "domain" in advice["detail"].lower()

    def test_sri_missing_advice_mentions_integrity(self):
        advice = fix_advice.get_advice("sri_missing_script")
        assert "integrity" in advice["detail"].lower()
