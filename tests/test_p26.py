"""Phase 26 regression tests: GraphQL + WebSocket XSS detection layers.

These tests validate the pure-Python logic of the two new modules added
in Phase 26 (``graphql_xss`` and ``websocket_xss``) without requiring
network access.  They give fast, isolated, regression-grade coverage
so future refactors cannot silently break the public API contract of
these modules.

The tests cover:

  * ``graphql_xss.detect_graphql_markers`` -- Apollo/urql/Relay/gql-tag
    detection, endpoint URL extraction, introspection hint.
  * ``graphql_xss.find_unsafe_sinks`` -- innerHTML/dangerouslySetInnerHTML
    /v-html/eval/jQuery sink detection with GraphQL data reference.
  * ``graphql_xss.analyze_page`` -- aggregate exploitable flag.
  * ``graphql_xss.probe_graphql_endpoint`` -- introspection/alias/
    argument reflection probes (with a mock fetcher).
  * ``graphql_xss.build_poc_html`` -- PoC generation for all sink types.
  * ``websocket_xss.detect_websocket_usage`` -- new WebSocket() /
    ws:// / wss:// / onmessage detection.
  * ``websocket_xss.find_websocket_handlers`` -- onmessage + sink + no
    origin check = exploitable.
  * ``websocket_xss.analyze_page`` -- aggregate.
  * ``websocket_xss.build_poc_html`` / ``build_poc_cswsh`` -- PoC
    generation.
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

from xssentinel.core import graphql_xss as gql
from xssentinel.core import websocket_xss as ws
from xssentinel.core import compliance, fix_advice, verify_fix


# =============================================================================
# graphql_xss.detect_graphql_markers
# =============================================================================

class TestDetectGraphqlMarkers:
    def test_empty_input_returns_safe_defaults(self):
        r = gql.detect_graphql_markers("")
        assert r["has_graphql"] is False
        assert r["endpoints"] == []
        assert r["clients_detected"] == []
        assert r["gql_tag_count"] == 0

    def test_none_input_returns_safe_defaults(self):
        r = gql.detect_graphql_markers(None)
        assert r["has_graphql"] is False

    def test_apollo_client_detected(self):
        html = '<script>var c = new ApolloClient({uri:"/graphql"});</script>'
        r = gql.detect_graphql_markers(html)
        assert r["has_graphql"] is True
        assert "apollo" in r["clients_detected"]
        assert "/graphql" in r["endpoints"]

    def test_urql_client_detected(self):
        html = '<script>import {createClient} from "urql";</script>'
        r = gql.detect_graphql_markers(html)
        assert "urql" in r["clients_detected"]
        assert r["has_graphql"] is True

    def test_relay_client_detected(self):
        html = '<script>graphql`query GetUser { user { id } }`</script>'
        r = gql.detect_graphql_markers(html)
        assert "relay" in r["clients_detected"]
        assert r["gql_tag_count"] >= 1

    def test_gql_tag_template_literal_counted(self):
        html = (
            '<script>'
            'const Q1 = gql`query { user }`;'
            'const Q2 = gql`mutation { setUser }`;'
            '</script>'
        )
        r = gql.detect_graphql_markers(html)
        assert r["gql_tag_count"] == 2

    def test_endpoint_url_extraction(self):
        html = '<script>fetch("https://api.example.com/v1/graphql", {method:"POST"})</script>'
        r = gql.detect_graphql_markers(html)
        assert any("graphql" in e for e in r["endpoints"])

    def test_apollo_hooks_detected(self):
        html = (
            '<script>'
            'function User(){ const {data} = useQuery(GET_USER); '
            'const [mutate] = useMutation(SET_USER); }'
            '</script>'
        )
        r = gql.detect_graphql_markers(html)
        assert "useQuery" in r["hooks_detected"]
        assert "useMutation" in r["hooks_detected"]

    def test_introspection_hint_flagged(self):
        html = '<script>const Q = gql`query { __typename }`;</script>'
        r = gql.detect_graphql_markers(html)
        assert r["has_introspection_hint"] is True

    def test_no_graphql_in_plain_page(self):
        html = '<html><body><h1>hello world</h1></body></html>'
        r = gql.detect_graphql_markers(html)
        assert r["has_graphql"] is False
        assert r["endpoints"] == []


# =============================================================================
# graphql_xss.find_unsafe_sinks
# =============================================================================

class TestFindUnsafeSinks:
    def test_empty_returns_empty(self):
        assert gql.find_unsafe_sinks("") == []
        assert gql.find_unsafe_sinks(None) == []

    def test_innerhtml_sink_with_graphql_data_ref(self):
        html = (
            '<script>'
            'function render(d) {'
            '  document.getElementById("out").innerHTML = data.user.bio;'
            '}'
            '</script>'
        )
        sinks = gql.find_unsafe_sinks(html)
        # The innerHTML sink should be detected.
        assert any(s["sink_type"] == "inner_html" for s in sinks)
        # And it should have a GraphQL data reference nearby.
        data_ref_sinks = [s for s in sinks if s["has_data_ref"]]
        assert len(data_ref_sinks) >= 1

    def test_dangerouslySetInnerHTML_sink_with_graphql_data_ref(self):
        html = (
            '<script>'
            'const { data } = useQuery(GET_USER);'
            'return React.createElement("div", {'
            '  dangerouslySetInnerHTML: { __html: data.user.bio }'
            '});'
            '</script>'
        )
        sinks = gql.find_unsafe_sinks(html)
        dsi = [s for s in sinks if s["sink_type"] == "dangerouslySetInnerHTML"]
        assert len(dsi) >= 1
        assert any(s["has_data_ref"] for s in dsi)

    def test_v_html_sink_with_graphql_data_ref(self):
        html = (
            '<div id="app">'
            '<div v-html="data.post.html"></div>'
            '</div>'
        )
        sinks = gql.find_unsafe_sinks(html)
        vh = [s for s in sinks if s["sink_type"] == "v_html"]
        assert len(vh) >= 1
        assert any(s["has_data_ref"] for s in vh)

    def test_eval_sink_detected(self):
        html = '<script>eval(data.code);</script>'
        sinks = gql.find_unsafe_sinks(html)
        ev = [s for s in sinks if s["sink_type"] == "eval_family"]
        assert len(ev) >= 1

    def test_safe_page_has_no_sinks(self):
        html = '<html><body><h1>safe</h1><script>var x = 1;</script></body></html>'
        sinks = gql.find_unsafe_sinks(html)
        assert sinks == []

    def test_overlapping_matches_deduplicated(self):
        # Two patterns targeting the same sink should not double-report.
        html = '<script>document.getElementById("o").innerHTML = data.x;</script>'
        sinks = gql.find_unsafe_sinks(html)
        # The inner_html regex is one pattern; only one match expected.
        inner_html_sinks = [s for s in sinks if s["sink_type"] == "inner_html"]
        assert len(inner_html_sinks) == 1

    def test_data_ref_sinks_sorted_first(self):
        # A sink with a data ref should come before a sink without one.
        html = (
            '<script>'
            'document.getElementById("a").innerHTML = data.x;'
            'document.getElementById("b").innerHTML = "static";'
            '</script>'
        )
        sinks = gql.find_unsafe_sinks(html)
        # The first sink should have a data ref.
        assert sinks[0]["has_data_ref"] is True


# =============================================================================
# graphql_xss.analyze_page
# =============================================================================

class TestGraphqlAnalyzePage:
    def test_vulnerable_apollo_app_is_exploitable(self):
        """A page with Apollo Client + dangerouslySetInnerHTML + GraphQL
        data reference is exploitable."""
        html = (
            '<html><body><div id="root"></div>'
            '<script>'
            'const client = new ApolloClient({uri:"/graphql", cache: new InMemoryCache()});'
            'const GET_USER = gql`query { user { id bio } }`;'
            'function UserBio() {'
            '  const { data, loading } = useQuery(GET_USER);'
            '  if (loading) return null;'
            '  return React.createElement("div", {'
            '    dangerouslySetInnerHTML: { __html: data.user.bio }'
            '  });'
            '}'
            '</script></body></html>'
        )
        r = gql.analyze_page(html)
        assert r["has_graphql"] is True
        assert r["exploitable"] is True
        assert r["vulnerable_count"] >= 1
        assert "/graphql" in r["endpoints"]

    def test_safe_page_not_exploitable(self):
        html = '<html><body><h1>hello</h1></body></html>'
        r = gql.analyze_page(html)
        assert r["has_graphql"] is False
        assert r["exploitable"] is False
        assert r["vulnerable_count"] == 0

    def test_graphql_without_sink_not_exploitable(self):
        """Apollo Client present but no unsafe sink -> not exploitable."""
        html = (
            '<script>'
            'const client = new ApolloClient({uri:"/graphql"});'
            'const Q = gql`query { user { id } }`;'
            '</script>'
        )
        r = gql.analyze_page(html)
        assert r["has_graphql"] is True
        assert r["exploitable"] is False


# =============================================================================
# graphql_xss.probe_graphql_endpoint
# =============================================================================

class TestProbeGraphqlEndpoint:
    def test_no_fetcher_returns_neutral_result(self):
        r = gql.probe_graphql_endpoint("http://t/graphql")
        assert r["is_graphql"] is False
        assert r["introspection"] is False
        assert r["alias_reflected"] is False

    def test_introspection_detected(self):
        """A fetcher that returns a valid __typename response flags
        introspection."""
        def fetcher(url, body, headers):
            return 200, '{"data":{"__typename":"Query"}}'
        r = gql.probe_graphql_endpoint("http://t/graphql", fetcher=fetcher)
        assert r["is_graphql"] is True
        assert r["introspection"] is True

    def test_alias_reflection_detected(self):
        """A fetcher that reflects the alias verbatim in the response
        flags alias_reflected."""
        calls = []

        def fetcher(url, body, headers):
            calls.append(body)
            # Inspect the body to return the right response.
            if "__typename" in body and ":" in body:
                # Alias probe -- reflect the alias.
                import json, re
                m = re.search(r'query\{([^:}]+):__typename\}', body)
                if m:
                    alias = m.group(1)
                    return 200, json.dumps({"data": {alias: "Query"}})
            if "__typename" in body:
                return 200, '{"data":{"__typename":"Query"}}'
            return 200, '{"errors":[{"message":"bad query"}]}'

        r = gql.probe_graphql_endpoint("http://t/graphql", fetcher=fetcher)
        assert r["alias_reflected"] is True
        assert r["is_graphql"] is True

    def test_argument_reflection_detected(self):
        """A fetcher that echoes the argument value in the error message
        flags argument_reflected."""
        def fetcher(url, body, headers):
            if "user(name:" in body:
                # Argument probe -- echo the value in the error.
                import re
                m = re.search(r'user\s*\(\s*name\s*:\s*\\"([^"]*)\\"', body)
                if m:
                    value = m.group(1)
                    return 200, (
                        '{"errors":[{"message":"unknown user: ' + value + '"}]}'
                    )
            if "__typename" in body:
                return 200, '{"data":{"__typename":"Query"}}'
            return 200, '{"errors":[{"message":"bad query"}]}'

        r = gql.probe_graphql_endpoint(
            "http://t/graphql", fetcher=fetcher,
            payload=gql.DEFAULT_ARGUMENT_PAYLOAD,
        )
        assert r["argument_reflected"] is True

    def test_fetcher_exception_does_not_propagate(self):
        def fetcher(url, body, headers):
            raise RuntimeError("network error")
        r = gql.probe_graphql_endpoint("http://t/graphql", fetcher=fetcher)
        # Must not raise; all flags stay False.
        assert r["is_graphql"] is False


# =============================================================================
# graphql_xss.build_poc_html / build_poc_query
# =============================================================================

class TestGraphqlBuildPoc:
    def test_build_poc_html_argument_reflection(self):
        html = gql.build_poc_html(
            "http://t/app", endpoint="/graphql",
            payload="<svg/onload=alert(1)>",
            sink_type="argument_reflection",
        )
        assert "<!DOCTYPE html>" in html
        assert "fetch(" in html
        assert "/graphql" in html
        assert "alert(1)" in html

    def test_build_poc_html_alias_reflection(self):
        html = gql.build_poc_html(
            "http://t/app", endpoint="/graphql",
            payload=gql.DEFAULT_ALIAS_PAYLOAD,
            sink_type="alias_reflection",
        )
        assert "fetch(" in html
        assert "__typename" in html  # the aliased query

    def test_build_poc_html_client_sink(self):
        html = gql.build_poc_html(
            "http://t/app", endpoint="/graphql",
            payload="<img src=x onerror=alert(1)>",
            sink_type="client_sink",
        )
        assert "mutation" in html  # simulates a stored-field mutation

    def test_build_poc_html_empty_target_returns_empty(self):
        assert gql.build_poc_html("") == ""

    def test_build_poc_query(self):
        q = gql.build_poc_query("myAlias")
        assert q == "query{myAlias:__typename}"


# =============================================================================
# websocket_xss.detect_websocket_usage
# =============================================================================

class TestDetectWebsocketUsage:
    def test_empty_returns_safe_defaults(self):
        r = ws.detect_websocket_usage("")
        assert r["has_websocket"] is False
        assert r["ws_urls"] == []

    def test_none_returns_safe_defaults(self):
        r = ws.detect_websocket_usage(None)
        assert r["has_websocket"] is False

    def test_websocket_constructor_detected(self):
        html = '<script>var ws = new WebSocket("wss://t/socket");</script>'
        r = ws.detect_websocket_usage(html)
        assert r["has_websocket"] is True
        assert r["ctor_count"] >= 1
        assert any("wss://" in u for u in r["ws_urls"])

    def test_insecure_ws_url_flagged(self):
        html = '<script>var ws = new WebSocket("ws://t/socket");</script>'
        r = ws.detect_websocket_usage(html)
        assert r["uses_insecure_ws"] is True

    def test_secure_wss_url_not_flagged_as_insecure(self):
        html = '<script>var ws = new WebSocket("wss://t/socket");</script>'
        r = ws.detect_websocket_usage(html)
        assert r["uses_insecure_ws"] is False

    def test_onmessage_handler_counted(self):
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.onmessage = function(e) {};'
            'ws.addEventListener("message", function(e) {});'
            '</script>'
        )
        r = ws.detect_websocket_usage(html)
        assert r["handler_count"] == 2

    def test_no_websocket_in_plain_page(self):
        html = '<html><body><h1>hello</h1></body></html>'
        r = ws.detect_websocket_usage(html)
        assert r["has_websocket"] is False


# =============================================================================
# websocket_xss.find_websocket_handlers
# =============================================================================

class TestFindWebsocketHandlers:
    def test_exploitable_handler_detected(self):
        """onmessage + innerHTML + event.data + no origin check = exploitable."""
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.onmessage = function(e) {'
            '  document.getElementById("out").innerHTML = e.data;'
            '};'
            '</script>'
        )
        handlers = ws.find_websocket_handlers(html)
        assert len(handlers) >= 1
        h = handlers[0]
        assert h["has_sink"] is True
        assert h["has_data_ref"] is True
        assert h["has_origin_check"] is False
        assert h["exploitable"] is True
        assert "innerhtml" in " ".join(h["sinks_found"]).lower()

    def test_origin_check_mitigates(self):
        """If the handler checks event.origin, it's not exploitable."""
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.onmessage = function(e) {'
            '  if (e.origin !== "https://t") return;'
            '  document.getElementById("out").innerHTML = e.data;'
            '};'
            '</script>'
        )
        handlers = ws.find_websocket_handlers(html)
        # The handler has a sink and data ref, but origin check mitigates.
        exploitable = [h for h in handlers if h["exploitable"]]
        assert len(exploitable) == 0

    def test_no_sink_not_exploitable(self):
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.onmessage = function(e) {'
            '  console.log(e.data);'
            '};'
            '</script>'
        )
        handlers = ws.find_websocket_handlers(html)
        exploitable = [h for h in handlers if h["exploitable"]]
        assert len(exploitable) == 0

    def test_eval_sink_detected(self):
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.addEventListener("message", function(e) {'
            '  eval(e.data);'
            '});'
            '</script>'
        )
        handlers = ws.find_websocket_handlers(html)
        exploitable = [h for h in handlers if h["exploitable"]]
        assert len(exploitable) >= 1

    def test_empty_returns_empty(self):
        assert ws.find_websocket_handlers("") == []
        assert ws.find_websocket_handlers(None) == []


# =============================================================================
# websocket_xss.analyze_page
# =============================================================================

class TestWebsocketAnalyzePage:
    def test_vulnerable_page(self):
        html = (
            '<script>'
            'var ws = new WebSocket("wss://t/socket");'
            'ws.onmessage = function(e) {'
            '  document.getElementById("out").innerHTML = e.data;'
            '};'
            '</script>'
        )
        r = ws.analyze_page(html)
        assert r["has_websocket"] is True
        assert r["vulnerable_count"] >= 1
        assert r["uses_insecure_ws"] is False

    def test_insecure_ws_without_sink_flagged(self):
        """A page that uses ws:// but has no unsafe sink should still be
        reported as insecure (medium-severity MITM risk)."""
        html = (
            '<script>'
            'var ws = new WebSocket("ws://chat.example.com/socket");'
            'ws.onmessage = function(e) {'
            '  console.log(e.data);'  # safe sink
            '};'
            '</script>'
        )
        r = ws.analyze_page(html)
        assert r["has_websocket"] is True
        assert r["uses_insecure_ws"] is True
        assert r["vulnerable_count"] == 0  # no exploitable sink

    def test_safe_page(self):
        html = '<html><body><h1>hello</h1></body></html>'
        r = ws.analyze_page(html)
        assert r["has_websocket"] is False
        assert r["vulnerable_count"] == 0


# =============================================================================
# websocket_xss.build_poc_html / build_poc_cswsh
# =============================================================================

class TestWebsocketBuildPoc:
    def test_build_poc_html_default(self):
        html = ws.build_poc_html(
            "http://t/app", ws_url="wss://t/socket",
            payload="<img src=x onerror=alert(1)>",
        )
        assert "WebSocket" in html
        assert "wss://t/socket" in html
        assert "alert(1)" in html

    def test_build_poc_html_empty_target_returns_empty(self):
        assert ws.build_poc_html("") == ""

    def test_build_poc_html_auto_generates_ws_url(self):
        """If ws_url is omitted, derive it from the target URL."""
        html = ws.build_poc_html("http://t/app")
        assert "wss://" in html

    def test_build_poc_cswsh(self):
        html = ws.build_poc_cswsh(
            "http://t/", ws_url="wss://t/socket",
            payload="<img src=x onerror=alert(1)>",
        )
        assert "CSWSH" in html or "Hijacking" in html
        assert "wss://t/socket" in html

    def test_build_poc_cswsh_empty_url_returns_empty(self):
        assert ws.build_poc_cswsh("http://t/", "", "payload") == ""


# =============================================================================
# compliance.py -- new finding types
# =============================================================================

class TestComplianceForNewTypes:
    def test_graphql_xss_maps_to_compliance(self):
        finding = {"type": "graphql_xss"}
        entries = compliance.compliance_for_finding(finding)
        frameworks = {e["framework"] for e in entries}
        assert "OWASP Top 10 2021" in frameworks
        assert "CWE" in frameworks
        cwe_ids = {e["requirement_id"] for e in entries if e["framework"] == "CWE"}
        assert "CWE-79" in cwe_ids
        assert "CWE-83" in cwe_ids  # attribute XSS

    def test_graphql_introspection_maps(self):
        finding = {"type": "graphql_introspection"}
        entries = compliance.compliance_for_finding(finding)
        cwe_ids = {e["requirement_id"] for e in entries if e["framework"] == "CWE"}
        assert "CWE-94" in cwe_ids  # code injection

    def test_websocket_xss_maps(self):
        finding = {"type": "websocket_xss"}
        entries = compliance.compliance_for_finding(finding)
        cwe_ids = {e["requirement_id"] for e in entries if e["framework"] == "CWE"}
        assert "CWE-79" in cwe_ids
        assert "CWE-1021" in cwe_ids  # rendered UI layers

    def test_websocket_insecure_maps_to_cwe_319(self):
        finding = {"type": "websocket_insecure"}
        entries = compliance.compliance_for_finding(finding)
        cwe_ids = {e["requirement_id"] for e in entries if e["framework"] == "CWE"}
        assert "CWE-319" in cwe_ids  # cleartext transmission

    def test_supported_types_include_new(self):
        types = compliance.supported_finding_types()
        assert "graphql_xss" in types
        assert "graphql_introspection" in types
        assert "websocket_xss" in types
        assert "websocket_insecure" in types

    def test_compliance_summary_aggregates_new_types(self):
        findings = [
            {"type": "graphql_xss"},
            {"type": "graphql_xss"},
            {"type": "websocket_xss"},
        ]
        s = compliance.compliance_summary(findings)
        # OWASP A03 count should be 3.
        assert s["OWASP Top 10 2021"]["A03:2021"]["count"] == 3


# =============================================================================
# fix_advice.py -- new finding types
# =============================================================================

class TestFixAdviceForNewTypes:
    def test_graphql_xss_advice(self):
        a = fix_advice.get_advice("graphql_xss")
        assert "headline" in a
        assert "DOMPurify" in a["code_example"] or "dangerouslySetInnerHTML" in a["code_example"]
        assert a["primary_cwe"] == "CWE-79"

    def test_graphql_introspection_advice(self):
        a = fix_advice.get_advice("graphql_introspection")
        assert "introspection" in a["headline"].lower()
        assert "ApolloServer" in a["code_example"] or "introspection" in a["code_example"]
        assert a["primary_cwe"] == "CWE-94"

    def test_websocket_xss_advice(self):
        a = fix_advice.get_advice("websocket_xss")
        assert "WebSocket" in a["headline"] or "event.data" in a["headline"]
        assert "textContent" in a["code_example"]  # safe sink example
        assert a["primary_cwe"] == "CWE-79"

    def test_websocket_insecure_advice(self):
        a = fix_advice.get_advice("websocket_insecure")
        assert "wss://" in a["headline"]
        assert a["primary_cwe"] == "CWE-319"


# =============================================================================
# verify_fix.py -- replayable classification
# =============================================================================

class TestVerifyFixReplayable:
    def test_graphql_xss_is_replayable(self):
        assert verify_fix._is_replayable("graphql_xss") is True

    def test_graphql_introspection_is_replayable(self):
        assert verify_fix._is_replayable("graphql_introspection") is True

    def test_websocket_xss_is_not_replayable(self):
        """WebSocket findings require scanner context (no static replay)."""
        assert verify_fix._is_replayable("websocket_xss") is False

    def test_websocket_insecure_is_not_replayable(self):
        assert verify_fix._is_replayable("websocket_insecure") is False


# =============================================================================
# Integration: advanced_layers wiring
# =============================================================================

class TestAdvancedLayersWiring:
    """Verify the new layers are imported and callable from
    advanced_layers without running a full scan."""

    def test_graphql_layer_callable(self):
        from xssentinel.core import advanced_layers
        assert hasattr(advanced_layers, "_scan_graphql")
        assert callable(advanced_layers._scan_graphql)

    def test_websocket_layer_callable(self):
        from xssentinel.core import advanced_layers
        assert hasattr(advanced_layers, "_scan_websocket")
        assert callable(advanced_layers._scan_websocket)

    def test_run_page_layers_invokes_new_layers(self):
        """run_page_layers should call _scan_graphql and _scan_websocket
        in addition to the existing layers."""
        from xssentinel.core import advanced_layers
        # The function source should reference both new functions.
        src = advanced_layers.run_page_layers.__code__.co_names
        # co_names doesn't include local function names, so check the
        # function's source code instead.
        import inspect
        source = inspect.getsource(advanced_layers.run_page_layers)
        assert "_scan_graphql" in source
        assert "_scan_websocket" in source
