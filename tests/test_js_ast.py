"""Tests for the JS AST data-flow channel (Phase 43, DalFox-v3-style).

Covers what regex windows CANNOT do: multi-hop variable chains, function-body
flows, minified single-letter identifiers, and sink-assignments.  Every test
feeds raw JS (no browser); parse-failure fallback is asserted explicitly.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import js_ast
from xssentinel.core import dom as dom_mod


class TestBasicFlows:
    def test_direct_source_to_sink(self):
        out = js_ast.analyze_script("el.innerHTML = location.hash;")
        assert out and out[0]["sink"] == "el.innerHTML"
        assert out[0]["source"] == "location.hash"
        assert out[0]["confidence"] == "high"

    def test_variable_chain(self):
        out = js_ast.analyze_script(
            "var x = location.hash; el.innerHTML = x;")
        assert out and out[0]["source"] == "var:x"
        assert out[0]["confidence"] == "high"

    def test_multi_hop_chain(self):
        out = js_ast.analyze_script(
            "var a = location.search; var b = a; eval(b);")
        assert out and out[0]["sink"] == "eval"

    def test_concatenation_propagates_taint(self):
        out = js_ast.analyze_script(
            "var q = location.hash; var payload = '<b>' + q + '</b>';\n"
            "el.innerHTML = payload;")
        assert out and "var:payload" in out[0]["source"]

    def test_document_write_direct(self):
        out = js_ast.analyze_script("document.write(location.hash);")
        assert out and out[0]["sink"] == "document.write"

    def test_settimeout_first_arg(self):
        out = js_ast.analyze_script("setTimeout(location.hash, 1000);")
        assert out and out[0]["sink"] == "setTimeout"


class TestFunctionScope:
    def test_postmessage_handler_flow(self):
        out = js_ast.analyze_script(
            "window.addEventListener('message', function(e) {\n"
            "  el.innerHTML = e.data;\n"
            "});")
        assert out and out[0]["source"] == "postMessage event.data"
        # Cross-function flows are reported at medium confidence.
        assert out[0]["confidence"] == "medium"
        assert "cross-function" in out[0]["detail"]


class TestMinifiedAndEdgeCases:
    def test_minified_identifiers(self):
        out = js_ast.analyze_script(
            "var a=location.hash,b=a+'<b>',c=b;document.body.innerHTML=c;")
        assert out and out[0]["source"] == "var:c"

    def test_parse_failure_returns_none(self):
        assert js_ast.analyze_script("{{{ not javascript") is None
        assert js_ast.analyze_script("") is None

    def test_safe_code_no_findings(self):
        # textContent is not a markup sink.
        out = js_ast.analyze_script(
            "var x = 'safe'; el.textContent = x;")
        assert out == []

    def test_srcdoc_sink(self):
        out = js_ast.analyze_script("el.srcdoc = location.hash;")
        assert out and "srcdoc" in out[0]["sink"]


class TestDomIntegration:
    def test_analyze_uses_ast_channel(self):
        html = ("<html><body><script>"
                "var x = location.hash; el.innerHTML = x;"
                "</script></body></html>")
        findings = dom_mod.analyze(html, is_html=True)
        ast_hits = [f for f in findings
                    if f.get("detail", "").startswith("[AST]")]
        assert ast_hits, "AST channel must contribute a finding"
        assert ast_hits[0]["confidence"] == "high"
        # The regex layer's low-confidence duplicate of the same sink is
        # suppressed when the AST chain covers it.
        regex_dupes = [f for f in findings
                       if f["sink"] == "innerHTML"
                       and not f.get("detail", "").startswith("[AST]")
                       and f["confidence"] == "low"]
        assert not regex_dupes

    def test_regex_fallback_on_unparseable_script(self):
        # Script body that esprima cannot parse; regex channel must still
        # produce the generic sink finding.
        html = "<html><body><script>el.innerHTML = x; {{{</script></body></html>"
        findings = dom_mod.analyze(html, is_html=True)
        # The regex channel reports the sink with its leading dot
        # (".innerHTML"), unlike the AST channel ("el.innerHTML").
        assert any("innerHTML" in f["sink"] for f in findings)
