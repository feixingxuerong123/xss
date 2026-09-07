"""Unit tests for Phase 32: generative payload builder, tagged-template
marking, endpoint-signature dedup, and content-type confidence downgrade.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import generator as gen
from xssentinel.core import verifier
from xssentinel.core.scanner import Scanner


def _prof(kept):
    return {"full_reflection": False, "chars_kept": kept,
            "chars_stripped": [], "chars_encoded": []}


class TestGenerate:
    def test_empty_on_full_profile_or_none(self):
        assert gen.generate({"full_reflection": True}, "html_element") == []
        assert gen.generate(None, "html_element") == []

    def test_tag_injection_parens_alive(self):
        out = gen.generate(_prof(list("\"'<>()=/;`")), "html_element")
        assert out, "expected generated payloads"
        for entry in out:
            assert entry["context"] == "html_element"
            assert entry["tags"] == ["generated"]
            assert "note" in entry and "confidence" in entry
        payloads = [e["payload"] for e in out]
        assert "<svg onload=alert(1)>" in payloads
        assert "<img src=x onerror=alert(1)>" in payloads
        # slash separator present too when / survives
        assert "<svg/onload=alert(1)>" in payloads

    def test_parens_dead_switches_to_tagged_template(self):
        out = gen.generate(_prof(list("\"'<>/;`")), "html_element")
        payloads = [e["payload"] for e in out]
        assert all("alert`1`" in p for p in payloads)
        assert not any("alert(1)" in p for p in payloads)

    def test_attr_breakout_when_tags_dead(self):
        out = gen.generate(_prof(list("\"'()/;`")), "html_element")
        payloads = [e["payload"] for e in out]
        # double quote preferred (alive), no tag characters used
        assert any(p.startswith('" onmouseover=alert(1)') for p in payloads)
        assert not any(p.startswith("<") for p in payloads)

    def test_single_quote_fallback(self):
        out = gen.generate(_prof(list("'()/;`")), "html_element")
        payloads = [e["payload"] for e in out]
        assert any(p.startswith("' onmouseover=") for p in payloads)

    def test_noquote_attr_injection(self):
        out = gen.generate(_prof(list("=()/;`")), "html_element")
        payloads = [e["payload"] for e in out]
        assert any(p.startswith(" onfocus=alert(1)") for p in payloads)

    def test_attribute_context_breakout(self):
        out = gen.generate(_prof(list("\"()=/;`")), "html_attribute_dq")
        payloads = [e["payload"] for e in out]
        assert any(p.startswith('" onmouseover=alert(1)') for p in payloads)
        assert any(p.startswith('" autofocus onfocus=alert(1)') for p in payloads)

    def test_attribute_context_tag_closeout_when_quotes_dead(self):
        out = gen.generate(_prof(list("<>()=/;`")), "html_attribute_dq")
        payloads = [e["payload"] for e in out]
        assert any(p.startswith("><svg onload=") for p in payloads)

    def test_script_string_breakout(self):
        out = gen.generate(_prof(list("'()=;`")), "script_string_sq")
        payloads = [e["payload"] for e in out]
        assert "';alert(1);//" in payloads

    def test_script_string_tagged_template_when_parens_dead(self):
        out = gen.generate(_prof(list('"=;`')), "script_string_dq")
        payloads = [e["payload"] for e in out]
        assert '";alert`1`;//' in payloads

    def test_script_block_direct_call(self):
        out = gen.generate(_prof(list("()")), "script_block")
        assert [e["payload"] for e in out] == ["alert(1)"]

    def test_url_context_generates_nothing(self):
        assert gen.generate(_prof(list("\"'<>()=/;`")), "url_href") == []


class TestMarkTaggedTemplate:
    def test_parens_form_unchanged(self):
        assert verifier.mark("alert(1)", "tok") == "alert('tok')"
        assert verifier.mark("alert(document.domain)", "tok") == "alert('tok')"

    def test_tagged_template_form(self):
        assert verifier.mark("alert`1`", "tok") == "alert`tok`"
        assert verifier.mark("<svg onload=alert`x`>", "tok") == \
            "<svg onload=alert`tok`>"


class TestEndpointSignatureDedup:
    def test_same_signature_collapsed(self):
        eps = [
            ("http://h/search", "GET", {"q": "1"}, {}),
            ("http://h/search", "GET", {"q": "2"}, {}),
            ("http://h/search", "GET", {"q": "3"}, {}),
        ]
        out = Scanner._dedupe_endpoint_signatures(eps)
        assert len(out) == 1
        assert out[0][2] == {"q": "1"}

    def test_entry_point_always_kept(self):
        eps = [("http://h/a", "GET", {}, {}),
               ("http://h/a", "GET", {}, {})]
        out = Scanner._dedupe_endpoint_signatures(eps)
        assert len(out) == 1

    def test_distinct_path_method_params_kept(self):
        eps = [
            ("http://h/a?x=1", "GET", {"x": "1"}, {}),
            ("http://h/b?x=1", "GET", {"x": "1"}, {}),      # different path
            ("http://h/a?x=1", "POST", {}, {"x": "1"}),     # different method
            ("http://h/a?x=1", "GET", {"x": "1", "y": ""}, {}),  # more params
        ]
        out = Scanner._dedupe_endpoint_signatures(eps)
        assert len(out) == 4

    def test_host_matters(self):
        eps = [("http://h1/a", "GET", {}, {}),
               ("http://h2/a", "GET", {}, {})]
        out = Scanner._dedupe_endpoint_signatures(eps)
        assert len(out) == 2

    def test_param_order_irrelevant(self):
        eps = [("http://h/a", "GET", {"a": "1", "b": "2"}, {}),
               ("http://h/a", "GET", {"b": "9", "a": "8"}, {})]
        out = Scanner._dedupe_endpoint_signatures(eps)
        assert len(out) == 1
