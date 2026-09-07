"""Unit tests for the form miner (Phase 43).

form_miner.py is pure HTML parsing -- tests feed markup directly, no mock
needed.  Covers extraction (bs4 path), attribute parsing fallback, field
filling rules, and the forms_to_endpoints convenience wrapper.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import form_miner as fm


class TestParseAttrs:
    def test_double_single_and_bare(self):
        attrs = fm._parse_attrs('action="/go" method=\'post\' disabled')
        assert attrs["action"] == "/go"
        assert attrs["method"] == "post"
        assert attrs["disabled"] == ""

    def test_names_lowercased(self):
        attrs = fm._parse_attrs('ACTION="/Go"')
        assert attrs["action"] == "/Go"


class TestExtractForms:
    def test_empty_html(self):
        assert fm.extract_forms("", "http://t/") == []

    def test_basic_get_form(self):
        html = ('<form action="/search" method="get">'
                '<input type="text" name="q">'
                '<input type="hidden" name="token" value="abc">'
                '<input type="submit" value="Go">'
                '</form>')
        forms = fm.extract_forms(html, "http://t/index")
        assert len(forms) == 1
        f = forms[0]
        assert f["action"] == "http://t/search"
        assert f["method"] == "GET"
        names = [x["name"] for x in f["fields"]]
        assert names == ["q", "token", "Go"] or set(names) >= {"q", "token"}

    def test_relative_action_resolved(self):
        html = '<form action="do" method="POST"><input name="a"></form>'
        forms = fm.extract_forms(html, "http://t/dir/page")
        assert forms[0]["action"] == "http://t/dir/do"
        assert forms[0]["method"] == "POST"

    def test_missing_action_defaults_to_base(self):
        html = '<form><input name="a"></form>'
        forms = fm.extract_forms(html, "http://t/page")
        assert forms[0]["action"] == "http://t/page"

    def test_textarea_and_select(self):
        html = ('<form><textarea name="bio">hello</textarea>'
                '<select name="lvl"><option value="2">b</option></select>'
                '</form>')
        f = fm.extract_forms(html, "http://t/")[0]
        byname = {x["name"]: x for x in f["fields"]}
        assert byname["bio"]["value"] == "hello"
        assert byname["lvl"]["type"] == "select"
        assert byname["lvl"]["value"] == "2"

    def test_inputs_without_name_skipped(self):
        html = '<form><input type="text"><input name="ok"></form>'
        f = fm.extract_forms(html, "http://t/")[0]
        assert [x["name"] for x in f["fields"]] == ["ok"]


class TestFillForm:
    def test_get_form_produces_params(self):
        form = {"action": "http://t/s", "method": "GET",
                "fields": [{"name": "q", "type": "text", "value": ""}]}
        params, data = fm.fill_form(form, marker="MARK")
        assert params == {"q": "MARK"}
        assert data == {}

    def test_post_form_produces_data(self):
        form = {"action": "http://t/s", "method": "POST",
                "fields": [{"name": "msg", "type": "text", "value": ""}]}
        params, data = fm.fill_form(form, marker="MARK")
        assert params == {}
        assert data == {"msg": "MARK"}

    def test_hidden_keeps_server_value(self):
        form = {"action": "http://t/s", "method": "POST",
                "fields": [{"name": "csrf", "type": "hidden", "value": "tok"},
                           {"name": "msg", "type": "text", "value": ""}]}
        _, data = fm.fill_form(form)
        assert data["csrf"] == "tok"

    def test_checkbox_defaults_on(self):
        form = {"action": "http://t/s", "method": "GET",
                "fields": [{"name": "agree", "type": "checkbox", "value": ""}]}
        params, _ = fm.fill_form(form)
        assert params["agree"] == "on"


class TestFormsToEndpoints:
    def test_end_to_end_tuples(self):
        html = ('<form action="/s" method="get"><input name="q"></form>'
                '<form action="/c" method="post"><input name="msg"></form>')
        eps = fm.forms_to_endpoints(html, "http://t/", marker="M")
        assert len(eps) == 2
        url0, method0, params0, data0 = eps[0]
        assert (url0, method0) == ("http://t/s", "GET")
        assert params0 == {"q": "M"} and data0 == {}
        url1, method1, params1, data1 = eps[1]
        assert (url1, method1) == ("http://t/c", "POST")
        assert params1 == {} and data1 == {"msg": "M"}
