"""Unit tests for Phase 30-3: modern framework SSTI enhancements.

Tests cover the new detection patterns added to framework_xss.py:
  * Vue 3 Composition API (ref+innerHTML, defineComponent, watch/watchEffect)
  * Angular 2+ ([style], [class], sanitizer pipe, $sce.trustAsHtml, ng-bind-html)
  * Svelte ({@html $store}, JSON.stringify, action+innerHTML, SvelteKit SSR)
  * Lit/Polymer (unsafeHTML, unsafeSVG, html`` interpolation,
    customElements.define, Polymer innerHTML, <dom-module>)

Each pattern is tested for:
  1. Positive detection (the dangerous snippet is flagged).
  2. Negative control (safe framework usage produces no findings).
  3. detect_framework() correctly identifies the framework.
  4. build_poc_html() returns a non-empty PoC for each framework.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import framework_xss as fw


# ---------------------------------------------------------------------------
# Fixture HTML samples -- Vue 3 Composition API
# ---------------------------------------------------------------------------
VUE3_VHTML = (
    '<div id="app" data-v-abc12345></div>'
    '<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>'
    '<script>'
    'const app = Vue.createApp({'
    '  template: \'<div v-html="userContent"></div>\','
    '  data() { return { userContent: "<img src=x onerror=alert(1)>" }; }'
    '});'
    'app.mount("#app");'
    '</script>'
)

VUE3_REF_INNERHTML = (
    '<div id="app" data-v-deadbeef></div>'
    '<script src="vue@3/dist/vue.global.js"></script>'
    '<script>'
    'const { createApp, ref } = Vue;'
    'createApp({'
    '  setup() {'
    '    const el = ref(null);'
    '    el.value.innerHTML = userInput;'
    '    return { el };'
    '  }'
    '}).mount("#app");'
    '</script>'
)

VUE3_DEFINE_COMPONENT_RENDER = (
    '<div data-v-feedface></div>'
    '<script src="vue@3"></script>'
    '<script>'
    'const Comp = defineComponent({'
    '  render() { return h("div", { innerHTML: this.dirty }); }'
    '});'
    '</script>'
)

VUE3_SCRIPT_SETUP_VHTML = (
    '<div data-v-cafebabe>'
    '<script setup>'
    'import { ref } from "vue";'
    'const html = ref("<b>hi</b>");'
    '</script>'
    '<template><div v-html="html"></div></template>'
    '</div>'
)

VUE3_WATCH_INNERHTML = (
    '<div data-v-12345678></div>'
    '<script src="vue@3"></script>'
    '<script>'
    'createApp({'
    '  setup() {'
    '    watchEffect(() => { document.body.innerHTML = state.value; });'
    '  }'
    '});'
    '</script>'
)

VUE3_SAFE = (
    '<div id="app" data-v-aaaabbbb></div>'
    '<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>'
    '<script>'
    'const app = Vue.createApp({'
    '  template: \'<div>{{ userContent }}</div>\','  # auto-escaped
    '  data() { return { userContent: "<b>safe</b>" }; }'
    '});'
    'app.mount("#app");'
    '</script>'
)


# ---------------------------------------------------------------------------
# Fixture HTML samples -- Angular 2+
# ---------------------------------------------------------------------------
ANGULAR_STYLE_BINDING = (
    '<app-root _nghost-abc></app-root>'
    '<script src="angular.min.js"></script>'
    '<div [style]="userStyle">content</div>'
    '<div [style.background-url]="bgUrl">bg</div>'
)

ANGULAR_SANITIZER_PIPE = (
    '<app-root _ngcontent-xyz ng-version="15"></app-root>'
    '<div [innerHTML]="content | bypassSecurityTrustHtml">raw</div>'
)

ANGULAR_SCE_TRUST = (
    '<div ng-app ng-version="12">'
    '<script>'
    'angular.module("app").controller("c", function($scope, $sce) {'
    '  $scope.html = $sce.trustAsHtml(userInput);'
    '});'
    '</script>'
    '<div ng-bind-html="html"></div>'
    '</div>'
)

ANGULAR_SAFE = (
    '<app-root _ngcontent-abc ng-version="15"></app-root>'
    '<div>{{ userContent }}</div>'  # auto-escaped interpolation
    '<div [innerText]="msg"></div>'
)


# ---------------------------------------------------------------------------
# Fixture HTML samples -- Svelte
# ---------------------------------------------------------------------------
SVELTE_HTML_STORE = (
    '<div class="svelte-1abc23"></div>'
    '<script src="svelte/internal/index.mjs"></script>'
    '<script>'
    'import { writable } from "svelte/store";'
    'const store = writable("<img src=x onerror=alert(1)>");'
    '</script>'
    '<div>{@html $store}</div>'
)

SVELTE_HTML_JSON = (
    '<div class="svelte-def456"></div>'
    '<script>'
    'const obj = JSON.parse(userInput);'
    '</script>'
    '<div>{@html JSON.stringify(obj)}</div>'
)

SVELTE_ACTION_INNERHTML = (
    '<div class="svelte-789abc"></div>'
    '<script>'
    'function dirty(node) { node.innerHTML = userData; }'
    '</script>'
    '<div use:dirty></div>'
)

SVELTE_SAFE = (
    '<div class="svelte-aaabbb"></div>'
    '<script src="svelte/internal/index.mjs"></script>'
    '<div>{userContent}</div>'  # auto-escaped
)


# ---------------------------------------------------------------------------
# Fixture HTML samples -- Lit / Polymer
# ---------------------------------------------------------------------------
LIT_UNSAFE_HTML = (
    '<my-element></my-element>'
    '<script type="module">'
    'import { html, render } from "lit";'
    'import { unsafeHTML } from "lit/directives/unsafe-html.js";'
    'render(html`<div>${unsafeHTML(userInput)}</div>`, document.body);'
    '</script>'
)

LIT_UNSAFE_SVG = (
    '<script type="module">'
    'import { html, render } from "lit";'
    'import { unsafeSVG } from "lit/directives/unsafe-svg.js";'
    'render(html`<svg>${unsafeSVG(userSvg)}</svg>`, document.body);'
    '</script>'
)

LIT_TEMPLATE_INTERPOLATION = (
    '<script type="module">'
    'import { html, render } from "lit";'
    'render(html`<a href="${userUrl}">link</a>`, document.body);'
    '</script>'
)

LIT_CUSTOM_ELEMENT = (
    '<script type="module">'
    'import { LitElement, html } from "lit";'
    'class MyEl extends LitElement {'
    '  render() { return html`<div>${this.data}</div>`; }'
    '}'
    'customElements.define("my-el", MyEl);'
    '</script>'
)

POLYMER_INNERHTML = (
    '<dom-module id="my-comp">'
    '<script>'
    'Polymer({'
    '  ready: function() { this.$.content.innerHTML = this.userData; }'
    '});'
    '</script>'
    '</dom-module>'
)

POLYMER_DOM_MODULE = (
    '<dom-module id="legacy-widget">'
    '<template><div>content</div></template>'
    '</dom-module>'
)

LIT_SAFE = (
    '<script type="module">'
    'import { html, render } from "lit";'
    'render(html`<div>${userInput}</div>`, document.body);'  # auto-escaped
    '</script>'
)


# ---------------------------------------------------------------------------
# detect_framework tests
# ---------------------------------------------------------------------------
class TestDetectFramework:
    def test_detect_vue3(self):
        assert "vue" in fw.detect_framework(VUE3_VHTML)

    def test_detect_angular(self):
        assert "angular" in fw.detect_framework(ANGULAR_STYLE_BINDING)

    def test_detect_svelte(self):
        assert "svelte" in fw.detect_framework(SVELTE_HTML_STORE)

    def test_detect_lit(self):
        assert "lit" in fw.detect_framework(LIT_UNSAFE_HTML)

    def test_detect_lit_custom_elements(self):
        assert "lit" in fw.detect_framework(LIT_CUSTOM_ELEMENT)

    def test_detect_polymer_dom_module(self):
        assert "lit" in fw.detect_framework(POLYMER_DOM_MODULE)

    def test_detect_empty_html(self):
        assert fw.detect_framework("") == []

    def test_detect_none_html(self):
        assert fw.detect_framework(None) == []


# ---------------------------------------------------------------------------
# Vue 3 Composition API tests
# ---------------------------------------------------------------------------
class TestVue3Patterns:
    def test_vhtml_detected(self):
        findings = fw.find_dangerous_patterns(VUE3_VHTML, "vue")
        descs = [f["description"] for f in findings]
        assert any("v-html" in d and "renders raw HTML" in d for d in descs), \
            f"v-html not detected: {descs}"

    def test_ref_innerhtml_detected(self):
        findings = fw.find_dangerous_patterns(VUE3_REF_INNERHTML, "vue")
        descs = [f["description"] for f in findings]
        assert any("ref()" in d and "innerHTML" in d for d in descs), \
            f"ref+innerHTML not detected: {descs}"

    def test_define_component_render_detected(self):
        findings = fw.find_dangerous_patterns(VUE3_DEFINE_COMPONENT_RENDER, "vue")
        descs = [f["description"] for f in findings]
        assert any("defineComponent" in d for d in descs), \
            f"defineComponent render not detected: {descs}"

    def test_script_setup_vhtml_detected(self):
        findings = fw.find_dangerous_patterns(VUE3_SCRIPT_SETUP_VHTML, "vue")
        descs = [f["description"] for f in findings]
        assert any("<script setup>" in d for d in descs), \
            f"<script setup> v-html not detected: {descs}"

    def test_watch_innerhtml_detected(self):
        findings = fw.find_dangerous_patterns(VUE3_WATCH_INNERHTML, "vue")
        descs = [f["description"] for f in findings]
        assert any("watch" in d.lower() and "innerHTML" in d for d in descs), \
            f"watch+innerHTML not detected: {descs}"

    def test_vue3_safe_no_high_findings(self):
        """Safe Vue 3 with {{ }} interpolation should not produce high findings."""
        findings = fw.find_dangerous_patterns(VUE3_SAFE, "vue")
        high = [f for f in findings if f["severity"] == "high"]
        assert high == [], f"safe Vue produced high findings: {high}"


# ---------------------------------------------------------------------------
# Angular 2+ tests
# ---------------------------------------------------------------------------
class TestAngularPatterns:
    def test_style_binding_detected(self):
        findings = fw.find_dangerous_patterns(ANGULAR_STYLE_BINDING, "angular")
        descs = [f["description"] for f in findings]
        assert any("[style]" in d for d in descs), \
            f"[style] binding not detected: {descs}"

    def test_sanitizer_pipe_detected(self):
        findings = fw.find_dangerous_patterns(ANGULAR_SANITIZER_PIPE, "angular")
        descs = [f["description"] for f in findings]
        assert any("pipe" in d.lower() and "bypassSecurityTrust" in d for d in descs), \
            f"sanitizer pipe not detected: {descs}"

    def test_sce_trust_html_detected(self):
        findings = fw.find_dangerous_patterns(ANGULAR_SCE_TRUST, "angular")
        descs = [f["description"] for f in findings]
        assert any("$sce.trustAsHtml" in d for d in descs), \
            f"$sce.trustAsHtml not detected: {descs}"

    def test_ng_bind_html_detected(self):
        findings = fw.find_dangerous_patterns(ANGULAR_SCE_TRUST, "angular")
        descs = [f["description"] for f in findings]
        assert any("ng-bind-html" in d for d in descs), \
            f"ng-bind-html not detected: {descs}"

    def test_angular_safe_no_high_findings(self):
        findings = fw.find_dangerous_patterns(ANGULAR_SAFE, "angular")
        high = [f for f in findings if f["severity"] == "high"]
        assert high == [], f"safe Angular produced high findings: {high}"


# ---------------------------------------------------------------------------
# Svelte tests
# ---------------------------------------------------------------------------
class TestSveltePatterns:
    def test_html_store_detected(self):
        findings = fw.find_dangerous_patterns(SVELTE_HTML_STORE, "svelte")
        descs = [f["description"] for f in findings]
        assert any("$store" in d for d in descs), \
            f"{{@html $store}} not detected: {descs}"

    def test_html_json_stringify_detected(self):
        findings = fw.find_dangerous_patterns(SVELTE_HTML_JSON, "svelte")
        descs = [f["description"] for f in findings]
        assert any("JSON.stringify" in d for d in descs), \
            f"{{@html JSON.stringify()}} not detected: {descs}"

    def test_action_innerhtml_detected(self):
        findings = fw.find_dangerous_patterns(SVELTE_ACTION_INNERHTML, "svelte")
        descs = [f["description"] for f in findings]
        assert any("action" in d.lower() and "innerHTML" in d for d in descs), \
            f"action+innerHTML not detected: {descs}"

    def test_svelte_safe_no_high_findings(self):
        findings = fw.find_dangerous_patterns(SVELTE_SAFE, "svelte")
        high = [f for f in findings if f["severity"] == "high"]
        assert high == [], f"safe Svelte produced high findings: {high}"


# ---------------------------------------------------------------------------
# Lit / Polymer tests
# ---------------------------------------------------------------------------
class TestLitPolymerPatterns:
    def test_unsafe_html_detected(self):
        findings = fw.find_dangerous_patterns(LIT_UNSAFE_HTML, "lit")
        descs = [f["description"] for f in findings]
        assert any("unsafeHTML" in d for d in descs), \
            f"unsafeHTML() not detected: {descs}"

    def test_unsafe_svg_detected(self):
        findings = fw.find_dangerous_patterns(LIT_UNSAFE_SVG, "lit")
        descs = [f["description"] for f in findings]
        assert any("unsafeSVG" in d for d in descs), \
            f"unsafeSVG() not detected: {descs}"

    def test_custom_elements_define_detected(self):
        findings = fw.find_dangerous_patterns(LIT_CUSTOM_ELEMENT, "lit")
        descs = [f["description"] for f in findings]
        assert any("custom element" in d.lower() for d in descs), \
            f"customElements.define not detected: {descs}"

    def test_polymer_innerhtml_detected(self):
        findings = fw.find_dangerous_patterns(POLYMER_INNERHTML, "lit")
        descs = [f["description"] for f in findings]
        assert any("innerHTML" in d and "Polymer" in d for d in descs) or \
               any("innerHTML" in d and "$." in d for d in descs) or \
               any("innerHTML" in d for d in descs), \
            f"Polymer innerHTML not detected: {descs}"

    def test_polymer_dom_module_detected(self):
        findings = fw.find_dangerous_patterns(POLYMER_DOM_MODULE, "lit")
        descs = [f["description"] for f in findings]
        assert any("dom-module" in d for d in descs), \
            f"<dom-module> not detected: {descs}"

    def test_lit_safe_no_high_findings(self):
        """Safe Lit with ${value} interpolation should not produce high findings."""
        findings = fw.find_dangerous_patterns(LIT_SAFE, "lit")
        high = [f for f in findings if f["severity"] == "high"]
        assert high == [], f"safe Lit produced high findings: {high}"


# ---------------------------------------------------------------------------
# analyze_page tests
# ---------------------------------------------------------------------------
class TestAnalyzePage:
    def test_vue3_page_exploitable(self):
        result = fw.analyze_page(VUE3_VHTML)
        assert "vue" in result["frameworks_detected"]
        assert result["exploitable"] is True
        assert result["vulnerable_count"] > 0

    def test_lit_page_exploitable(self):
        result = fw.analyze_page(LIT_UNSAFE_HTML)
        assert "lit" in result["frameworks_detected"]
        assert result["exploitable"] is True

    def test_svelte_page_exploitable(self):
        result = fw.analyze_page(SVELTE_HTML_STORE)
        assert "svelte" in result["frameworks_detected"]
        assert result["exploitable"] is True

    def test_angular_sanitizer_pipe_exploitable(self):
        result = fw.analyze_page(ANGULAR_SANITIZER_PIPE)
        assert "angular" in result["frameworks_detected"]
        assert result["exploitable"] is True

    def test_empty_page(self):
        result = fw.analyze_page("")
        assert result["frameworks_detected"] == []
        assert result["exploitable"] is False
        assert result["vulnerable_count"] == 0

    def test_safe_vue3_not_exploitable(self):
        """Safe Vue 3 page (auto-escaped) should not be exploitable."""
        result = fw.analyze_page(VUE3_SAFE)
        # May have low/medium findings (e.g. createApp) but NOT exploitable
        # (no high-severity direct sink).
        assert result["exploitable"] is False, \
            f"safe Vue 3 marked exploitable: {[f['description'] for f in result['findings']]}"


# ---------------------------------------------------------------------------
# build_poc_html tests
# ---------------------------------------------------------------------------
class TestBuildPoc:
    @pytest.mark.parametrize("framework", ["react", "vue", "angular", "svelte", "lit"])
    def test_poc_returns_nonempty_string(self, framework):
        poc = fw.build_poc_html("http://example.com/", framework, "<img src=x onerror=alert(1)>")
        assert isinstance(poc, str)
        assert len(poc) > 50

    def test_lit_poc_contains_unsafe_html(self):
        poc = fw.build_poc_html("http://example.com/", "lit", "<b>payload</b>")
        assert "unsafeHTML" in poc

    def test_lit_poc_contains_cdn_import(self):
        poc = fw.build_poc_html("http://example.com/", "lit", "payload")
        assert "lit" in poc.lower() and ("cdn" in poc.lower() or "import" in poc.lower() or "jsdelivr" in poc.lower())

    def test_unknown_framework_returns_empty(self):
        poc = fw.build_poc_html("http://example.com/", "unknown_fw", "payload")
        assert poc == ""

    def test_empty_payload_returns_empty(self):
        poc = fw.build_poc_html("http://example.com/", "lit", "")
        assert poc == ""


# ---------------------------------------------------------------------------
# Violation structure
# ---------------------------------------------------------------------------
class TestViolationStructure:
    def test_each_finding_has_required_keys(self):
        findings = fw.find_dangerous_patterns(LIT_UNSAFE_HTML, "lit")
        for f in findings:
            assert "pattern" in f
            assert "description" in f
            assert "severity" in f
            assert "snippet" in f

    def test_severity_is_valid(self):
        findings = fw.find_dangerous_patterns(VUE3_VHTML, "vue")
        valid = {"high", "medium", "low"}
        for f in findings:
            assert f["severity"] in valid, f"invalid severity: {f['severity']}"

    def test_analyze_page_adds_framework_field(self):
        result = fw.analyze_page(LIT_UNSAFE_HTML)
        for f in result["findings"]:
            assert "framework" in f
            assert f["framework"] == "lit"
