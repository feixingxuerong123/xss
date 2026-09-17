"""L3 DOM + L7 advanced-layer methods, as a Scanner mixin.

Phase 40 split: methods moved verbatim from scanner.py.  Provides
_scan_dom, _scan_jsonp, _scan_csp, _scan_mutation, _scan_dom_clobber,
_scan_template and _scan_polyglot.
"""
from __future__ import annotations

import copy
import secrets
from typing import TYPE_CHECKING

from . import payloads
from . import verifier
from . import transform
from . import context as ctx
from . import csp as csp_mod
from . import cors_check as cors_mod
from . import xs_leaks as xsleak_mod
from . import jsonp as jsonp_mod
from . import mutation as mxss_mod
from . import dom_clobber as clobber_mod
from . import template as tpl_mod
from . import polyglot as poly_mod
from . import dom as dommod
from . import dom_engine
from .findings import Finding
from .logger import get_logger
from .requester import JsonBody

if TYPE_CHECKING:  # only ever referenced inside annotations
    import requests

_log = get_logger("scanner.mixins")



class AdvancedLayerMixin:
    """L3 DOM + L7 advanced detection methods."""

    def _scan_dom(self, req, url) -> tuple[str, "requests.Response | None"]:
        """DOM-XSS layer.

        L3 (static): heuristic source->sink taint analysis of the page source.
            Cheap, dependency-free, but can only *guess* whether the tainted
            value truly reaches a sink at runtime. Reported as medium/low hints.
        L6/DOM-dynamic (real browser): execute the page in Playwright with the
            sinks instrumented and a unique marker injected into the
            attacker-controllable source. When the marker is observed flowing
            into a sink, that is a CONFIRMED, high-confidence DOM-XSS.

        If a sink is confirmed dynamically we suppress the matching static hint
        so the same issue isn't reported twice at two severities.

        Returns ``(text, resp)`` where ``text`` is the fetched page HTML
        (empty string on failure) and ``resp`` is the response object (or
        ``None`` on failure).  The caller can reuse ``resp`` for header-only
        checks (e.g. CSP analysis) to avoid a redundant duplicate GET.
        """
        try:
            resp = req.get(url)
            self._bump()
            self.coverage.record_request(url, "GET")
        except Exception:
            return "", None
        text = resp.text or ""

        # --- L3: static taint heuristic (medium/low hints) ---
        static_results = dommod.analyze(text, is_html=True)
        # Phase 20-3: record L3 DOM-static layer (always runs).
        self.coverage.touch_layer(url, "L3_dom_static", "GET",
                                  detail=f"{len(static_results)} hint(s)")

        # --- L6: real-browser dynamic confirmation (high confidence) ---
        dyn_findings: list = []
        engine = self._dom_engine
        # Phase 154: page_has_client_js alone is too coarse -- 41 of 57
        # slow benchmark cases had JS but no possible sink and paid ~5.6s
        # each for nothing.  page_can_run_sink lets every external-script
        # page through (SPA bundles), so this only skips provably dead
        # browser sessions.
        if (engine is not None and dom_engine.page_has_client_js(text)
                and dom_engine.page_can_run_sink(text)):
            # Phase 20-3: record L6 DOM-dynamic layer when a real browser
            # engine is available and the page has client-side JS.
            self.coverage.touch_layer(url, "L6_dom_dynamic", "GET",
                                      detail="playwright engine")
            try:
                dyn_findings = engine.analyze(url)
            except Exception:
                dyn_findings = []

        # Collect normalized dynamic sinks for dedup against static hints.
        dyn_sinks: set = set()
        for d in dyn_findings:
            s = (d.get("sink") or "").lower()
            dyn_sinks.add(s)
            dyn_sinks.add(s.split(".")[-1])  # Element.innerHTML -> innerHTML

        def _suppressed(r) -> bool:
            norm = (r.get("type") or "").lower()
            hay = ((r.get("type") or "") + " " + (r.get("context") or "") + " "
                   + (r.get("detail") or "")).lower()
            if not hay:
                return False
            # suppress when the confirmed dynamic sink name appears anywhere in
            # the static hint's text (type/context/detail).
            return any(s and s in hay for s in dyn_sinks)

        for r in static_results:
            if _suppressed(r):
                continue  # confirmed dynamically; the dynamic finding covers it
            self._add(Finding(**{
                "url": url, "method": "GET", "param": None,
                "type": "dom", "context": r.get("type"),
                "payload": r.get("snippet", ""), "transform": [],
                "severity": "medium" if r.get("confidence") == "medium" else "low",
                "confidence": r.get("confidence", "low"),
                "detail": r.get("detail", ""),
                "headless": None, "proof": None,
            }))
            self.coverage.record_finding(url, "GET")

        for d in dyn_findings:
            self._add(Finding(**{
                "url": url, "method": "GET", "param": None,
                "type": "dom_dynamic", "context": d.get("sink"),
                "payload": d.get("snippet", ""), "transform": [],
                "severity": "high", "confidence": d.get("confidence", "high"),
                "detail": d.get("detail", ""),
                "headless": {"available": True, "confirmed": True,
                             "detail": "marker executed in real browser sink"},
                "proof": d.get("snippet", ""),
            }))
            self.coverage.record_finding(url, "GET")
        return text, resp

    # -- helpers -----------------------------------------------------------
    def _is_marker_escaped(self, text: str, marker: str) -> bool:
        """Phase 27-1: detect whether the marker is HTML-encoded in the response.

        When the server applies context-aware output encoding, the marker
        (a plain alphanumeric token like ``xss9a3f``) will appear in the
        response but any ``<``/``>``/``"`` characters around it will be
        encoded as ``&lt;``/``&gt;``/``&quot;``.  We detect this by
        checking whether the marker appears inside an escaped context:
        if the character immediately before or after the marker (in the
        raw response) is part of an HTML entity (``&...;``), the server
        is encoding the surrounding input.

        Returns True if the marker appears to be inside an escaped
        context (early-stop is safe), False otherwise.
        """

        # Phase 93: delegates to the canonical implementation in
        # context.py -- do not re-implement it here.
        return ctx.is_marker_escaped(text, marker)

    # NOTE (2026-09-14 cleanup): the stale duplicates that used to live
    # here (_try_pre_encoded, _probe_reflection_profile, _add, dedup,
    # attach_pocs, _set_param, _record, ...) were deleted.  Scanner
    # (core/scanner.py) defines all of them, so MRO shadowed these
    # copies unconditionally -- they were dead.  Worse, they referenced
    # seven module-level names (pre_mod/wafmod/rp_mod/pocmod/cvss_mod/
    # replay_mod/SEVERITY_ORDER) that are only defined in scanner.py,
    # so activating any of them would have raised NameError; and two of
    # them (_set_param/_record) were missing the newer JSON-body
    # handling that Scanner has.  Scanner is the single source of truth.
    # -- L7 advanced detection layers (Phase 1+) ---------------------------
    def _scan_jsonp(self, req, url, method, params, data):
        """JSONP callback XSS detection.

        Probes common callback parameter names (callback, jsonp, cb, ...)
        on the endpoint.  For each, sends a marker and checks whether the
        response is JSONP-shaped AND starts with our marker.

        If the URL already carries a callback-like parameter (e.g.
        ``?callback=foo``), that parameter is tested FIRST since it's the
        one the application actually uses.
        """
        # Phase 20-3: record L7 JSONP layer (always runs -- probes candidates).
        self.coverage.touch_layer(url, "L7_jsonp", method,
                                  detail="probed callback params")
        existing = set(params.keys()) | set(data.keys())
        # Test existing callback-like params first, then probe candidates.
        existing_cb = [p for p in existing if p in jsonp_mod.candidate_params()]
        candidates = existing_cb + [p for p in jsonp_mod.candidate_params()
                                    if p not in existing][:8]
        marker = jsonp_mod.confirm_marker()
        for cb_param in candidates:
            send_params = dict(params)
            send_data = dict(data)
            if method.upper() == "POST":
                send_data[cb_param] = marker
            else:
                send_params[cb_param] = marker
            try:
                resp = req.request(method, url, params=send_params,
                                    data=send_data)
                self._bump()
                self.coverage.record_request(url, method)
            except Exception:
                continue
            result = jsonp_mod.analyze_response(resp.text or "", marker)
            if result["exploitable"]:
                # Secondary verification: confirm dangerous chars survive.
                # A whitelist that only allows [a-zA-Z0-9_.] will reflect the
                # marker (a valid identifier) but reject alert(1)// -- meaning
                # the endpoint is NOT truly exploitable.
                danger_payload = "alert(1)//"
                send_params2 = dict(params)
                send_data2 = dict(data)
                if method.upper() == "POST":
                    send_data2[cb_param] = danger_payload
                else:
                    send_params2[cb_param] = danger_payload
                try:
                    resp2 = req.request(method, url, params=send_params2,
                                        data=send_data2)
                    self._bump()
                    self.coverage.record_request(url, method)
                except Exception:
                    continue
                # Check if the dangerous payload survived at response start
                danger_result = jsonp_mod.analyze_response(
                    resp2.text or "", danger_payload)
                if not danger_result["marker_reflected"]:
                    # Dangerous chars were sanitized -> not exploitable
                    continue
                poc = jsonp_mod.build_poc(url, cb_param,
                                          result["poc_payload"])
                with self._lock:
                    self.findings.append(Finding(
                        url=url, method=method, param=cb_param,
                        payload=result["poc_payload"],
                        context="script_block",
                        severity="high",
                        type="jsonp_xss",
                        evidence=f"callback name reflected at response start; "
                                 f"callback_name={result['callback_name']}",
                        poc_html=poc,
                    ))
                self.coverage.record_finding(url, method)
                if self.verbose:
                    _log.debug(f"    [+] JSONP XSS via '{cb_param}' parameter")

    def _scan_csp(self, req, url, resp=None):
        """CSP header analysis.  Reports weak/bypassable CSP as an info/medium
        finding so the auditor knows the residual XSS risk.

        ``resp`` is an optional pre-fetched response (Phase 21-3): when the
        caller already has a response for this URL (e.g. from _scan_dom),
        pass it here to avoid a redundant duplicate GET.
        """
        # Phase 20-3: record L7 CSP layer (always runs -- header parse).
        self.coverage.touch_layer(url, "L7_csp", "GET",
                                  detail="parsed CSP header")
        if resp is None:
            try:
                resp = req.get(url)
                self._bump()
                self.coverage.record_request(url, "GET")
            except Exception:
                return
        # CSP can be in Content-Security-Policy or Content-Security-Policy-Report-Only.
        csp_header = ""
        for h in ("Content-Security-Policy",
                   "Content-Security-Policy-Report-Only"):
            val = resp.headers.get(h) if hasattr(resp, "headers") else None
            if val:
                csp_header = val
                break
        if not csp_header:
            return  # No CSP -> nothing to analyze (no finding either).
        report = csp_mod.analyze(csp_header)
        if not report.bypassable:
            return
        best = csp_mod.best_bypass(csp_header) or {}
        with self._lock:
            self.findings.append(Finding(
                url=url, method="GET", param="(header)",
                payload=best.get("payload", ""),
                context="csp_header",
                severity="medium" if report.bypassable else "info",
                type="csp_bypass",
                evidence="; ".join(report.weak),
                csp_header=csp_header,
                bypass_type=best.get("type", ""),
                bypass_reason=best.get("reason", ""),
            ))
        self.coverage.record_finding(url, "GET")
        if self.verbose:
            _log.debug(f"    [*] CSP bypassable: {best.get('type', 'unknown')}")

    def _scan_cors(self, req, url):
        """Target CORS audit (Phase 51): origin-reflection detection.

        Runs ONCE per origin (the ``_cors_checked`` set on the scanner),
        because the CORS policy is a host-level property -- probing it on
        every crawled endpoint would burn the request budget for nothing.
        Two cheap probes (GET with an attacker Origin, then an OPTIONS
        preflight if the GET did not reflect) classify the policy via
        cors_check.classify; a permissive policy becomes a
        ``cors_misconfig`` finding (high when credentials ride along).
        """
        # Host-level dedup across endpoints of the same origin.
        checked = getattr(self, "_cors_checked", None)
        if checked is None:
            checked = set()
            self._cors_checked = checked
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            return
        if not origin or origin in checked:
            return
        checked.add(origin)
        self.coverage.touch_layer(url, "L7_cors", "GET",
                                  detail="ACAO origin-reflection probe")
        evil = cors_mod.EVIL_ORIGIN
        for method, extra in cors_mod.PROBES:
            try:
                resp = req.request(method, url, headers={**extra})
                self._bump()
                self.coverage.record_request(url, method)
            except Exception:
                continue
            headers = getattr(resp, "headers", None)
            if headers is None:
                continue
            acao = headers.get("Access-Control-Allow-Origin") or ""
            acac = headers.get("Access-Control-Allow-Credentials") or ""
            verdict = cors_mod.classify(acao, acac, evil)
            if verdict is None:
                continue
            sev, reason = verdict
            evidence = (
                f"probe: {method} {url}\n"
                f"Origin: {evil}\n"
                f"-> Access-Control-Allow-Origin: {acao or '(absent)'}\n"
                f"-> Access-Control-Allow-Credentials: "
                f"{acac or '(absent)'}")
            with self._lock:
                self.findings.append(Finding(
                    url=url, method=method, param="",
                    payload=evil, context="cors_header",
                    severity=sev, type="cors_misconfig",
                    confidence="firm", evidence=evidence,
                    detail=reason,
                ))
            self.coverage.record_finding(url, method)
            if self.verbose:
                _log.debug(f"    [+] CORS misconfiguration ({sev}): {reason}")
            return  # one finding per origin is enough

    def _scan_xsleak_audit(self, url: str, resp=None):
        """Phase 53: XS-Leaks surface audit (opt-in via ``xsleak_audit``).

        A page that sets NO cross-origin isolation (COOP/CORP/COEP) and no
        framing guard leaves every cross-site-leak channel open for the
        origin.  Records ONE low ``xs_leak_surface`` finding per origin by
        reusing the page response already fetched by the caller (zero extra
        requests).  Only fires for GET pages with response headers.
        """
        if not getattr(self, "xsleak_audit", False):
            return
        if resp is None or not hasattr(resp, "headers"):
            return
        checked = getattr(self, "_xsleak_audited", None)
        if checked is None:
            checked = set()
            self._xsleak_audited = checked
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            return
        if not origin or origin in checked:
            return
        checked.add(origin)
        try:
            headers = getattr(resp, "headers", None)
            verdict = xsleak_mod.audit_mitigations(headers or {})
        except Exception:
            return
        if verdict is None:
            return
        self.coverage.touch_layer(url, "L7_xsleak", "GET",
                                  detail="isolation-header surface audit")
        with self._lock:
            self.findings.append(Finding(
                url=url, method="GET", param="",
                payload="", context=verdict.get("context", "response_headers"),
                severity=verdict.get("severity", "low"),
                type=verdict.get("type", "xs_leak_surface"),
                confidence=verdict.get("confidence", "firm"),
                evidence=verdict.get("evidence", ""),
                detail=verdict.get("detail", ""),
            ))
        self.coverage.record_finding(url, "GET")

    def _scan_mutation(self, req, url, method, params, data, param, is_body,
                        marker, response_text):
        """mXSS detection: inject mXSS payloads and check reflection + sinks.

        Called from _scan_param when a marker is reflected, so we have the
        page's response in hand to check for mutating sinks (innerHTML etc.).
        """
        # Phase 20-3: record L7 mXSS layer.
        self.coverage.touch_layer(url, "L7_mutation", method,
                                  detail=f"param='{param}'")
        # Pick the best mXSS payload for the surrounding context.
        idx = response_text.find(marker)
        around = response_text[max(0, idx-100):idx+100] if idx >= 0 else ""
        payload = mxss_mod.best_payload_for_context(around) or \
                  mxss_mod.payloads()[0]
        send = self._set_param(params, data, param, payload, is_body)
        try:
            resp = req.request(method, url, params=send["params"],
                                data=send["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception:
            return
        result = mxss_mod.analyze(resp.text or "", payload)
        if result["exploitable"]:
            with self._lock:
                self.findings.append(Finding(
                    url=url, method=method, param=param,
                    payload=payload,
                    context="html_element",
                    severity="high",
                    type="mutation_xss",
                    evidence=f"reflected + mutating sinks: {result['sinks']}",
                    vector=result["vector"],
                ))
            self.coverage.record_finding(url, method)
            if self.verbose:
                _log.debug(f"    [+] mXSS: payload reflected with sinks "
                      f"{result['sinks']}")

    def _scan_dom_clobber(self, req, url, method, params, data, param, is_body):
        """DOM clobbering: inject id/name attributes and check for JS refs.

        Tries BOTH a unique token (to track reflection) and common clobber
        targets (x, action, location) that the page's JS is likely to
        reference via getElementById or property access.
        """
        # Phase 20-3: record L7 DOM clobber layer.
        self.coverage.touch_layer(url, "L7_dom_clobber", method,
                                  detail=f"param='{param}'")
        # Strategy 1: unique token — proves the endpoint reflects id= attrs
        # without escaping.  This alone doesn't prove clobbering, but it's a
        # prerequisite.
        token = "xclob_" + secrets.token_hex(3)
        payload = f'<a id={token} name={token} href="javascript:alert(1)">x</a>'
        send = self._set_param(params, data, param, payload, is_body)
        try:
            resp = req.request(method, url, params=send["params"],
                                data=send["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception:
            return
        text = resp.text or ""
        result = clobber_mod.analyze(text, token)
        # Strategy 2: if reflection is confirmed, also check if the page's JS
        # references ANY common clobber target (x, action, location, ...) via
        # getElementById or property access.  If so, the attacker can inject
        # id=<that target> to clobber the JS reference.
        if result["reflected"]:
            import re as _re
            # Check for getElementById("...") or querySelector("#...") with
            # any argument, plus property access patterns.
            js_refs = []
            for m in _re.finditer(r'<script[^>]*>(.*?)</script>',
                                  text, _re.IGNORECASE | _re.DOTALL):
                script = m.group(1)
                # getElementById('any_id') — the any_id is the clobber target
                for ref in _re.finditer(
                    r'getElementById\(\s*[\'"]([^\'"]+)[\'"]\s*\)', script):
                    js_refs.append(f"getElementById('{ref.group(1)}')")
                # querySelector('#any_id')
                for ref in _re.finditer(
                    r'querySelector\(\s*[\'"]#([^\'"]+)[\'"]\s*\)', script):
                    js_refs.append(f"querySelector('#{ref.group(1)}')")
                # document.any_id / window.any_id property access
                for ref in _re.finditer(
                    r'(?:document|window)\.([a-zA-Z_]\w*)\b', script):
                    name = ref.group(1)
                    if name not in ("write", "writeln", "cookie", "domain",
                                    "location", "title", "referrer",
                                    "getElementById", "querySelector",
                                    "createElement", "body", "head",
                                    "forms", "images", "links", "scripts"):
                        js_refs.append(f"document.{name}")
            danger = clobber_mod.has_danger_sink(text)
            if js_refs and danger:
                with self._lock:
                    self.findings.append(Finding(
                        url=url, method=method, param=param,
                        payload=payload,
                        context="html_element",
                        severity="high",
                        type="dom_clobber",
                        evidence=f"reflected id={token}; JS refs: "
                                 f"{js_refs[:3]}; danger sink present",
                    ))
                self.coverage.record_finding(url, method)
                if self.verbose:
                    _log.debug(f"    [+] DOM clobber via id reflection + JS refs "
                          f"({js_refs[:3]})")
                return
        # Fallback: original token-based detection (exact match to our id)
        if result["exploitable"]:
            with self._lock:
                self.findings.append(Finding(
                    url=url, method=method, param=param,
                    payload=payload,
                    context="html_element",
                    severity="high",
                    type="dom_clobber",
                    evidence=f"reflected id={token}; JS refs: {result['js_refs']}",
                ))
            self.coverage.record_finding(url, method)
            if self.verbose:
                _log.debug(f"    [+] DOM clobber via id={token}")

    def _scan_template(self, req, url, method, params, data, param, is_body,
                        response_text):
        """Template SSTI -> XSS: detect client-side template engines running.

        Two-stage detection:
        1. Send a probe ``{{7*7}}`` — if the response contains ``49`` (the
           rendered result), a template engine is executing user input.
        2. Send the framework-specific XSS payload to confirm exploitation.
        """
        # Phase 20-3: record L7 template SSTI layer.
        self.coverage.touch_layer(url, "L7_template", method,
                                  detail=f"param='{param}'")
        # Stage 1: probe with {{7*7}} to detect template rendering.
        probe_payload = "{{7*7}}"
        send = self._set_param(params, data, param, probe_payload, is_body)
        try:
            resp = req.request(method, url, params=send["params"],
                                data=send["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception:
            return
        probe_text = resp.text or ""
        frameworks = tpl_mod.exploitable_frameworks(probe_text)
        if not frameworks:
            return
        for fw, confirm in frameworks:
            send = self._set_param(params, data, param, confirm, is_body)
            try:
                resp = req.request(method, url, params=send["params"],
                                    data=send["data"])
                self._bump()
                self.coverage.record_request(url, method)
            except Exception:
                continue
            # If the confirm payload's effect appears, we have SSTI -> XSS.
            # Heuristic: the framework's eval-style execution often produces
            # an error page or the alert marker; treat reflection of the
            # payload as a strong indicator since the probe already confirmed
            # the engine runs.
            if confirm in (resp.text or ""):
                with self._lock:
                    self.findings.append(Finding(
                        url=url, method=method, param=param,
                        payload=confirm,
                        context="template_angular",
                        severity="critical",
                        type=f"template_ssti_{fw.lower()}",
                        evidence=f"{fw} template engine executing user input "
                                 f"(probe {{{{7*7}}}} rendered to 49)",
                    ))
                if self.verbose:
                    _log.debug(f"    [+] {fw} SSTI -> XSS")
                break  # one framework per param is enough

    def _scan_polyglot(self, req, url, method, params, data, param, is_body):
        """Polyglot injection: try context-spanning payloads when regular
        context-specific payloads didn't fire.

        Phase 13a enhancement: now tries THREE polyglot flavours in order:
          1. Multi-stage polyglot (breaks out of multiple contexts at once).
          2. Context-aware polyglot (tuned to the detected reflection context).
          3. WAF-evasion polyglot (multi-stage + WAF-specific bypass chain).
        The original single-stage polyglot is kept as a final fallback.
        """
        # Phase 20-3: record L7 polyglot layer.
        self.coverage.touch_layer(url, "L7_polyglot", method,
                                  detail=f"param='{param}'")
        token = poly_mod.make_token()
        msg = f"xss_poly_{token}"
        # Build the candidate polyglots to try, in priority order.
        polies: list[tuple[str, str]] = [
            ("multi_stage", poly_mod.build_multi_stage_polyglot(token)),
            ("waf_evasion", poly_mod.build_waf_evasion_polyglot(
                token, self.waf_name)),
            ("generic",     poly_mod.build_polyglot(token)),
        ]
        for kind, poly in polies:
            send = self._set_param(params, data, param, poly, is_body)
            try:
                resp = req.request(method, url, params=send["params"],
                                    data=send["data"])
                self._bump()
                self.coverage.record_request(url, method)
            except Exception:
                continue
            text = resp.text or ""
            # The polyglot token appears in the alert call -- if it's reflected
            # in an EXECUTABLE context (not just echoed as escaped text), the
            # page is vulnerable in some context (the polyglot tries multiple
            # breakouts).  We reuse the semantic verifier so an html.escape'd
            # endpoint (e.g. /safe) does NOT false-positive: the token survives
            # escaping (it's alphanumeric) but the payload's HTML tags don't,
            # so verify_semantic correctly reports non-executable.
            v = verifier.verify_semantic(text, msg,
                                         response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None)
            if v["confirmed"]:
                with self._lock:
                    self.findings.append(Finding(
                        url=url, method=method, param=param,
                        payload=poly,
                        context=v.get("context") or "html_element",
                        severity="medium",   # polyglot = unconfirmed which context
                        type="polyglot_reflection",
                        evidence=f"polyglot ({kind}) token '{msg}' reflected: "
                                 f"{v['detail']}",
                    ))
                self.coverage.record_finding(url, method)
                if self.verbose:
                    _log.debug(f"    [*] polyglot ({kind}) reflected (token={token})")
                return  # one confirmed polyglot finding is enough


    # -- shared parameter plumbing (moved from Scanner, Phase 132) ---------
    #
    # These two used to live on ``Scanner``.  They are needed by BOTH
    # engines: the sync Scanner runs them directly, and the async engine
    # reaches them through ``_AsyncScannerShim`` (which now inherits this
    # mixin).  Keeping one copy here keeps the two engines from drifting --
    # the async engine had no equivalent of either, so ``--async`` never
    # ran the L7 parameter layers at all.

    def _set_param(self, params, data, param, value, is_body):
        p = dict(params)
        if is_body and self.json_body is not None:
            # Phase 46: JSON-carrier probe -- set the leaf at the dotted
            # path inside a deep copy of the original document and send it
            # as application/json (Requester translates JsonBody).
            #
            # ``_set_json_leaf`` is defined in scanner.py, which imports
            # this module -- a module-level import here would be circular,
            # so it is resolved lazily on the JSON path only.
            from .scanner import _set_json_leaf
            try:
                obj = copy.deepcopy(self.json_body)
                _set_json_leaf(obj, param, value)
            except Exception:
                obj = dict(self.json_body)
                obj[param] = value
            return {"params": p, "data": JsonBody(obj)}
        d = dict(data)
        if is_body:
            d[param] = value
        else:
            p[param] = value
        return {"params": p, "data": d}

    def _run_advanced_layers(self, req, url, method, params, data, param,
                             is_body, marker, resp_text):
        """L7 advanced layers: mutation / DOM clobber / template / polyglot
        / markdown etc.  Failures here are logged, never fatal."""
        try:
            self._scan_mutation(req, url, method, params, data, param,
                                is_body, marker, resp_text)
            self._scan_dom_clobber(req, url, method, params, data, param,
                                   is_body)
            self._scan_template(req, url, method, params, data, param,
                                is_body, resp_text)
            # Polyglot is a FALLBACK: only run when no other finding was
            # confirmed for this (url, param) -- otherwise it's just noise
            # on top of an already-confirmed XSS.
            already_found = any(
                f.data.get("url") == url and f.data.get("param") == param
                for f in self.findings
            )
            if not already_found:
                self._scan_polyglot(req, url, method, params, data, param,
                                    is_body)
            # Markdown/BBCode XSS (Phase 11): inject markup-renderer payloads
            # when the response looks like it might be rendering markup.
            if self._advanced_layers:
                from . import advanced_layers
                advanced_layers.run_param_layers(
                    self, req, url, method, params, data, param, is_body,
                    resp_text)
        except Exception as e:
            if self.verbose:
                _log.debug(f"    [!] advanced param layers error: {e}")
