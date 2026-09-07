"""L3 DOM + L7 advanced-layer methods, as a Scanner mixin.

Phase 40 split: methods moved verbatim from scanner.py.  Provides
_scan_dom, _scan_jsonp, _scan_csp, _scan_mutation, _scan_dom_clobber,
_scan_template and _scan_polyglot.
"""
from __future__ import annotations

from __future__ import annotations

import secrets

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
from . import spa_crawler as spa_mod
from .findings import (Finding, _DEFAULT_TRANSFORMS,
                       _norm, _proof, _safe_snippet)
from .logger import get_logger
from .stealth import marker as _stem_marker

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
        if engine is not None and dom_engine.page_has_client_js(text):
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

    def _try_pre_encoded(self, req, url, method, params, data, param,
                         is_body, orig_value, struct, context):
        """Phase 34: fire container-encoded probes (base64/JWT/JSON).

        The base payload is token-marked FIRST, then re-wrapped into the
        container the original value used -- so the app decodes it back to
        the executable payload and the semantic verifier can confirm it.
        No transform chains: the container encoding IS the transformation.
        """
        self.coverage.touch_layer(
            url, "L1_pre_encoded", method,
            detail=f"param='{param}' struct={struct}")
        for base in pre_mod.PRE_ENCODE_BASES:
            token = "xssv_" + secrets.token_hex(4)
            marked = verifier.mark(base, token)
            enc = pre_mod.encode_payload(orig_value, struct, marked)
            if not enc:
                continue
            probe = self._set_param(params, data, param, enc, is_body)
            try:
                resp2 = req.request(method, url, params=probe["params"],
                                    data=probe["data"])
                self._bump()
                self.coverage.record_request(url, method)
            except Exception:
                continue
            w = wafmod.detect(resp2)
            if w.get("blocked") and w.get("reason"):
                continue
            v = verifier.verify_semantic(resp2.text, token,
                                         response_headers=dict(resp2.headers))
            if v["confirmed"]:
                self._add(Finding(**{
                    "url": url, "method": method, "param": param,
                    "type": "reflected", "context": context,
                    "payload": enc,
                    "transform": [f"pre_encode:{struct}"],
                    "severity": "high", "confidence": "high",
                    "detail": v["detail"] + f" (pre-encoded {struct} param)",
                    "headless": None,
                    "proof": _proof(resp2, method, param, enc),
                }))
                return True
        return False

    def _probe_reflection_profile(self, req, url, method, params, data,
                                  param, is_body):
        """Phase 31: sandwich-marker probe (DalFox-style).

        Sends ONE extra request whose value is ``<token>"'><>()=/;`` and
        analyzes which special characters survive verbatim / come back
        encoded / are stripped.  Returns a reflection-profile dict, or
        None when the probe itself did not reflect (the caller then keeps
        the default payload/transform order -- prioritization only).
        """
        probe_token = _stem_marker("xssp_") + secrets.token_hex(4)
        probe_val = rp_mod.build_probe(probe_token)
        probe = self._set_param(params, data, param, probe_val, is_body)
        try:
            resp = req.request(method, url, params=probe["params"],
                               data=probe["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception:
            return None
        prof = rp_mod.profile_reflection(resp.text or "", probe_token)
        if prof is None or not prof["reflected"]:
            return None
        self.coverage.touch_layer(url, "L1_reflection_profile", method,
                                  detail=prof["detail"])
        if self.verbose:
            _log.debug(f"    [profile] {prof['detail']}")
        return prof

    @staticmethod
    def _dedupe_endpoint_signatures(endpoints):
        """Phase 32: drop endpoints whose scan signature was already seen.

        Signature = (method, host, path, sorted param names, sorted body
        field names).  Query VALUES are deliberately excluded: /search?q=1
        and /search?q=2 exercise the same sink, so only the first crawl
        result per signature is scanned.  Index 0 (the user entry point)
        always survives.
        """
        from urllib.parse import urlparse
        seen = set()
        out = []
        for i, (url, method, params, data) in enumerate(endpoints):
            try:
                p = urlparse(url)
                sig = (method.upper(), p.netloc.lower(), p.path or "/",
                       tuple(sorted(params or {})),
                       tuple(sorted(data or {})))
            except Exception:
                sig = None  # unparseable -> keep as-is
            if i and sig is not None and sig in seen:
                continue
            if sig is not None:
                seen.add(sig)
            out.append((url, method, params, data))
        return out

    @staticmethod
    def _audit_priority(endpoints):
        """Phase 33: rank endpoints by attack-surface value (Burp's 80/20
        audit ordering).  More parameters first, POST before GET, and
        interesting path keywords (admin/comment/profile/...) boosted.
        Stable sort: equal-value endpoints keep their crawl order."""
        _KEYS = ("admin", "comment", "profile", "search", "upload",
                 "message", "config", "user", "settings", "feedback")

        def _score(ep):
            url, method, params, data = ep
            s = (len(params or {}) + len(data or {})) * 10
            if method.upper() == "POST":
                s += 5
            low = (url or "").lower()
            if any(k in low for k in _KEYS):
                s += 5
            return -s

        return sorted(endpoints, key=_score)

    def _set_param(self, params, data, param, value, is_body):
        p = dict(params)
        d = dict(data)
        if is_body:
            d[param] = value
        else:
            p[param] = value
        return {"params": p, "data": d}

    def _record(self, req, url, method, param, is_body, ftype, context, payload,
                tset, verify, resp, token):
        headless = None
        if self.use_headless:
            headless = verifier.verify_headless(
                url, method,
                params=None if is_body else {param: payload},
                data={param: payload} if is_body else None,
                headers=dict(self.req.session.headers),
                token=token)
        severity, confidence = "high", "high"
        detail = verify["detail"]
        # Phase 32: content-type confidence downgrade (ZAP-style).  Markup
        # reflected into a JSON/plain-text response cannot execute in a
        # browser tab -- keep the finding (the reflection is real) but mark
        # it low-confidence so humans prioritize real HTML sinks first.
        try:
            ctype = (resp.headers.get("Content-Type") or "").lower() if resp is not None else ""
        except Exception:
            ctype = ""
        if ctype and not any(t in ctype for t in (
                "text/html", "application/xhtml", "image/svg")):
            confidence = "low"
            detail = (detail + " (non-HTML content-type '%s')"
                      % ctype.split(";")[0].strip())
        self._add(Finding(**{
            "url": url, "method": method, "param": param,
            "type": ftype, "context": context, "payload": payload,
            "transform": tset, "severity": severity,
            "confidence": confidence, "detail": detail,
            "headless": headless, "proof": _proof(resp, method, param, payload),
        }))

    def _add(self, finding: Finding):
        # Phase 48: see findings.attach_replay_ctx -- carries the CSRF /
        # hidden fields of the original request onto confirmed findings.
        try:
            from .findings import attach_replay_ctx
            attach_replay_ctx(finding, getattr(self, "_tl", None))
        except Exception:
            pass
        with self._lock:
            self.findings.append(finding)
        if self._progress:
            self._progress.on_finding(finding.data)

    def _bump(self):
        with self._lock:
            self.requests_made += 1
        if self._progress:
            self._progress.on_request()

    # -- dedup + poc ---------------------------------------------------------
    @staticmethod
    def _dedup_key(d: dict) -> tuple:
        """Group key for collapsing duplicate findings.  Two findings are the
        same issue when they hit the same sink with the same parameter on the
        same (normalized) URL and context -- regardless of which crawl path or
        transform variant discovered them.

        For DOM types we strip the query string: a DOM XSS reachable via
        location.hash / document.cookie is independent of URL query params, so
        ``/dom`` and ``/dom?probe=1`` are the same finding and must merge.
        """
        url = _norm(d.get("url") or "")
        if d.get("type") in ("dom", "dom_dynamic"):
            url = url.split("?", 1)[0]
        return (d.get("type"), url, d.get("param"), d.get("context"))

    def dedup(self):
        """Collapse duplicate findings, keeping the highest-severity copy of
        each (type, url, param, context) group.  Idempotent."""
        if not self.findings:
            return
        groups: dict = {}
        order: list = []
        for f in self.findings:
            k = self._dedup_key(f.data)
            if k not in groups:
                groups[k] = f
                order.append(k)
            else:
                # keep the higher-severity finding; tie-break: already kept.
                sev = SEVERITY_ORDER.get(f.data.get("severity"), 0)
                cur = SEVERITY_ORDER.get(groups[k].data.get("severity"), 0)
                if sev > cur:
                    groups[k] = f
        self.findings = [groups[k] for k in order]

    def attach_pocs(self):
        """Generate a reproducible PoC for every finding (curl / URL / HTML).

        Also enriches each finding with a CVSS v3.1 score and a replay
        command (curl/browser URL/HTML PoC).  Call once after scanning +
        dedup, before building reports.
        """
        for f in self.findings:
            try:
                cookies = None
                replay_headers = None
                if getattr(self, "poc_include_auth", False):
                    try:
                        cookies = self.req.session.cookies.get_dict() or None
                    except Exception:
                        cookies = None
                    # Phase 98: same replay-header logic as the sync
                    # attach_pocs (Authorization / X-API-Key / ...).
                    try:
                        replay_headers = (dict(self.req.session.headers)
                                          or None)
                    except Exception:
                        replay_headers = None
                f.data["poc"] = pocmod.build_poc(
                    f, csrf_fields=f.data.get("csrf_fields"),
                    cookies=cookies, headers=replay_headers)
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] PoC build error: {e}")
                f.data["poc"] = {"curl": "", "url": "", "html": ""}
            # CVSS v3.1 scoring (Phase 6).
            try:
                enriched = cvss_mod.enrich_finding(f.data)
                f.data["cvss_score"] = enriched["cvss_score"]
                f.data["cvss_severity"] = enriched["cvss_severity"]
                f.data["cvss_vector"] = enriched["cvss_vector"]
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] CVSS score error: {e}")
                f.data.setdefault("cvss_score", 0.0)
                f.data.setdefault("cvss_severity", "info")
                f.data.setdefault("cvss_vector", "")
            # Replay PoC (curl/browser/HTML).
            try:
                replay = replay_mod.replay_for_finding(f.data, cookies=cookies)
                f.data["replay"] = replay
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] replay build error: {e}")
                f.data["replay"] = {}

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

