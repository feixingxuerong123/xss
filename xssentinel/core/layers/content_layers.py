"""Content/config advanced layers: markdown, Trusted Types, CSP nonce
reuse, cookie tossing, SRI bypass, import maps, sanitizer bypass, CSS
injection, dangling markup, SVG XSS.  (Phase 39 split: moved verbatim.)"""
from __future__ import annotations

import secrets

from .. import markdown_xss as md_mod
from .. import trusted_types as tt_mod
from .. import csp as csp_mod
from .. import cookie_tossing as ct_mod
from .. import sri_bypass as sri_mod
from .. import import_map_xss as imap_mod
from .. import sanitizer_bypass as san_mod
from .. import css_injection as cssi_mod
from .. import dangling_markup as dml_mod
from .. import svg_xss as svg_mod

from .common import _make_finding

def _scan_markdown(scanner, req, url, method, params, data, param, is_body,
                   response_text):
    """Markdown / BBCode XSS: inject markup-renderer payloads."""
    # Phase 20-3: record L8 markdown XSS layer.
    scanner.coverage.touch_layer(url, "L8_markdown", method,
                                 detail=f"param='{param}'")
    try:
        # Only run if the response looks like it might be rendering markup
        # (contains <p>, <br>, <a href>, etc. from previous rendering).
        if not response_text:
            return
        markup_hints = ("<p>", "<br", "<a href", "<ul>", "<ol>", "<li>",
                        "<strong>", "<em>", "<blockquote>")
        if not any(h in response_text for h in markup_hints):
            return
        token = "xsmd_" + secrets.token_hex(3)
        # Use a Markdown payload that embeds our token via an onerror handler.
        base_payload = f'![x](x" onerror=alert("{token}"))'
        send = scanner._set_param(params, data, param, base_payload, is_body)
        try:
            resp = req.request(method, url, params=send["params"],
                               data=send["data"])
            scanner._bump()
            scanner.coverage.record_request(url, method)
        except Exception:
            return
        text = resp.text or ""
        result = md_mod.analyze_response(text, token)
        if not result["reflected"] or not result.get("rendered_html"):
            return
        from .. import verifier
        v = verifier.verify_semantic(text, token,
                                     response_headers=dict(resp.headers))
        if not v["confirmed"]:
            return
        poc_md = md_mod.build_poc_markdown(base_payload)
        scanner._add(_make_finding(
            url=url, method=method, param=param,
            payload=base_payload,
            context="markdown_render",
            severity="high",
            ftype="markdown_xss",
            evidence=(
                f"Markdown/BBCode payload rendered to executable HTML: "
                f"{v['detail']}"
            ),
            poc_markdown=poc_md,
        ))
        scanner.coverage.record_finding(url, method)
        if scanner.verbose:
            print(f"    [+] Markdown XSS via {param}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] markdown layer error: {e}")


# =============================================================================
# Phase 27-2: Trusted Types + CSP nonce reuse layers
# =============================================================================

def _scan_trusted_types(scanner, url: str, html: str, csp_header: str = "") -> None:
    """Trusted Types violation detection.

    Reports four classes of finding:

      * ``trusted_types_taint_flow`` -- user-controlled data flows into a
        DOM sink without a TT policy wrapping it (high severity).
      * ``trusted_types_policy_bypass`` -- a TT policy is registered but
        its ``createHTML`` is an identity function (high severity).
      * ``trusted_types_no_policy`` -- dangerous DOM sinks are present but
        no TT policy is registered (medium -- defense-in-depth gap).
      * ``trusted_types_policy_unused`` -- a TT policy is registered but
        never called via ``policy.createHTML(...)`` (low -- dead code).
    """
    # Phase 27-2: record L8 Trusted Types layer.
    scanner.coverage.touch_layer(url, "L8_trusted_types", "GET",
                                 detail="static page analysis + CSP check")
    try:
        result = tt_mod.analyze_page(html, csp_header)
        if not result["violations"]:
            return
        for v in result["violations"][:2]:
            vtype = v.get("type", "tt_violation")
            ftype_map = {
                "tt_taint_flow": "trusted_types_taint_flow",
                "tt_policy_bypass": "trusted_types_policy_bypass",
                "tt_no_policy": "trusted_types_no_policy",
                "tt_policy_unused": "trusted_types_policy_unused",
            }
            ftype = ftype_map.get(vtype, "trusted_types_violation")
            sink = v.get("sink", "")
            taint_source = v.get("taint_source", "")
            poc = tt_mod.build_poc_html(url, sink, taint_source)
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload=f"(TT: {vtype})",
                context=f"trusted_types_{sink or 'page'}",
                severity=v.get("severity", "medium"),
                ftype=ftype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
                tt_violation_type=vtype,
                tt_sink=sink,
                tt_taint_source=taint_source,
                tt_policy_name=v.get("policy_name", ""),
                tt_enforced_in_csp=result.get("tt_enforced_in_csp", False),
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Trusted Types violation ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] trusted_types layer error: {e}")


def _scan_csp_nonce(scanner, url: str, html: str, csp_header: str = "") -> None:
    """CSP nonce reuse / exposure detection.

    Reports:

      * ``csp_nonce_too_short`` -- nonce is < 16 chars (brute-forceable).
      * ``csp_nonce_predictable`` -- nonce looks sequential (all digits,
        low entropy).
      * ``csp_nonce_misconfigured`` -- CSP declares a nonce but the HTML
        has no ``<script nonce=...>`` tags (page is broken).
      * ``csp_nonce_multi`` -- CSP declares multiple different nonces
        (config bug).
    """
    # Phase 27-2: record L7 CSP nonce layer.
    scanner.coverage.touch_layer(url, "L7_csp_nonce", "GET",
                                 detail="static nonce reuse analysis")
    try:
        if not csp_header:
            return  # no CSP -> no nonce analysis possible
        result = csp_mod.analyze_nonce_reuse(csp_header, html)
        if not result["nonce_in_csp"]:
            return  # CSP has no nonce directive -> nothing to check

        # Report each bypass condition as a separate finding.
        reported = False
        if result["nonce_too_short"]:
            scanner._add(_make_finding(
                url=url, method="GET", param="(header)",
                payload="",
                context="csp_nonce",
                severity="high",
                ftype="csp_nonce_too_short",
                evidence=(
                    f"CSP nonce '{result['csp_nonces'][0]}' is only "
                    f"{result['nonce_length']} chars long (< 16); an "
                    f"attacker can brute-force it and inject "
                    f"<script nonce=KNOWN> to bypass CSP"
                ),
                csp_header=csp_header,
                nonce_value=result["csp_nonces"][0],
                nonce_length=result["nonce_length"],
            ))
            scanner.coverage.record_finding(url, "GET")
            reported = True
            if scanner.verbose:
                print(f"    [+] CSP nonce too short: "
                      f"{result['csp_nonces'][0]} ({result['nonce_length']} chars)")

        if result["nonce_looks_sequential"]:
            scanner._add(_make_finding(
                url=url, method="GET", param="(header)",
                payload="",
                context="csp_nonce",
                severity="high",
                ftype="csp_nonce_predictable",
                evidence=(
                    f"CSP nonce '{result['csp_nonces'][0]}' looks sequential "
                    f"(all digits, low entropy); likely predictable"
                ),
                csp_header=csp_header,
                nonce_value=result["csp_nonces"][0],
            ))
            scanner.coverage.record_finding(url, "GET")
            reported = True
            if scanner.verbose:
                print(f"    [+] CSP nonce looks sequential: "
                      f"{result['csp_nonces'][0]}")

        # Misconfiguration: CSP has nonce but HTML has no nonce attrs.
        if result["csp_nonces"] and not result["html_nonces"]:
            scanner._add(_make_finding(
                url=url, method="GET", param="(header)",
                payload="",
                context="csp_nonce",
                severity="medium",
                ftype="csp_nonce_misconfigured",
                evidence=(
                    f"CSP declares nonce '{result['csp_nonces'][0]}' but no "
                    f"<script nonce=...> appears in the HTML -- scripts "
                    f"will be blocked by CSP (page is broken, or the nonce "
                    f"is applied via a non-standard mechanism)"
                ),
                csp_header=csp_header,
                nonce_value=result["csp_nonces"][0],
            ))
            scanner.coverage.record_finding(url, "GET")
            reported = True
            if scanner.verbose:
                print(f"    [+] CSP nonce misconfigured: declared but "
                      f"absent from HTML")

        # Multiple different nonces in one CSP (config bug).
        if len(set(result["csp_nonces"])) > 1:
            scanner._add(_make_finding(
                url=url, method="GET", param="(header)",
                payload="",
                context="csp_nonce",
                severity="low",
                ftype="csp_nonce_multi",
                evidence=(
                    f"CSP declares {len(set(result['csp_nonces']))} different "
                    f"nonces: {result['csp_nonces']}; usually a single nonce "
                    f"per response is expected (config bug or mid-migration)"
                ),
                csp_header=csp_header,
                nonce_values=result["csp_nonces"],
            ))
            scanner.coverage.record_finding(url, "GET")
            reported = True
            if scanner.verbose:
                print(f"    [+] CSP declares multiple nonces: "
                      f"{result['csp_nonces']}")

        if not reported and scanner.verbose:
            print(f"    [*] CSP nonce analysis: {result['nonce_count_in_html']} "
                  f"nonce= attrs in HTML, nonce length="
                  f"{result['nonce_length']}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] csp_nonce layer error: {e}")


# =============================================================================
# Phase 27-3: Cookie tossing XSS + SRI bypass layers
# =============================================================================

def _scan_cookie_tossing(scanner, req, url: str, html: str) -> None:
    """Cookie-tossing XSS detection.

    Reports:

      * ``cookie_tossing_set_cookie`` -- Set-Cookie with parent Domain
        attribute (server-side tossing vector).
      * ``cookie_tossing_client`` -- document.cookie with domain=
        attribute (client-side tossing vector).
      * ``cookie_sink_flow`` -- cookie read flows into a DOM sink
        (the receiving side of a tossed cookie).
    """
    # Phase 27-3: record L8 cookie-tossing layer.
    scanner.coverage.touch_layer(url, "L8_cookie_tossing", "GET",
                                 detail="Set-Cookie + client-side tossing analysis")
    try:
        # Fetch Set-Cookie headers for this URL (the page-level response
        # we already have doesn't carry headers; we need a fresh GET).
        set_cookie_headers: list[str] = []
        response_host = ""
        try:
            from urllib.parse import urlparse
            response_host = urlparse(url).hostname or ""
            resp = req.get(url)
            scanner._bump()
            # requests' Response.raw.headers.getlist returns all values
            # for a multi-valued header; .headers.get returns only the
            # first.  We try both.
            if hasattr(resp, "raw") and hasattr(resp.raw, "headers"):
                set_cookie_headers = resp.raw.headers.getlist("Set-Cookie")
            if not set_cookie_headers and hasattr(resp, "headers"):
                sc_val = resp.headers.get("Set-Cookie")
                if sc_val:
                    set_cookie_headers = [sc_val]
        except Exception:
            pass

        result = ct_mod.analyze_page(
            html, set_cookie_headers=set_cookie_headers,
            response_host=response_host,
        )
        if not result["violations"]:
            return
        for v in result["violations"][:3]:
            vtype = v.get("type", "cookie_tossing")
            ftype_map = {
                "cookie_tossing_set_cookie": "cookie_tossing_set_cookie",
                "cookie_tossing_client": "cookie_tossing_client",
                "cookie_sink_flow": "cookie_sink_flow",
            }
            ftype = ftype_map.get(vtype, "cookie_tossing")
            cookie_name = v.get("cookie_name", "")
            cookie_domain = v.get("cookie_domain", "")
            # Build a PoC for the tossing cases.
            poc = ""
            if vtype in ("cookie_tossing_set_cookie", "cookie_tossing_client"):
                poc = ct_mod.build_poc_html(
                    url,
                    cookie_name=cookie_name or "theme",
                    tossing_domain=cookie_domain or "",
                )
            scanner._add(_make_finding(
                url=url, method="GET", param=f"(cookie:{cookie_name})" if cookie_name else None,
                payload=f"(cookie tossing: {vtype})",
                context=f"cookie_tossing_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=ftype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
                cookie_name=cookie_name,
                cookie_domain=cookie_domain,
                ct_violation_type=vtype,
                sink=v.get("sink", ""),
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Cookie tossing ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] cookie_tossing layer error: {e}")


def _scan_sri_bypass(scanner, url: str, html: str) -> None:
    """Subresource Integrity (SRI) bypass detection.

    Reports:

      * ``sri_missing_script`` -- cross-origin <script> without integrity=.
      * ``sri_missing_style`` -- cross-origin <link rel=stylesheet> without
        integrity=.
      * ``sri_broken_no_crossorigin`` -- integrity= present but no
        crossorigin attribute (SRI silently disabled).
      * ``sri_malformed`` -- malformed integrity= attribute (treated as
        no SRI by browsers).
      * ``sri_insecure_origin`` -- script/style loaded over http://.
    """
    # Phase 27-3: record L7 SRI bypass layer.
    scanner.coverage.touch_layer(url, "L7_sri_bypass", "GET",
                                 detail="static SRI analysis")
    try:
        result = sri_mod.analyze_page(html, page_url=url)
        if not result["violations"]:
            return
        for v in result["violations"][:3]:
            vtype = v.get("type", "sri_bypass")
            ftype_map = {
                "sri_missing_script": "sri_missing_script",
                "sri_missing_script_summary": "sri_missing_script_summary",
                "sri_missing_style": "sri_missing_style",
                "sri_broken_no_crossorigin": "sri_broken_no_crossorigin",
                "sri_malformed": "sri_malformed",
                "sri_insecure_origin": "sri_insecure_origin",
            }
            ftype = ftype_map.get(vtype, "sri_bypass")
            resource_url = v.get("resource_url", "")
            poc = sri_mod.build_poc_html(
                url, resource_url=resource_url,
                resource_type=v.get("resource_type", "script"),
            )
            scanner._add(_make_finding(
                url=url, method="GET", param="(resource)",
                payload=f"(SRI: {vtype})",
                context=f"sri_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=ftype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
                resource_url=resource_url,
                sri_violation_type=vtype,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] SRI bypass ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] sri_bypass layer error: {e}")


def _scan_import_map(scanner, url: str, html: str,
                     params: dict | None = None) -> None:
    """Import Maps tampering detection (Phase 28-4).

    Reports:

      * ``import_map_user_controlled``        -- import map reflects user input.
      * ``import_map_insecure_origin``        -- entry uses http://.
      * ``import_map_cross_origin``           -- cross-origin entry without integrity.
      * ``import_map_multiple``               -- more than one import map.
      * ``import_map_after_module``           -- import map after <script type=module>.
      * ``import_map_invalid_json``           -- malformed import map JSON.
    """
    scanner.coverage.touch_layer(url, "L7_import_map", "GET",
                                 detail="static import-map analysis")
    try:
        result = imap_mod.analyze_page(html, page_url=url,
                                       extra_markers=params)
        if not result["violations"]:
            return
        for v in result["violations"][:3]:
            vtype = v.get("type", "import_map_bypass")
            poc = imap_mod.build_poc_html(
                url, violation_type=vtype,
                resource_url=v.get("resource_url", ""),
            )
            scanner._add(_make_finding(
                url=url, method="GET", param="(importmap)",
                payload=f"(ImportMap: {vtype})",
                context=f"import_map_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=vtype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
                resource_url=v.get("resource_url", ""),
                import_map_violation_type=vtype,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Import map ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] import_map layer error: {e}")


def _scan_sanitizer_bypass(scanner, url: str, html: str) -> None:
    """HTML Sanitizer bypass detection (Phase 28-4).

    Reports:

      * ``sanitizer_vulnerable_version``         -- known-vulnerable sanitizer version.
      * ``sanitizer_config_*``                   -- unsafe sanitizer configuration.
      * ``sanitizer_output_to_innerhtml``        -- sanitize() result to innerHTML.
      * ``unsanitized_innerhtml_user_source``    -- innerHTML = userVar without sanitizer.
    """
    scanner.coverage.touch_layer(url, "L7_sanitizer_bypass", "GET",
                                 detail="static sanitizer-bypass analysis")
    try:
        result = san_mod.analyze_page(html, page_url=url)
        if not result["violations"]:
            return
        for v in result["violations"][:3]:
            vtype = v.get("type", "sanitizer_bypass")
            poc = san_mod.build_poc_html(
                url, violation_type=vtype,
                sanitizer=v.get("sanitizer", ""),
            )
            scanner._add(_make_finding(
                url=url, method="GET", param="(sanitizer)",
                payload=f"(Sanitizer: {vtype})",
                context=f"sanitizer_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=vtype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
                sanitizer=v.get("sanitizer", ""),
                sanitizer_version=v.get("version", ""),
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Sanitizer bypass ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] sanitizer_bypass layer error: {e}")


def _scan_css_injection(scanner, url: str, html: str,
                        params: dict | None = None) -> None:
    """CSS Injection (CSSI) detection (Phase 30-1).

    Reports CSS exfiltration gadgets and CSSOM sinks:

      * ``css_font_face_exfil``         -- @font-face unicode-range exfil.
      * ``css_selector_exfil``          -- CSS keylogger (input[value^=...]).
      * ``css_import_injection``        -- @import loads external stylesheet.
      * ``css_javascript_uri``          -- url(javascript:...) in CSS.
      * ``css_expression``              -- expression() (IE < 11).
      * ``css_moz_binding``             -- -moz-binding (legacy Firefox).
      * ``css_behavior``                -- behavior:url() (IE HTC).
      * ``css_template_reflection``     -- template {{ }} inside <style>.
      * ``cssom_cssText``               -- element.style.cssText = sink.
      * ``cssom_background``            -- element.style.background = sink.
      * ``cssom_insertrule``            -- CSSStyleSheet.insertRule() sink.
      * ``css_dynamic_exfil_gadget``    -- JS-built CSS keylogger.
    """
    scanner.coverage.touch_layer(url, "L7_css_injection", "GET",
                                 detail="static CSSI analysis")
    try:
        result = cssi_mod.analyze_page(html, page_url=url,
                                       extra_markers=list(params.keys())
                                       if params else None)
        if not result["violations"]:
            return
        for v in result["violations"][:5]:
            vtype = v.get("type", "css_injection")
            poc = cssi_mod.build_poc_html(
                url, violation_type=vtype,
                resource_url=v.get("resource_url", ""),
            )
            scanner._add(_make_finding(
                url=url, method="GET", param="(css)",
                payload=f"(CSSI: {vtype})",
                context=f"cssi_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=vtype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] CSSI ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] css_injection layer error: {e}")


def _scan_dangling_markup(scanner, url: str, html: str,
                          params: dict | None = None) -> None:
    """Dangling Markup Injection detection (Phase 30-2).

    Reports:

      * ``dangling_markup_risk``       -- attribute reflection + nearby secret.
      * ``dangling_markup_potential``  -- sensitive data + URL attributes (no
                                          observed reflection yet).
    """
    scanner.coverage.touch_layer(url, "L7_dangling_markup", "GET",
                                 detail="static dangling-markup analysis")
    try:
        # Pass param VALUES as markers (not keys) -- the page reflects the
        # value, so we look for the value inside attribute contexts.  Also
        # include keys as fallback (some pages echo the key in the URL).
        markers: list[str] | None = None
        if params:
            markers = [str(v) for v in params.values() if v]
            markers.extend(str(k) for k in params.keys() if k)
        result = dml_mod.analyze_page(html, page_url=url,
                                      extra_markers=markers)
        if not result["violations"]:
            return
        for v in result["violations"][:3]:
            vtype = v.get("type", "dangling_markup")
            poc = dml_mod.build_poc_html(
                url, violation_type=vtype,
                context=v.get("context", "attr_dq"),
                captured_content=v.get("sensitive_data_type", ""),
            )
            scanner._add(_make_finding(
                url=url, method="GET", param="(dangling)",
                payload=f"(DanglingMarkup: {vtype})",
                context=f"dangling_{vtype}",
                severity=v.get("severity", "medium"),
                ftype=vtype,
                evidence=v.get("title", "") + " | " + v.get("evidence", "")[:200],
                poc_html=poc,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Dangling markup ({vtype}): "
                      f"{v.get('title', '')[:80]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] dangling_markup layer error: {e}")


def _scan_svg_xss(scanner, url: str, html: str) -> None:
    """SVG-based XSS detection (Phase 30-4).

    Reports one finding per SVG XSS vector found, capped at 5 to avoid
    flooding the report on SVG-heavy pages.  Each finding's ``type`` is
    ``svg_xss_<vector_type>`` (e.g. ``svg_xss_use_jsuri``).
    """
    scanner.coverage.touch_layer(url, "L7_svg_xss", "GET",
                                 detail="static SVG-vector analysis")
    try:
        result = svg_mod.analyze_svg(html)
        if not result["findings"]:
            return
        for finding in result["findings"][:5]:
            vtype = finding.get("vector_type", "svg_xss")
            ftype = f"svg_xss_{vtype}"
            # Prefer the standalone SVG PoC; fall back to the HTML wrapper
            # so the finding always has a usable poc_html.
            poc_svg = svg_mod.build_poc_svg(vtype)
            poc_html = svg_mod.build_poc_html(url, vtype) or poc_svg
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload=f"(SVG vector: {vtype})",
                context=f"svg_{vtype}",
                severity=finding.get("severity", "medium"),
                ftype=ftype,
                evidence=(
                    f"{finding.get('description', '')} | "
                    f"snippet: {finding.get('snippet', '')[:200]}"
                ),
                poc_html=poc_html,
                vector_type=vtype,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] SVG XSS ({vtype}): "
                      f"{finding.get('description', '')[:70]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] svg_xss layer error: {e}")


# =============================================================================
# Helpers
