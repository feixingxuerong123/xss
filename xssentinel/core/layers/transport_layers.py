"""Transport-injection advanced layers: header, URL path, cookie, error
page.  (Phase 39 split: moved verbatim from advanced_layers.py.)"""
from __future__ import annotations

import secrets

from .. import header_xss as header_mod
from .. import path_xss as path_mod
from .. import cookie_xss as cookie_mod
from .. import error_xss as error_mod

from .common import _make_finding
from ..stealth import marker as _stem_marker

def _scan_header_xss(scanner, req, url: str) -> None:
    """Inject payloads via HTTP headers (User-Agent, Referer, XFF, ...)."""
    # Phase 20-3: record L8 header XSS layer.
    scanner.coverage.touch_layer(url, "L8_header", "GET",
                                 detail="probe injectable headers")
    try:
        for header in header_mod.INJECTABLE_HEADERS[:6]:  # top 6 headers
            token = "xsshd_" + secrets.token_hex(3)
            payload = f"<svg/onload=alert('{token}')>"
            try:
                # Most requester implementations accept headers kwarg.
                resp = req.get(url, headers={header: payload})
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            result = header_mod.analyze_response(text, header, token)
            if not result["reflected"]:
                continue
            # Confirm the payload is in an executable context (not just the
            # token echoed as escaped text).
            from .. import verifier
            v = verifier.verify_semantic(text, token,
                                         response_headers=dict(resp.headers))
            if not v["confirmed"]:
                continue
            curl_poc = header_mod.build_poc_curl(url, header, payload)
            html_poc = header_mod.build_poc_html(url, header, payload)
            scanner._add(_make_finding(
                url=url, method="GET", param=f"(header:{header})",
                payload=payload,
                context=result.get("context_hint", "html_element"),
                severity="high",
                ftype="header_xss",
                evidence=(
                    f"payload reflected from {header} header: {v['detail']}"
                ),
                poc_curl=curl_poc,
                poc_html=html_poc,
                header=header,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Header XSS via {header}")
            break  # one header finding per URL is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] header layer error: {e}")


def _scan_path_xss(scanner, req, url: str) -> None:
    """Inject payloads via URL path segments."""
    # Phase 20-3: record L8 path XSS layer.
    scanner.coverage.touch_layer(url, "L8_path", "GET",
                                 detail="probe URL path segment")
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        if not parsed.path or parsed.path == "/":
            return  # nothing to inject into
        token = "xspath_" + secrets.token_hex(3)
        payload = f"<svg/onload=alert('{token}')>"
        # Insert the payload as a new path segment at the end.
        new_path = parsed.path.rstrip("/") + "/" + payload
        test_url = urlunparse((parsed.scheme, parsed.netloc, new_path,
                               parsed.params, parsed.query, ""))
        try:
            resp = req.get(test_url)
            scanner._bump()
            scanner.coverage.record_request(url, "GET")
        except Exception:
            return
        text = resp.text or ""
        result = path_mod.analyze_response(text, token)
        if not result["reflected"]:
            return
        from .. import verifier
        v = verifier.verify_semantic(text, token,
                                     response_headers=dict(resp.headers))
        if not v["confirmed"]:
            return
        curl_poc = path_mod.build_poc_curl(test_url)
        link_poc = path_mod.build_poc_link(test_url)
        scanner._add(_make_finding(
            url=test_url, method="GET", param="(path)",
            payload=payload,
            context=result.get("context", "html_element"),
            severity="high",
            ftype="path_xss",
            evidence=f"path segment reflected: {v['detail']}",
            poc_curl=curl_poc,
            poc_html=link_poc,
        ))
        scanner.coverage.record_finding(url, "GET")
        if scanner.verbose:
            print(f"    [+] Path XSS via URL segment")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] path layer error: {e}")


def _scan_cookie_xss(scanner, req, url: str) -> None:
    """Inject payloads via cookie values."""
    # Phase 20-3: record L8 cookie XSS layer.
    scanner.coverage.touch_layer(url, "L8_cookie", "GET",
                                 detail="probe injectable cookies")
    try:
        for cookie_name in cookie_mod.candidate_cookies()[:5]:  # top 5 cookies
            token = "xsck_" + secrets.token_hex(3)
            payload = f"<svg/onload=alert('{token}')>"
            try:
                resp = req.get(url, headers={"Cookie": f"{cookie_name}={payload}"})
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            result = cookie_mod.analyze_response(text, token)
            if not result["reflected"]:
                continue
            from .. import verifier
            v = verifier.verify_semantic(text, token,
                                         response_headers=dict(resp.headers))
            if not v["confirmed"]:
                continue
            curl_poc = cookie_mod.build_poc_curl(url, cookie_name, payload)
            html_poc = cookie_mod.build_poc_html(url, cookie_name, payload)
            scanner._add(_make_finding(
                url=url, method="GET", param=f"(cookie:{cookie_name})",
                payload=payload,
                context=result.get("context", "html_element"),
                severity="high",
                ftype="cookie_xss",
                evidence=(
                    f"payload reflected from cookie {cookie_name}: {v['detail']}"
                ),
                poc_curl=curl_poc,
                poc_html=html_poc,
                cookie=cookie_name,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Cookie XSS via {cookie_name}")
            break  # one cookie finding per URL is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] cookie layer error: {e}")


def _scan_error_xss(scanner, req, url: str) -> None:
    """Inject payloads to trigger error pages (404/500) that reflect input."""
    # Phase 20-3: record L8 error page XSS layer.
    scanner.coverage.touch_layer(url, "L8_error_page", "GET",
                                 detail="probe error-page reflection")
    try:
        # One error-page finding per host is enough -- the error page is
        # the same regardless of which endpoint triggered the 404 probe.
        from urllib.parse import urlparse
        host_key = urlparse(url).netloc
        with scanner._lock:
            already = any(
                f.data.get("type") == "error_page_xss"
                and urlparse(f.data.get("url", "")).netloc == host_key
                for f in scanner.findings
            )
        if already:
            return

        token = _stem_marker("xserr_") + secrets.token_hex(3)
        payload = f"<svg/onload=alert('{token}')>"
        from urllib.parse import urlunparse, quote
        parsed = urlparse(url)
        # Probe TWO error-page vectors:
        #   1. Append to the existing path (catches apps whose router
        #      falls through to a 404 handler for unknown sub-paths).
        #   2. A root-level non-existent path (catches apps whose router
        #      matches known path prefixes like /echo and returns 200 for
        #      /echo/<anything> -- the root probe avoids that false match).
        err_paths = [
            parsed.path.rstrip("/") + "/" + quote(payload, safe=""),
            "/__xssentinel_err__/" + quote(payload, safe=""),
        ]
        for err_path in err_paths:
            err_url = urlunparse((parsed.scheme, parsed.netloc, err_path,
                                  parsed.params, parsed.query, ""))
            try:
                resp = req.get(err_url)
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            result = error_mod.analyze_response(text, token,
                                                status_code=getattr(resp, "status_code", None))
            if not result["reflected"] or not result.get("is_error_page"):
                continue
            from .. import verifier
            v = verifier.verify_semantic(text, token,
                                         response_headers=dict(resp.headers))
            if not v["confirmed"]:
                continue
            curl_poc = error_mod.build_poc_curl(err_url)
            link_poc = error_mod.build_poc_link(err_url)
            scanner._add(_make_finding(
                url=err_url, method="GET", param="(error_path)",
                payload=payload,
                context=result.get("context", "html_element"),
                severity="high",
                ftype="error_page_xss",
                evidence=(
                    f"error page ({getattr(resp, 'status_code', '?')}) "
                    f"reflects payload: {v['detail']}"
                ),
                poc_curl=curl_poc,
                poc_html=link_poc,
                status_code=getattr(resp, "status_code", None),
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Error page XSS ({getattr(resp, 'status_code', '?')})")
            break  # one error-page finding per host is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] error layer error: {e}")


# =============================================================================
# Parameter-level layers
# =============================================================================

