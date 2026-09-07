"""Advanced detection layers - public entry points (Phase 39 facade).

The 23 layer implementations live in the ``core.layers`` package, split
by detection domain (client / transport / content); this module keeps
the stable entry points the Scanner, API server, async scanner and
tests use:

    run_page_layers(scanner, req, url, response_text=None, params=None)
    run_request_layers(scanner, req, url, method, params, data)
    run_param_layers(scanner, req, url, method, params, data, param,
                     is_body, response_text)

All ``_scan_*`` layer functions and ``_make_finding`` are re-exported
here for backwards compatibility (tests/test_p26.py imports
_scan_graphql and _scan_websocket from this module).
"""
from __future__ import annotations


from . import layer_guard
from .layers.common import _make_finding  # noqa: F401  (re-export)
from .layers.client_layers import (  # noqa: F401  (re-exports)
    _scan_postmessage, _scan_prototype, _scan_service_worker,
    _scan_worker, _scan_redirect, _scan_framework, _scan_graphql,
    _scan_websocket,
)
from .layers.transport_layers import (  # noqa: F401  (re-exports)
    _scan_header_xss, _scan_path_xss, _scan_cookie_xss, _scan_error_xss,
)
from .layers.content_layers import (  # noqa: F401  (re-exports)
    _scan_markdown, _scan_trusted_types, _scan_csp_nonce,
    _scan_cookie_tossing, _scan_sri_bypass, _scan_import_map,
    _scan_sanitizer_bypass, _scan_css_injection, _scan_dangling_markup,
    _scan_svg_xss,
)

def run_page_layers(scanner, req, url: str, response_text: str | None = None,
                    params: dict | None = None) -> None:
    """Run all page-level advanced detection layers.

    Page-level layers analyze the HTML/JS of the page itself (no extra
    requests needed for most of them).  ``response_text`` is the page
    HTML if already fetched; if None, the layer will fetch it.
    ``params`` is the query/body params dict for the current request --
    some layers (e.g. import map) use it to detect user-controlled
    reflection in static HTML.

    Layers run:
      * postMessage handler XSS
      * Prototype pollution source + sink gadget
      * Service Worker XSS (registers + script analysis)
      * Web Worker XSS
      * Open redirect -> XSS (DOM-based)
      * Framework-specific DOM XSS (React/Vue/Angular/Svelte)
      * GraphQL XSS (Phase 26: endpoint + unsafe client sink)
      * WebSocket XSS (Phase 26: onmessage + sink)
      * Trusted Types violations (Phase 27-2: no-policy / bypass / taint flow)
      * CSP nonce reuse / exposure (Phase 27-2)
    """
    text = response_text
    if text is None:
        try:
            resp = req.get(url)
            scanner._bump()
            text = resp.text or ""
        except Exception:
            return
    # Fetch the CSP header once so the TT and nonce layers can share it
    # without re-issuing a GET.  When the caller passes the page response
    # (preferred path), we use it directly; otherwise we fetch it here.
    csp_header = ""
    try:
        # Reuse the text we already have if the caller also passed a
        # response object via scanner state -- but advanced_layers only
        # receives the text.  Fall back to a single GET for the header.
        # The scanner already caches bare-URL GETs (Phase 21-1), so this
        # is usually a cache hit.
        resp2 = req.get(url)
        scanner._bump()
        csp_header = (resp2.headers.get("Content-Security-Policy")
                      or resp2.headers.get("Content-Security-Policy-Report-Only")
                      or "") if hasattr(resp2, "headers") else ""
    except Exception:
        pass
    layer_guard.run_layer(scanner, "postmessage", _scan_postmessage, scanner,
                          url, text)
    layer_guard.run_layer(scanner, "prototype", _scan_prototype, scanner,
                          url, text)
    layer_guard.run_layer(scanner, "service_worker", _scan_service_worker,
                          scanner, url, text)
    layer_guard.run_layer(scanner, "worker", _scan_worker, scanner, url, text)
    layer_guard.run_layer(scanner, "redirect", _scan_redirect, scanner,
                          url, text)
    layer_guard.run_layer(scanner, "framework", _scan_framework, scanner,
                          url, text)
    # Phase 26: new page-level detection layers.
    layer_guard.run_layer(scanner, "graphql", _scan_graphql, scanner, req,
                          url, text)
    layer_guard.run_layer(scanner, "websocket", _scan_websocket, scanner,
                          url, text)
    # Phase 27-2: Trusted Types + CSP nonce reuse.
    layer_guard.run_layer(scanner, "trusted_types", _scan_trusted_types,
                          scanner, url, text, csp_header)
    layer_guard.run_layer(scanner, "csp_nonce", _scan_csp_nonce,
                          scanner, url, text, csp_header)
    # Phase 27-3: Cookie tossing XSS + SRI bypass.
    layer_guard.run_layer(scanner, "cookie_tossing", _scan_cookie_tossing,
                          scanner, req, url, text)
    layer_guard.run_layer(scanner, "sri_bypass", _scan_sri_bypass,
                          scanner, url, text)
    # Phase 28-4: Import Maps tampering + Sanitizer bypass.
    layer_guard.run_layer(scanner, "import_map", _scan_import_map,
                          scanner, url, text, params=params)
    layer_guard.run_layer(scanner, "sanitizer_bypass", _scan_sanitizer_bypass,
                          scanner, url, text)
    # Phase 30-1: CSS Injection (CSSI) -- exfiltration gadgets + CSSOM sinks.
    layer_guard.run_layer(scanner, "css_injection", _scan_css_injection,
                          scanner, url, text, params=params)
    # Phase 30-2: Dangling Markup Injection -- attribute-capture exfil.
    layer_guard.run_layer(scanner, "dangling_markup", _scan_dangling_markup,
                          scanner, url, text, params=params)
    # Phase 30-4: SVG XSS -- foreignObject / use / set / animate / SMIL.
    layer_guard.run_layer(scanner, "svg_xss", _scan_svg_xss, scanner,
                          url, text)


def run_request_layers(scanner, req, url: str, method: str = "GET",
                       params: dict | None = None,
                       data: dict | None = None) -> None:
    """Run all request-injection advanced detection layers.

    These layers inject payloads via HTTP headers, URL path segments, or
    cookies (not query/body params -- those are covered by the main
    reflection scanner).

    Layers run:
      * Header injection XSS (User-Agent, Referer, XFF, ...)
      * Path segment XSS
      * Cookie value XSS
      * Error page XSS (provokes 404/500 with payload)
    """
    params = params or {}
    data = data or {}
    layer_guard.run_layer(scanner, "header_xss", _scan_header_xss, scanner,
                           req, url)
    layer_guard.run_layer(scanner, "path_xss", _scan_path_xss, scanner,
                           req, url)
    layer_guard.run_layer(scanner, "cookie_xss", _scan_cookie_xss, scanner,
                           req, url)
    layer_guard.run_layer(scanner, "error_xss", _scan_error_xss, scanner,
                           req, url)


def run_param_layers(scanner, req, url: str, method: str,
                     params: dict, data: dict, param: str, is_body: bool,
                     response_text: str) -> None:
    """Run parameter-level advanced detection layers.

    These layers inject additional payload families into a parameter that
    is already known to be reflected (the main scanner has confirmed it).

    Layers run:
      * Markdown / BBCode XSS (when the endpoint renders markup)
    """
    layer_guard.run_layer(scanner, "markdown", _scan_markdown, scanner, req,
                           url, method, params, data, param, is_body,
                           response_text)
