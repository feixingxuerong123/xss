"""Page-level advanced layers: postMessage, prototype pollution, service
worker, web worker, open redirect, framework DOM XSS, GraphQL, WebSocket.
(Phase 39 split: moved verbatim from advanced_layers.py; entry points stay
in advanced_layers.py.)"""
from __future__ import annotations


from .. import postmessage as pm_mod
from .. import prototype as proto_mod
from .. import sw_xss as sw_mod
from .. import worker_xss as worker_mod
from .. import redirect_xss as redirect_mod
from .. import framework_xss as fw_mod
from .. import graphql_xss as gql_mod
from .. import websocket_xss as ws_xss_mod

from .common import _make_finding

def _scan_postmessage(scanner, url: str, html: str) -> None:
    """postMessage handler XSS: detect message listeners with sinks and no
    origin check."""
    # Phase 20-3: record L8 postMessage layer.
    scanner.coverage.touch_layer(url, "L8_postmessage", "GET",
                                 detail="static page analysis")
    try:
        result = pm_mod.analyze_page(html)
        if not result["vulnerable_count"]:
            return
        for listener in result["listeners"]:
            poc = pm_mod.build_poc_html(url)
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload="(postMessage listener)",
                context="dom_postmessage",
                severity="high",
                ftype="postmessage_xss",
                evidence=(
                    f"vulnerable postMessage listener: "
                    f"sinks={listener.get('sinks_found', [])[:3]}; "
                    f"no origin check"
                ),
                poc_html=poc,
                snippet=listener.get("snippet", "")[:300],
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] postMessage XSS: {listener.get('sinks_found', [])[:2]}")
            break  # one finding per page is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] postMessage layer error: {e}")


def _scan_prototype(scanner, url: str, html: str) -> None:
    """Prototype pollution -> XSS: detect merge + sink gadget."""
    # Phase 20-3: record L8 prototype pollution layer.
    scanner.coverage.touch_layer(url, "L8_prototype", "GET",
                                 detail="static page analysis")
    try:
        result = proto_mod.analyze_page(html)
        if not result["exploitable"]:
            return
        poc = proto_mod.build_poc_html(url)
        scanner._add(_make_finding(
            url=url, method="GET", param=None,
            payload="(prototype pollution)",
            context="dom_prototype",
            severity="high",
            ftype="prototype_pollution",
            evidence=(
                f"recursive merge + sink gadget: "
                f"merges={[m.get('description') for m in result.get('merges', [])][:2]}; "
                f"sinks={[s.get('gadget') for s in result.get('sinks', [])][:2]}"
            ),
            poc_html=poc,
            pollution_payloads=result.get("pollution_payloads", [])[:5],
        ))
        scanner.coverage.record_finding(url, "GET")
        if scanner.verbose:
            print(f"    [+] Prototype pollution -> XSS detected")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] prototype layer error: {e}")


def _scan_service_worker(scanner, url: str, html: str) -> None:
    """Service Worker XSS: detect register() calls and analyze SW scripts."""
    # Phase 20-3: record L8 service worker layer.
    scanner.coverage.touch_layer(url, "L8_service_worker", "GET",
                                 detail="static page analysis")
    try:
        def _fetcher(sw_url: str) -> str:
            try:
                r = scanner.req.get(sw_url)
                scanner._bump()
                return r.text or ""
            except Exception:
                return ""
        result = sw_mod.analyze_page(html, fetcher=_fetcher)
        if not result["vulnerable_count"]:
            return
        for listener in result["listeners"]:
            sw_url = listener.get("sw_url", "")
            poc = sw_mod.build_poc_html(url, sw_url)
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload=f"(SW register: {sw_url})",
                context="dom_service_worker",
                severity="high",
                ftype="service_worker_xss",
                evidence=(
                    f"navigator.serviceWorker.register with user-controlled URL "
                    f"and sink in SW script: "
                    f"{listener.get('sinks_found', [])[:3]}"
                ),
                poc_html=poc,
                sw_url=sw_url,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Service Worker XSS: {sw_url}")
            break
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] service worker layer error: {e}")


def _scan_worker(scanner, url: str, html: str) -> None:
    """Web Worker XSS: detect new Worker() and analyze worker scripts."""
    # Phase 20-3: record L8 web worker layer.
    scanner.coverage.touch_layer(url, "L8_web_worker", "GET",
                                 detail="static page analysis")
    try:
        def _fetcher(w_url: str) -> str:
            try:
                r = scanner.req.get(w_url)
                scanner._bump()
                return r.text or ""
            except Exception:
                return ""
        result = worker_mod.analyze_page(html, fetcher=_fetcher)
        if not result["vulnerable_count"]:
            return
        for w in result["workers"]:
            w_url = w.get("worker_url", "")
            poc = worker_mod.build_poc_html(url, w_url, "<img src=x onerror=alert(1)>")
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload=f"(new Worker: {w_url})",
                context="dom_web_worker",
                severity="high",
                ftype="web_worker_xss",
                evidence=(
                    f"new Worker() with user-controlled URL and sink in worker "
                    f"script: {w.get('sinks_found', [])[:3]}"
                ),
                poc_html=poc,
                worker_url=w_url,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Web Worker XSS: {w_url}")
            break
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] worker layer error: {e}")


def _scan_redirect(scanner, url: str, html: str) -> None:
    """Open redirect -> XSS: detect DOM redirect sinks fed by user input."""
    # Phase 20-3: record L8 open redirect layer.
    scanner.coverage.touch_layer(url, "L8_open_redirect", "GET",
                                 detail="static page analysis")
    try:
        result = redirect_mod.analyze_page(html)
        if not result["exploitable"]:
            return
        params_found = result.get("redirect_params_found", [])
        sinks = result.get("sinks", [])
        # Pick the first discovered redirect param to build a PoC.
        param = params_found[0] if params_found else "url"
        payload = "javascript:alert(1)//"
        poc = redirect_mod.build_poc_link(url, param, payload)
        scanner._add(_make_finding(
            url=url, method="GET", param=param,
            payload=payload,
            context="dom_open_redirect",
            severity="high",
            ftype="open_redirect_xss",
            evidence=(
                f"DOM redirect sink fed by user input: "
                f"sinks={[s.get('sink', '') for s in sinks][:3]}; "
                f"params={params_found[:3]}"
            ),
            poc_link=poc,
        ))
        scanner.coverage.record_finding(url, "GET")
        if scanner.verbose:
            print(f"    [+] Open redirect -> XSS: param={param}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] redirect layer error: {e}")


def _scan_framework(scanner, url: str, html: str) -> None:
    """Framework-specific DOM XSS (React/Vue/Angular/Svelte/Lit)."""
    # Phase 20-3: record L8 framework layer.
    scanner.coverage.touch_layer(url, "L8_framework", "GET",
                                 detail="static page analysis")
    try:
        result = fw_mod.analyze_page(html)
        if not result["vulnerable_count"]:
            return
        frameworks = result.get("frameworks_detected", [])
        # Only report medium+ severity findings.  Low-severity patterns
        # (e.g. ``createApp(`` detected, ``eval(`` without user input)
        # are framework-detection hints, not confirmed vulnerabilities --
        # including them would produce false positives on every Vue 3 page
        # that uses ``createApp()`` even with auto-escaped ``{{ }}`` templates.
        for finding in result.get("findings", [])[:3]:
            if finding.get("severity", "medium") == "low":
                continue
            fw = finding.get("framework", frameworks[0] if frameworks else "unknown")
            payload = finding.get("snippet", "")[:200]
            poc = fw_mod.build_poc_html(url, fw, payload)
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload=payload,
                context=f"framework_{fw.lower()}",
                severity=finding.get("severity", "medium"),
                ftype=f"framework_{fw.lower()}_xss",
                evidence=(
                    f"{fw} dangerous pattern: "
                    f"{finding.get('description', '')}"
                ),
                poc_html=poc,
                framework=fw,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] {fw} framework XSS: {finding.get('description', '')[:60]}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] framework layer error: {e}")


def _scan_graphql(scanner, req, url: str, html: str) -> None:
    """GraphQL XSS: detect GraphQL endpoints + unsafe client sinks, and
    optionally probe the endpoint for error-message reflection.

    Detection has two arms:

      1. **Static arm** -- scan the page HTML/JS for Apollo/urql/Relay
         markers, ``gql`` template tags, and unsafe sinks (innerHTML,
         dangerouslySetInnerHTML, v-html, ...) that consume GraphQL
         response data.  When both are present, the page is exploitable
         (a mutation can store a payload that the sink renders raw).

      2. **Probe arm** -- if a GraphQL endpoint URL is discovered on
         the page, send three probes (introspection, alias, argument)
         to detect server-side error-message reflection that the
         client may render raw.
    """
    # Phase 26-1: record L8 graphql layer.
    scanner.coverage.touch_layer(url, "L8_graphql", "GET",
                                 detail="static page analysis + endpoint probe")
    try:
        result = gql_mod.analyze_page(html)
        if not result["has_graphql"]:
            return

        endpoints = result.get("endpoints", []) or []
        markers = result.get("markers", {})
        clients = markers.get("clients_detected", [])
        hooks = markers.get("hooks_detected", [])

        # -- Static arm: report unsafe sinks that consume GraphQL data. --
        reported_sink = False
        for sink in result.get("sinks", [])[:3]:
            if not sink.get("has_data_ref"):
                continue
            sink_type = sink.get("sink_type", "inner_html")
            endpoint_str = endpoints[0] if endpoints else ""
            poc = gql_mod.build_poc_html(
                url, endpoint=endpoint_str,
                payload=gql_mod.DEFAULT_ARGUMENT_PAYLOAD,
                sink_type="client_sink",
            )
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload="(GraphQL data sink)",
                context=f"graphql_{sink_type}",
                severity=sink.get("severity", "high"),
                ftype="graphql_xss",
                evidence=(
                    f"GraphQL client ({'/'.join(clients) or 'unknown'}) "
                    f"feeds response data into a dangerous sink "
                    f"({sink.get('sink', '')}); "
                    f"endpoints={endpoints[:2]}; hooks={hooks[:3]}"
                ),
                poc_html=poc,
                graphql_endpoints=endpoints[:3],
                graphql_clients=clients,
                graphql_sink_type=sink_type,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] GraphQL client-sink XSS: {sink.get('sink', '')[:60]}")
            reported_sink = True
            break  # one static finding per page is enough

        # -- Probe arm: if we found a GraphQL endpoint URL, probe it. --
        # Resolve the endpoint to an absolute URL.
        from urllib.parse import urljoin
        probe_endpoint = ""
        for ep in endpoints:
            if ep.startswith(("http://", "https://")):
                probe_endpoint = ep
                break
            elif ep.startswith("/"):
                probe_endpoint = urljoin(url, ep)
                break
        if probe_endpoint:
            def _fetcher(gql_url: str, body: str, headers: dict):
                try:
                    r = req.post(gql_url, data=body, headers=headers)
                    scanner._bump()
                    scanner.coverage.record_request(url, "POST")
                    return getattr(r, "status_code", 0), (r.text or "")
                except Exception:
                    try:
                        r = req.get(gql_url)
                        scanner._bump()
                        scanner.coverage.record_request(url, "GET")
                        return getattr(r, "status_code", 0), (r.text or "")
                    except Exception as e:
                        return 0, ""

            probe = gql_mod.probe_graphql_endpoint(probe_endpoint, fetcher=_fetcher)

            # Report introspection as an info finding (schema exposed).
            if probe.get("introspection") and not reported_sink:
                scanner._add(_make_finding(
                    url=url, method="POST", param="(graphql:introspection)",
                    payload=gql_mod.INTROSPECTION_PROBE,
                    context="graphql_introspection",
                    severity="low",
                    ftype="graphql_introspection",
                    evidence=(
                        f"GraphQL introspection enabled at {probe_endpoint}; "
                        f"attacker can enumerate schema to craft precise "
                        f"alias/argument XSS payloads"
                    ),
                    graphql_endpoint=probe_endpoint,
                ))
                scanner.coverage.record_finding(url, "POST")
                if scanner.verbose:
                    print(f"    [+] GraphQL introspection enabled: {probe_endpoint}")
                reported_sink = True  # don't double-report on same page

            # Report alias reflection (high severity -- direct XSS).
            if probe.get("alias_reflected"):
                poc = gql_mod.build_poc_html(
                    url, endpoint=probe_endpoint,
                    payload=gql_mod.DEFAULT_ALIAS_PAYLOAD,
                    sink_type="alias_reflection",
                )
                scanner._add(_make_finding(
                    url=probe_endpoint, method="POST",
                    param="(graphql:alias)",
                    payload=gql_mod.DEFAULT_ALIAS_PAYLOAD,
                    context="graphql_alias_reflection",
                    severity="high",
                    ftype="graphql_xss",
                    evidence=(
                        f"GraphQL endpoint reflects alias verbatim in response "
                        f"JSON keys: {probe.get('response_snippet', '')[:160]}"
                    ),
                    poc_html=poc,
                    poc_query=gql_mod.build_poc_query(
                        gql_mod.DEFAULT_ALIAS_PAYLOAD),
                    graphql_endpoint=probe_endpoint,
                    graphql_sink_type="alias_reflection",
                ))
                scanner.coverage.record_finding(url, "POST")
                if scanner.verbose:
                    print(f"    [+] GraphQL alias-reflection XSS: {probe_endpoint}")

            # Report argument reflection (high severity -- error-message XSS).
            if probe.get("argument_reflected"):
                poc = gql_mod.build_poc_html(
                    url, endpoint=probe_endpoint,
                    payload=gql_mod.DEFAULT_ARGUMENT_PAYLOAD,
                    sink_type="argument_reflection",
                )
                scanner._add(_make_finding(
                    url=probe_endpoint, method="POST",
                    param="(graphql:argument)",
                    payload=gql_mod.DEFAULT_ARGUMENT_PAYLOAD,
                    context="graphql_argument_reflection",
                    severity="high",
                    ftype="graphql_xss",
                    evidence=(
                        f"GraphQL endpoint reflects argument value in error "
                        f"message: {probe.get('response_snippet', '')[:160]}"
                    ),
                    poc_html=poc,
                    graphql_endpoint=probe_endpoint,
                    graphql_sink_type="argument_reflection",
                ))
                scanner.coverage.record_finding(url, "POST")
                if scanner.verbose:
                    print(f"    [+] GraphQL argument-reflection XSS: {probe_endpoint}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] graphql layer error: {e}")


def _scan_websocket(scanner, url: str, html: str) -> None:
    """WebSocket XSS: detect ``new WebSocket()`` + ``onmessage`` handlers
    that feed ``event.data`` into dangerous sinks without origin checks.
    """
    # Phase 26-2: record L8 websocket layer.
    scanner.coverage.touch_layer(url, "L8_websocket", "GET",
                                 detail="static page analysis")
    try:
        result = ws_xss_mod.analyze_page(html)
        if not result["has_websocket"]:
            return

        usage = result.get("usage", {})
        ws_urls = usage.get("ws_urls", [])
        uses_insecure = result.get("uses_insecure_ws", False)

        # Report each exploitable handler (one finding per page max).
        for handler in result.get("handlers", [])[:1]:
            ws_url = handler.get("ws_url", "") or (ws_urls[0] if ws_urls else "")
            poc = ws_xss_mod.build_poc_html(url, ws_url=ws_url)
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload="(WebSocket onmessage sink)",
                context="dom_websocket",
                severity="high",
                ftype="websocket_xss",
                evidence=(
                    f"WebSocket onmessage handler feeds event.data into a "
                    f"dangerous sink without origin check: "
                    f"sinks={handler.get('sinks_found', [])[:3]}; "
                    f"ws_url={ws_url}"
                ),
                poc_html=poc,
                ws_url=ws_url,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] WebSocket XSS: {handler.get('sinks_found', [])[:2]}")
            break

        # If no exploitable sink but the page uses an insecure ws:// URL,
        # report it as a medium finding (MITM risk).
        if not result.get("handlers") and uses_insecure:
            ws_url = ws_urls[0] if ws_urls else ""
            scanner._add(_make_finding(
                url=url, method="GET", param=None,
                payload="(insecure WebSocket)",
                context="websocket_insecure",
                severity="medium",
                ftype="websocket_insecure",
                evidence=(
                    f"Page uses unencrypted ws:// WebSocket endpoint -- "
                    f"MITM can inject payloads into onmessage handlers; "
                    f"ws_urls={ws_urls[:3]}"
                ),
                ws_url=ws_url,
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Insecure WebSocket (ws://): {ws_url}")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] websocket layer error: {e}")


# =============================================================================
# Request-injection layers
# =============================================================================

