#!/usr/bin/env python
"""XSSentinel CLI — comprehensive XSS detection.

Usage:
  python -m xssentinel -u https://target.com/search?q=test
  python -m xssentinel -u https://target.com/form --data "name=x&bio=y" -m POST
  python -m xssentinel -u https://target.com -c            # crawl + scan
  python -m xssentinel -u https://target.com --headless     # real-browser proof
  python -m xssentinel --config scan.json                   # load config file
  python -m xssentinel -u https://target.com --resume scan.ckpt.json
  python -m xssentinel --batch urls.txt -o reports/         # batch scan
  python -m xssentinel --verify-fix old_report.json -o verify.html  # re-test fixes
  python -m xssentinel --diff baseline.json current.json -o diff.html  # compare reports

Use only on systems you are authorized to test.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

# Allow running as a module or script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.oob import make_listener
from xssentinel.core.config import Config, save_config
from xssentinel.core.checkpoint import Checkpoint
from xssentinel.core.logger import configure_logging, get_logger

_log = get_logger("cli")


# Phase 43: sub-command + runner implementations live in cli_runner /
# cli_commands; re-exported here so `cli._run_async_batch`-style access
# in tests and downstream scripts keeps working unchanged.
from .cli_runner import (  # noqa: F401
    _build_progress, _do_login, _run_scan, _run_async_scan,
    _run_async_batch, _write_report)
from .cli_commands import (  # noqa: F401
    _run_self_test, _run_serve, _run_verify_fix, _run_diff,
    _run_passive_proxy, _run_marker_fuzz)


# Phase 33: scan-policy presets (ZAP-style Threshold/Strength analogue).
# Explicit CLI flags take precedence: the preset only fills parameters the
# user left unset (argparse defaults are None for policy-managed flags).
SCAN_POLICIES = {
    "quick": {"max_payloads": 6, "max_transforms": 4, "threads": 4},
    "normal": {"max_payloads": 14, "max_transforms": 12, "threads": 4},
    "deep": {"max_payloads": 30, "max_transforms": 20, "threads": 4},
}


def apply_scan_policy(args) -> None:
    """Fill policy-managed args (max_payloads/max_transforms/threads) from
    the selected preset unless the user set them explicitly."""
    pol = SCAN_POLICIES.get(getattr(args, "scan_policy", "normal"),
                            SCAN_POLICIES["normal"])
    for key, val in pol.items():
        if getattr(args, key, None) is None:
            setattr(args, key, val)


def _parse_kv(s: str) -> dict:
    out = {}
    if not s:
        return out
    for pair in s.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
        else:
            out[pair] = ""
    return out


def build_parser():
    ap = argparse.ArgumentParser(
        prog="xssentinel",
        description="Comprehensive XSS detection framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  xssentinel -u 'https://t.com/search?q=test'\n"
               "  xssentinel -u https://t.com -c --crawl-depth 3\n"
               "  xssentinel --config scan.json\n"
               "  xssentinel -u https://t.com --resume scan.ckpt.json\n"
               "  xssentinel --batch urls.txt -o reports/\n"
               "  xssentinel --self-test            # validate all detection layers\n")
    # Target
    g_tgt = ap.add_argument_group("Target")
    g_tgt.add_argument("-u", "--url", help="Target URL")
    g_tgt.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    g_tgt.add_argument("-d", "--data", default="",
                       help="POST body / GET params as key=value&...")
    g_tgt.add_argument("--batch", default=None,
                       help="File of URLs to scan (one per line, # = comment)")
    g_tgt.add_argument("--batch-stdin", action="store_true",
                       help="Read URLs from stdin (pipe mode, one per line,"
                            " # = comment).  Pairs with -o DIR for per-target"
                            " reports; empty lines/comments ignored.")
    g_tgt.add_argument("--har", default=None, metavar="FILE",
                       help="Import scan targets from a HAR (HTTP Archive)"
                            " file -- every request the browser/app made is"
                            " a real endpoint to probe.  Method, form/JSON"
                            " body, cookies and auth headers are carried"
                            " into each scan; pairs with -o DIR.")
    g_tgt.add_argument("--openapi", default=None, metavar="FILE",
                       help="Import scan targets from an OpenAPI/Swagger"
                            " spec (JSON) -- the documented API contract:"
                            " every path+operation becomes an endpoint to"
                            " probe, including routes the browser never hit."
                            " Path templates are resolved to sample URLs,"
                            " form/JSON bodies built from schemas, apiKey/"
                            " bearer security added as headers; pairs with"
                            " -o DIR.")
    g_tgt.add_argument("--self-test", action="store_true",
                       help="Start the local vuln server and run the full "
                            "self-test suite to validate every detection layer")
    g_tgt.add_argument("--fuzz-body", dest="fuzz_body", default=None,
                       help="Marker-injection mode: body template "
                            "containing the marker token (inline text or "
                            "@file); every marker occurrence is replaced "
                            "with each payload.  Use with -m POST.")
    g_tgt.add_argument("--fuzz-marker", dest="fuzz_marker", default="FUZZ",
                       help="Marker token in --fuzz-body (default FUZZ)")
    g_tgt.add_argument("--fuzz-max", dest="fuzz_max", type=int, default=20,
                       help="Max payloads to send in marker-fuzz mode")
    g_tgt.add_argument("--raw-request", dest="raw_request", default=None,
                       help="Scan a raw HTTP request file (Burp/ZAP "
                            "'copy as raw' format).  Method, URL (from "
                            "Host), headers, cookies and body all flow "
                            "into the normal scan pipeline.")
    g_tgt.add_argument("--bav", action="store_true",
                       help="BAV follow-up: on hidden-param miner hits, "
                            "also probe the same parameter for SSTI / "
                            "open-redirect / CRLF (adds up to 3 requests "
                            "per interesting param)")
    g_tgt.add_argument("--verify-fix", dest="verify_fix", default=None,
                       help="Re-verify findings from a previous JSON report "
                            "(e.g. report.json). Replays each original payload "
                            "and reports fixed / still_vuln / error / skipped. "
                            "Pair with -o and -f (html or json) for the output.")
    g_tgt.add_argument("--diff", dest="diff", nargs=2, default=None,
                       metavar=("BASELINE", "CURRENT"),
                       help="Compare two JSON scan reports and emit a diff "
                            "report (new / fixed / regressed / unchanged). "
                            "CI verdict: FAIL if new or regressed findings "
                            "exist. Pair with -o and -f (html or json).")
    g_tgt.add_argument("--serve", action="store_true",
                       help="Start the REST API server (microservice mode). "
                            "Clients submit scans via POST /api/v1/scans and "
                            "poll status via GET /api/v1/scans/{id}.  Pair "
                            "with --host, --port, and optionally --api-key.")
    g_tgt.add_argument("--host", default="127.0.0.1",
                       help="Bind address for --serve (default: 127.0.0.1; "
                            "use 0.0.0.0 to expose externally)")
    g_tgt.add_argument("--port", type=int, default=8000,
                       help="Bind port for --serve (default: 8000)")
    g_tgt.add_argument("--api-key", dest="api_key", default=None,
                       help="Require X-API-Key header for --serve API calls. "
                            "If omitted, the API is open (use only on a "
                            "trusted network).")
    g_tgt.add_argument("--max-jobs", dest="max_jobs", type=int, default=200,
                       help="Max scan jobs to retain in --serve memory "
                            "(oldest terminal jobs evicted first; default 200)")
    g_tgt.add_argument("--use-flask", dest="use_flask", action="store_true",
                       help="Use the Flask backend for --serve instead of "
                            "the stdlib server (requires flask to be installed)")
    g_tgt.add_argument("--db", dest="db_path", default=None,
                       help="SQLite database path for --serve persistence. "
                            "When set, scan jobs survive process restarts: "
                            "terminal jobs are reloaded on startup, and "
                            "any job that was RUNNING when the previous "
                            "process died is marked FAILED.  Example: "
                            "--db xssentinel.db")
    g_tgt.add_argument("--webhook", dest="webhook_urls", action="append",
                       default=[],
                       help="Webhook URL to notify on scan completion "
                            "(repeatable).  POSTs a JSON payload with "
                            "scan_id, state, finding_count, etc. to each "
                            "URL when a scan reaches a terminal state. "
                            "Pair with --webhook-secret for HMAC signing.")
    g_tgt.add_argument("--webhook-secret", dest="webhook_secret", default=None,
                       help="Shared secret for HMAC-signing webhook "
                            "deliveries.  When set, each webhook request "
                            "includes 'X-XSSentinel-Signature: sha256=<hex>'.")
    # HTTP
    g_http = ap.add_argument_group("HTTP")
    g_http.add_argument("-H", "--header", action="append", default=[],
                        help="Extra header 'Name: Value' (repeatable)")
    g_http.add_argument("-b", "--cookie", default="", help="Cookie string")
    g_http.add_argument("-x", "--proxy", default=None, help="HTTP/HTTPS proxy")
    g_http.add_argument("--timeout", type=int, default=15)
    g_http.add_argument("--no-verify-ssl", action="store_true")
    g_http.add_argument("--rate-limit", type=float, default=0,
                        help="Max requests/sec (0 = unlimited). Keeps the "
                             "scanner polite on sensitive targets.")
    g_http.add_argument("--max-requests", dest="max_requests", type=int,
                        default=None,
                        help="Stop the scan after this many outgoing "
                             "requests (compliance guardrail for "
                             "authorized-testing scope). Default: unlimited.")
    g_http.add_argument("--max-requests-per-endpoint",
                        dest="max_requests_per_endpoint", type=int,
                        default=None,
                        help="Stop scanning an endpoint after this many "
                             "requests (default: unlimited).")
    g_http.add_argument("--breaker-threshold", dest="breaker_threshold",
                        type=int, default=25,
                        help="Circuit breaker: stop the scan after this "
                             "many 5xx/429 responses within a 2-minute "
                             "window (target down / blocking us). "
                             "0 disables. Default: 25.")
    # Stealth (pentest-readiness): the default UA identifies the tool and
    # the request markers (xssm_/xssp_/...) are recognizable in SIEM logs.
    g_http.add_argument("--user-agent", dest="user_agent", default=None,
                        help="Override the User-Agent header (default: "
                             "Chrome-shaped with an XSSentinel token). "
                             "Use a real browser UA on assessments.")
    g_http.add_argument("--random-agent", dest="random_agent",
                        action="store_true",
                        help="Rotate the User-Agent per scan from a small "
                             "pool of common browser UAs.")
    g_http.add_argument("--marker-prefix", dest="marker_prefix", default=None,
                        help="Custom prefix for request markers (default "
                             "xssm_/xssp_/...). Markers are visible in "
                             "target logs; a neutral prefix (e.g. 'q_') "
                             "reduces fingerprinting.")
    # Phase 51: the remaining stealth gaps from the pentest audit -- no
    # egress rotation, no header rotation, no pacing jitter.
    g_http.add_argument("--proxy-list", dest="proxy_list", default=None,
                        metavar="LIST",
                        help="Rotate egress: comma-separated proxies or a "
                             "file path (one per line, # comments). Dead "
                             "relays are evicted from rotation.")
    g_http.add_argument("--rotate-headers", dest="rotate_headers",
                        action="store_true",
                        help="Vary browser-consistent headers per request "
                             "(Accept-Language / Sec-Fetch-*, pinned to the "
                             "session UA family).")
    g_http.add_argument("--jitter-ratio", dest="jitter_ratio", type=float,
                        default=0.0, metavar="R",
                        help="Randomise pacing by +/- R (0-1) so the request "
                             "stream is not metronomic. Needs --rate-limit; "
                             "0 (default) keeps a fixed interval.")
    # Crawl
    g_crawl = ap.add_argument_group("Crawl")
    g_crawl.add_argument("-c", "--crawl", action="store_true",
                         help="Crawl forms/links")
    g_crawl.add_argument("--crawl-depth", type=int, default=2)
    g_crawl.add_argument("--crawl-engine", dest="crawl_engine",
                         choices=["auto", "spa", "static"], default="auto",
                         help="Crawler engine: 'auto' uses Playwright SPA "
                              "crawler when available (handles client-side "
                              "routing, XHR interception, lazy-loaded routes); "
                              "'spa' forces it (degrades to static if "
                              "Playwright missing); 'static' uses legacy "
                              "BeautifulSoup crawler (default: auto)")
    g_crawl.add_argument("--scope", default=None,
                         help="Crawl scope prefix (default: same-origin only)")
    # Detection
    g_det = ap.add_argument_group("Detection")
    g_det.add_argument("--headless", action="store_true",
                       help="Real-browser confirmation (needs playwright)")
    g_det.add_argument("--dom-engine", dest="dom_engine",
                       choices=["auto", "playwright", "static"], default="auto",
                       help="DOM-XSS engine mode")
    g_det.add_argument("--scan-policy", choices=["quick", "normal", "deep"],
                       default="normal",
                       help="Scan policy preset (ZAP-style): quick=fast "
                            "low-budget pass, normal=balanced (default), "
                            "deep=maximum coverage. Explicit flags override.")
    g_det.add_argument("--max-transforms", type=int, default=None)
    g_det.add_argument("--fuzz", action="store_true",
                       help="Enable fuzzer mode: triage params with response-difference scoring before deep payload testing (reduces request count on large targets)")
    g_det.add_argument("--fuzz-top-n", type=int, default=5,
                       help="Max params to deep-test after fuzzer triage (default 5)")
    g_det.add_argument("--async", dest="async_mode", action="store_true",
                       help="Use async scanner (aiohttp) for high-throughput multi-target scans")
    g_det.add_argument("--max-payloads", type=int, default=None)
    g_det.add_argument("--threads", type=int, default=None)
    g_det.add_argument("--custom-payloads", default=None,
                       help="File of custom payloads to append to the corpus")
    g_det.add_argument("--json", dest="json_body", action="store_true",
                       help="Treat -d as a JSON document (application/json "
                            "body). Auto-detected when -d starts with '{'; "
                            "body params are tested at every leaf of the "
                            "document (deep nested coverage).")
    g_det.add_argument("--scenarios", default=None,
                       help="JSON file of declarative multi-step detection "
                            "scenarios (stored flows etc.; see "
                            "data/scenarios.example.json)")
    # Phase 53: XS-Leaks surface audit (opt-in -- records a low finding on
    # pages that set no cross-origin isolation / framing headers).
    g_det.add_argument("--audit-xs-leaks", dest="xsleak_audit",
                       action="store_true",
                       help="Audit pages for a missing XS-Leaks surface "
                            "(COOP/CORP/COEP/frame guards all absent -> low "
                            "xs_leak_surface finding per origin)")
    g_det.add_argument("--param-wordlist", dest="param_wordlist", default=None,
                       help="Extra hidden-parameter name candidates, one "
                            "per line (# comments). Prepended to the "
                            "built-in list for --fuzz triage and crawl-time "
                            "param mining.")
    g_det.add_argument("--upload-field", dest="upload_field", default=None,
                       action="append",
                       help="Name of a file-upload form field to multipart-"
                            "probe on POST endpoints (multipart filename "
                            "XSS; repeatable). Filenames carry payloads; a "
                            "filename echoed unencoded by the app is "
                            "reported as upload_xss, a stored file served "
                            "back as stored_upload.")
    g_det.add_argument("--poc-auth", dest="poc_include_auth",
                       action="store_true",
                       help="Embed the scan session's credentials (cookies "
                            "AND replay-worthy headers like Authorization / "
                            "X-API-Key) into curl PoCs. OFF by default so "
                            "shared reports do not leak the tester's "
                            "authenticated session.")
    # Blind / Stored
    g_bs = ap.add_argument_group("Blind / Stored XSS")
    g_bs.add_argument("--oob", choices=["self", "interactsh"], default=None,
                      help="Blind-XSS OOB callback mode")
    g_bs.add_argument("--oob-timeout", type=float, default=12,
                      help="OOB callback collection window in seconds "
                           "(default 12). Realistic blind-XSS (admin views "
                           "a page later) needs minutes -- raise it or pair "
                           "with --oob-keep-listening.")
    g_bs.add_argument("--oob-keep-listening", dest="oob_keep_listening",
                      action="store_true",
                      help="Keep the OOB listener armed after the first "
                           "collection and retain un-confirmed injections, "
                           "so late callbacks (hours later) can still be "
                           "attributed by a follow-up collect.")
    g_bs.add_argument("--stored-fresh-session",
                      dest="stored_fresh_session", action="store_true",
                      help="Confirm stored-XSS findings from a fresh "
                           "cookie-free viewer session (independent visitor) "
                           "instead of the scan session. Without it, a "
                           "same-page self-view is only reported at "
                           "confidence=medium.")
    g_bs.add_argument("--stored-inject", default=None,
                      help="Stored-XSS inject URL (POST)")
    g_bs.add_argument("--stored-view", default=None,
                      help="Stored-XSS view URL")
    g_bs.add_argument("--stored-param", default="q")
    # Second-order XSS (Phase 21-4): inject at A, crawl to discover B.
    g_bs.add_argument("--second-order-inject", default=None,
                      help="Second-order XSS inject URL (inject A, crawl B)")
    g_bs.add_argument("--second-order-param", default="q",
                      help="Param name for second-order injection")
    g_bs.add_argument("--second-order-method", default="POST",
                      choices=["GET", "POST"],
                      help="HTTP method for second-order injection")
    g_bs.add_argument("--second-order-start", default=None,
                      help="Crawl start URL for viewer discovery "
                           "(defaults to the inject URL)")
    g_bs.add_argument("--second-order-viewers", default=None,
                      help="Comma-separated explicit viewer URLs "
                           "(skips crawling)")
    # Auth
    g_auth = ap.add_argument_group("Authentication")
    g_auth.add_argument("--login-url", default=None,
                        help="Login form URL (pre-scan auth)")
    g_auth.add_argument("--login-user", default=None, help="Login username")
    g_auth.add_argument("--login-pass", default=None, help="Login password")
    g_auth.add_argument("--login-field-user", default="username",
                        help="Login form username field name")
    g_auth.add_argument("--login-field-pass", default="password",
                        help="Login form password field name")
    g_auth.add_argument("--login-csrf-field", default="csrf_token",
                        help="Login form CSRF token field name")
    g_auth.add_argument("--login-success-marker", default=None,
                        help="Substring expected in the response after a "
                             "successful form login (e.g. 'Logout').  More "
                             "reliable than the 200/302+cookie heuristic")
    g_auth.add_argument("--login-failure-marker", default=None,
                        help="Substring expected on a failed form login "
                             "(e.g. 'Invalid credentials')")
    # -- non-form auth (Phase 45: these call SessionManager methods that
    # already existed but had no CLI entry point)
    g_auth.add_argument("--login-basic", default=None, metavar="USER:PASS",
                        help="HTTP Basic authentication")
    g_auth.add_argument("--login-header", default=None,
                        metavar="'NAME: VALUE'",
                        help="Static auth header, e.g. 'X-API-Key: abc123' "
                             "or 'Authorization: Bearer eyJ...'")
    g_auth.add_argument("--login-token", default=None, metavar="TOKEN",
                        help="Bearer/API token sent as "
                             "'Authorization: Bearer <token>'")
    g_auth.add_argument("--login-token-header", default="Authorization",
                        help="Header name for --login-token (default "
                             "Authorization; use X-API-Key etc.)")
    g_auth.add_argument("--login-token-scheme", default="Bearer",
                        help="Scheme prefix for --login-token; use '' for a "
                             "raw header value")
    g_auth.add_argument("--login-verify-url", default=None,
                        help="URL to GET to verify a token is accepted")
    g_auth.add_argument("--login-verify-marker", default=None,
                        help="Substring expected in the --login-verify-url "
                             "response (e.g. 'user_id')")
    g_auth.add_argument("--login-oauth-token", default=None, metavar="TOKEN",
                        help="OAuth 2.0 access token (with refresh support "
                             "when --oauth-refresh/--oauth-token-url/"
                             "--oauth-client-id are also given)")
    g_auth.add_argument("--oauth-refresh", default=None, metavar="TOKEN",
                        help="OAuth 2.0 refresh token (RFC 6749 §6)")
    g_auth.add_argument("--oauth-token-url", default=None,
                        help="OAuth token endpoint for refresh")
    g_auth.add_argument("--oauth-client-id", default=None,
                        help="OAuth client_id for refresh")
    g_auth.add_argument("--oauth-client-secret", default=None,
                        help="OAuth client_secret for refresh")
    g_auth.add_argument("--auth-refresh-interval", type=float, default=1800.0,
                        help="Re-authenticate when the session is older "
                             "than this many seconds (default 1800)")
    g_auth.add_argument("--auth-relogin-on-loss", action="store_true",
                        help="Detect 401/403/redirect-to-login during the "
                             "scan and re-authenticate automatically")
    # Config / Resume / Progress
    g_cfg = ap.add_argument_group("Config & Resume")
    g_cfg.add_argument("--config", default=None,
                       help="Load scan options from JSON config file")
    g_cfg.add_argument("--save-config", default=None,
                       help="Save current options to a JSON config file and exit")
    g_cfg.add_argument("--exit-code", type=int, default=0,
                       help="Exit with non-zero code if findings >= this threshold "
                            "(default: 0 = always exit 0). Set to 1 for CI gate.")
    g_cfg.add_argument("--resume", default=None,
                       help="Resume from a checkpoint file")
    g_cfg.add_argument("--checkpoint", default=None,
                       help="Save scan progress to this checkpoint file")
    g_cfg.add_argument("--progress", choices=["bar", "line", "none"],
                       default="bar", help="Progress display mode")
    # Output
    g_out = ap.add_argument_group("Output")
    # default=None on purpose: mutually exclusive modes (scan / --passive /
    # --verify-fix / --diff) each fall back to their OWN default filename,
    # so `args.output or "mode_default.html"` is not dead code.
    g_out.add_argument("-o", "--output", default=None,
                       help="Report path (or directory for --batch)")
    g_out.add_argument("-f", "--format", default="html",
                       choices=["html", "json", "csv", "sarif", "junit",
                                "markdown", "burp", "nuclei"])
    g_out.add_argument("-v", "--verbose", action="store_true")
    g_out.add_argument("--log-level", default=None,
                       choices=["debug", "info", "warning", "error"],
                       help="Logging verbosity (default: warning; "
                            "verbose implies info)")
    # Phase 44: passive proxy scanning (learned from xray / w13scan).
    g_passive = ap.add_argument_group("Passive proxy (Phase 44)")
    g_passive.add_argument("--passive", action="store_true",
                           help="Run as a passive HTTP proxy: capture "
                                "browser traffic, extract params, scan each "
                                "unique endpoint (xray/w13scan-style)")
    g_passive.add_argument("--proxy-port", dest="proxy_port", type=int,
                           default=8080,
                           help="Port for the passive proxy (default: 8080)")
    g_passive.add_argument("--proxy-host", dest="proxy_host",
                           default="127.0.0.1",
                           help="Bind address for the passive proxy "
                                "(default: 127.0.0.1)")
    # Phase 50: HTTPS interception (the documented --passive-mitm extension).
    g_passive.add_argument("--mitm-ca", dest="mitm_ca", default=None,
                           metavar="PEM",
                           help="Enable HTTPS interception: combined CA "
                                "key+cert PEM path (auto-generated when "
                                "missing).  Install the sibling "
                                "<path>-cert.pem into the browser/OS trust "
                                "store so intercepted per-host certs are "
                                "accepted; out-of-scope hosts stay blind "
                                "tunneled.")
    # Phase 44: fast SQLi error-reflection grep (learned from dalfox/xray).
    g_grep = ap.add_argument_group("Fast checks (Phase 44)")
    g_grep.add_argument("--sqli-check", action="store_true",
                        help="Fast SQLi error-reflection grep: inject quote "
                             "probes, match DB error fingerprints "
                             "(dalfox grep-engine style)")
    g_grep.add_argument("--check-outdated-js", action="store_true",
                        help="Report outdated JS libraries (known-CVE "
                             "versions) found in page HTML (XSStrike "
                             "retireJS style)")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)

    # Configure logging based on --log-level or --verbose.
    level = args.log_level
    if level is None:
        # Phase 37 (P0-3): verbose now routes through the logger at DEBUG;
        # core modules' verbose diagnostics are _log.debug() calls.
        level = "debug" if args.verbose else "warning"
    configure_logging(level)

    # --self-test: run the built-in self-test suite and exit.
    if args.self_test:
        return _run_self_test()

    # --serve: start the REST API server (microservice mode).
    if args.serve:
        return _run_serve(args)

    # Phase 80: --fuzz-body marker injection mode.
    if getattr(args, "fuzz_body", None):
        return _run_marker_fuzz(args)

    # Phase 44: --passive -- run as a passive proxy scanner (xray-style).
    if getattr(args, "passive", False):
        return _run_passive_proxy(args)

    # Phase 83: --raw-request -- parse the raw file into args and fall
    # through to the normal scan pipeline (auth/OOB/checkpoint included).
    if getattr(args, "raw_request", None):
        from .core.http_raw import parse_raw_request
        with open(args.raw_request, "r", encoding="utf-8",
                  errors="replace") as fh:
            parsed = parse_raw_request(fh.read())
        args.url = parsed["url"]
        args.method = parsed["method"]
        if parsed["cookies"] and not args.cookie:
            args.cookie = parsed["cookies"]
        if parsed["body"] and not args.data:
            args.data = parsed["body"]
        for hname, hval in parsed["headers"].items():
            if hname.lower() in ("host", "content-length", "cookie",
                                 "content-type", "connection"):
                continue
            if hname.lower() == "user-agent" and not args.user_agent:
                args.user_agent = hval
                continue
            args.header.append(f"{hname}: {hval}")
        print(f"[*] raw request loaded: {args.method} {args.url} "
              f"({len(parsed['headers'])} headers)")

    # --verify-fix: replay findings from a previous JSON report.
    if args.verify_fix:
        return _run_verify_fix(args)

    # --diff: compare two JSON reports and emit a diff report.
    if args.diff:
        return _run_diff(args)

    # Scan-mode default output (modes above fall back to their own names).
    # Phase 49: nuclei produces a template DIRECTORY and burp an XML file,
    # so those formats get honest default names instead of report.html +
    # appended extension.
    if args.output is None:
        if args.format == "nuclei":
            args.output = "xssentinel-nuclei"
        elif args.format == "burp":
            args.output = "xssentinel-burp.xml"
        else:
            args.output = "report.html"

    # Load config file and merge with CLI args.
    cfg = Config.load(args.config) if args.config else Config()
    cli_dict = {k: v for k, v in vars(args).items()}
    merged = cfg.merge_args(cli_dict)

    # Apply merged config to args (CLI already took precedence in merge_args).
    for k, v in merged.items():
        if k not in ("login", "batch_file", "custom_payloads", "verify_ssl"):
            setattr(args, k, v)
    args.verify_ssl = not args.no_verify_ssl

    # --save-config: dump current options and exit.
    if args.save_config:
        cfg_data = {k: v for k, v in vars(args).items()
                    if v is not None and v != "" and v is not False
                    and k not in ("save_config", "config", "resume",
                                  "checkpoint", "batch",
                                  "login_pass", "login_basic",
                                  "login_token", "login_oauth_token",
                                  "oauth_client_secret", "webhook_secret")}
        omitted = [k for k in ("login_pass", "login_basic", "login_token",
                               "login_oauth_token", "oauth_client_secret",
                               "webhook_secret")
                   if getattr(args, k, None)]
        if omitted:
            print("[!] --save-config: secret values omitted from the "
                  "config file (re-enter on use): " + ", ".join(omitted),
                  file=sys.stderr)

        if save_config(args.save_config, cfg_data):
            print(f"[+] Config saved to {args.save_config}")
            return 0
        _log.error("Failed to save config to %s", args.save_config)
        return 1

    # Determine target URL(s).  Phase 88: --batch-stdin accepts URLs on
    # stdin so recon pipelines can stream straight into the scanner
    # (``httpx ... | xssentinel --batch-stdin -o out/``).  Target loading
    # (file/stdin/comment stripping/duplicate suppression) lives in
    # cli_runner.load_target_urls so tests can drive it directly.
    from .cli_runner import load_target_urls
    urls, load_err = load_target_urls(
        batch_file=args.batch, batch_stdin=args.batch_stdin,
        url=args.url)
    if load_err:
        _log.error("%s", load_err)
        return 2

    # Phase 88/89 (P1): --har / --openapi expand into one scan target per
    # captured/declared HTTP operation (method/body/cookies/headers or
    # security preserved).  Spec targets override the global
    # method/data/cookie per URL, so they are kept separate from the
    # plain-URL list.
    spec_targets: list[dict] = []
    if getattr(args, "har", None):
        from .core.har_import import har_to_scan_targets
        try:
            spec_targets = har_to_scan_targets(args.har)
        except Exception as e:
            _log.error("HAR import failed: %s", e)
            return 2
        src_label = f"HAR {args.har}"
    elif getattr(args, "openapi", None):
        from .core.openapi_import import openapi_to_scan_targets
        try:
            spec_targets = openapi_to_scan_targets(args.openapi)
        except Exception as e:
            _log.error("OpenAPI import failed: %s", e)
            return 2
        src_label = f"OpenAPI {args.openapi}"
    if spec_targets:
        urls = [t["url"] for t in spec_targets]
        print(f"[*] {src_label}: {len(spec_targets)} endpoint(s) imported")

    if not urls:
        ap.print_help()
        print("\n[!] No target specified. Use -u URL, --batch FILE, "
              "--batch-stdin, --har FILE or --openapi FILE.",
              file=sys.stderr)
        return 2

    # Validate URLs.
    for url in urls:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            _log.error("Invalid URL: %s", url)
            return 2

    # Build shared HTTP requester.
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    # Phase 46 wiring: --user-agent / --random-agent / --marker-prefix were
    # parsed but never consumed (dead flags).  The UA override feeds the
    # shared requester (and therefore every worker clone); the marker
    # prefix is a module-global consumed by stealth.marker() in every
    # detection layer.  An explicit -H "User-Agent: ..." wins over
    # --random-agent (last-mile override).
    #
    # Resolved BEFORE the Requester is built (Phase 51): --rotate-headers
    # binds its browser bundle to the session UA, so the persona must
    # already be in place when the rotator is created.
    try:
        from .core.stealth import pick_user_agent, set_marker_prefix
        _ua = pick_user_agent(getattr(args, "user_agent", None),
                              getattr(args, "random_agent", False))
        if _ua and "User-Agent" not in headers:
            headers["User-Agent"] = _ua
        if getattr(args, "marker_prefix", None):
            set_marker_prefix(args.marker_prefix)
    except Exception as e:                       # stealth must never break setup
        _log.debug("stealth wiring skipped: %s", e)

    # Phase 51: proxy rotation / header rotation / pacing jitter (the last
    # un-wired half of the pentest audit's stealth item).  All default OFF.
    _proxy_pool = None
    try:
        from .core.stealth import load_proxies
        _proxy_pool = load_proxies(getattr(args, "proxy_list", None)) or None
        if _proxy_pool:
            print(f"[*] Proxy rotation: {len(_proxy_pool)} proxy/proxies "
                  f"in pool")
    except Exception as e:
        _log.debug("proxy pool setup skipped: %s", e)
        _proxy_pool = None

    requester = Requester(timeout=args.timeout, proxy=args.proxy,
                          headers=headers or None, cookies=cookies or None,
                          verify_ssl=args.verify_ssl,
                          rate_limit=args.rate_limit,
                          proxy_pool=_proxy_pool,
                          rotate_headers=getattr(args, "rotate_headers",
                                                 False),
                          jitter=getattr(args, "jitter_ratio", 0.0) or 0.0)

    # Phase 46: one shared request budget for the whole run (batch mode
    # included) -- the per-URL Scanner instances all spend against it via
    # the shared requester.
    if getattr(args, "max_requests", None) or \
            getattr(args, "max_requests_per_endpoint", None):
        from .core.budget import Budget
        requester.budget = Budget(
            max_total=getattr(args, "max_requests", None),
            max_per_endpoint=getattr(args, "max_requests_per_endpoint", None))

    # Phase 46: circuit breaker -- stop gracefully when the target starts
    # answering 5xx/429 in bulk (down / overloaded / already blocking us).
    _bth = getattr(args, "breaker_threshold", 25)
    if _bth and _bth > 0:
        from .core.budget import CircuitBreaker
        requester.breaker = CircuitBreaker(threshold=_bth, window=120.0)

    # Pre-scan login (returns a SessionManager so the scan loop can keep
    # the session alive -- Phase 45: previously the return value was
    # discarded and the session silently expired on long scans).
    session_mgr = _do_login(requester, args)

    # OOB listener.
    oob = make_listener(args.oob) if args.oob else None

    # Progress reporter.
    progress = _build_progress(args.progress)

    # Checkpoint (resume or new).
    checkpoint = None
    if args.resume:
        checkpoint = Checkpoint.load(args.resume)
        if checkpoint:
            print(f"[*] Resumed from {args.resume} "
                  f"({checkpoint.scanned_count} URL(s) already scanned)")
        else:
            print(f"[*] No checkpoint at {args.resume}, starting fresh")
            checkpoint = Checkpoint(args.resume, urls[0] if urls else "")
    elif args.checkpoint:
        checkpoint = Checkpoint(args.checkpoint, urls[0] if urls else "")

    # Determine output path (file or directory for batch).  --batch-stdin
    # and --har behave like --batch for reporting purposes (per-target
    # files under -o DIR, or next to -o FILE when a directory is not
    # given).
    is_batch = bool(args.batch or args.batch_stdin or spec_targets)
    out_dir = None
    if is_batch:
        # Phase 88: -o may point at an existing directory (per-target
        # files inside), a fresh directory to create, or a file path whose
        # parent directory holds the per-target files.  Previously a
        # not-yet-existing -o DIR silently wrote reports into its parent
        # because dirname() was used before makedirs() could create it.
        if args.output and os.path.isdir(args.output):
            out_dir = args.output
        elif args.output and os.path.splitext(args.output)[1]:
            # Looks like a file (has an extension): use its parent.
            out_dir = os.path.dirname(args.output) or "."
        else:
            # Directory (existing or to-be-created) or "-o out/".
            out_dir = args.output or "."
        os.makedirs(out_dir, exist_ok=True)

    # Run scan(s).
    total_findings = 0
    failed_targets: list[str] = []  # Phase 25-2: track per-target failures

    # Phase 25-3: when --async is enabled with multiple URLs, run ALL URLs
    # through a single asyncio.run() call (one event loop, one aiohttp
    # session) instead of N separate asyncio.run() calls.  This avoids
    # N event-loop teardowns and N DNS/SSL cold starts.
    async_results: dict[str, object] = {}
    if (getattr(args, "async_mode", False) and len(urls) > 1
            and not all(checkpoint and checkpoint.is_scanned(u) for u in urls)):
        try:
            async_results = _run_async_batch(
                args, urls, requester, oob, progress, checkpoint)
        except Exception as e:
            _log.error("async batch failed: %s", e, exc_info=args.verbose)
            async_results = {}

    for i, url in enumerate(urls):
        if checkpoint and checkpoint.is_scanned(url) and url not in async_results:
            print(f"[*] Skipping already-scanned: {url}")
            continue
        if len(urls) > 1:
            print(f"\n[{i+1}/{len(urls)}] {url}")

        # Phase 88 (P1): HAR entries carry their own method/body/cookies/
        # headers.  Apply them as per-target overrides on a shallow copy so
        # the global args (and every later target) stay untouched.
        scan_args = args
        if spec_targets:
            import copy as _copy
            scan_args = _copy.copy(args)
            tgt = spec_targets[i]
            scan_args.method = tgt["method"]
            scan_args.data = tgt.get("data", "")
            # Per-target cookie/header markers consumed by _run_scan to
            # derive a dedicated requester clone for this endpoint.
            scan_args._har_target = True
            scan_args.cookie = "; ".join(tgt["cookies"]) \
                if tgt.get("cookies") else getattr(args, "cookie", None)
            scan_args.har_headers = list(tgt.get("headers", []))

        # Phase 25-2: wrap the per-target scan so a single failing target
        # (connection refused, DNS failure, scanner bug, ...) does NOT abort
        # the whole batch.  The failure is recorded, reported in the final
        # summary, and counted towards the CI exit-code gate so a flaky
        # batch is visible to the operator instead of silently truncated.
        scanner = None
        try:
            # Phase 45: keep the authenticated session alive across URLs
            # (age-based refresh always; loss-detection probe when asked).
            if session_mgr is not None:
                try:
                    if session_mgr.keep_alive(
                            probe_url=url,
                            relogin_on_loss=getattr(
                                args, "auth_relogin_on_loss", False)):
                        _log.info("Session re-established for %s", url)
                except Exception as e:
                    _log.debug("session keep-alive failed: %s", e)
            if async_results:
                # Phase 25-3: use the pre-computed async batch result.
                scanner = async_results.get(url)
                if scanner is None:
                    raise RuntimeError(
                        "async batch scan did not produce a result for this URL")
            elif getattr(args, "async_mode", False):
                scanner = _run_async_scan(args, url, oob, progress, checkpoint)
            if scanner is None:
                scanner = _run_scan(scan_args, url, requester, oob,
                                    progress, checkpoint)
        except Exception as e:
            _log.error("Scan failed for %s: %s", url, e, exc_info=args.verbose)
            failed_targets.append(url)
            # Record the failure in the checkpoint so --resume doesn't
            # re-scan a target that crashed the scanner last time.
            if checkpoint:
                checkpoint.mark_scanned(url)
            continue

        total_findings += len(scanner.findings)

        # Write report.
        if out_dir:
            # Phase 88: sanitise the per-target filename for the host
            # filesystem.  URLs contain ':' (and possibly other reserved
            # chars); on Windows ':' silently becomes an NTFS alternate
            # data stream, so ``http_127.0.0.1:8080_a.json`` created a
            # 0-byte ``http_127.0.0.1`` file with the report hidden in an
            # ADS -- the report appeared to vanish.  Replace every
            # filesystem-reserved character with '_'.
            import re as _re
            safe_name = url.replace("://", "_").replace("?", "_")
            safe_name = _re.sub(r'[\\/:*?"<>|\r\n\t]', "_", safe_name)
            safe_name = safe_name[:80].strip(". ")
            out_path = os.path.join(out_dir, f"{safe_name}.{args.format}")
        else:
            out_path = args.output

        meta = {"target": url}
        try:
            out_path = _write_report(scanner, url, out_path, args.format, meta)
        except Exception as e:
            _log.error("Report write failed: %s", e, exc_info=args.verbose)
            failed_targets.append(url)
            continue

        hi = sum(1 for f in scanner.findings
                 if (f.data if hasattr(f, "data") else f).get("severity") == "high")
        if len(urls) == 1:
            print(f"[+] Done. {len(scanner.findings)} finding(s) "
                  f"({hi} high). Report: {out_path}")
            if scanner.waf_name:
                print(f"[*] WAF detected: {scanner.waf_name}")

    if len(urls) > 1:
        # Phase 25-2: include the failure count in the batch summary so the
        # operator knows some targets were skipped due to errors.
        ok = len(urls) - len(failed_targets)
        print(f"\n[+] Batch complete: {len(urls)} target(s) "
              f"({ok} ok, {len(failed_targets)} failed), "
              f"{total_findings} total finding(s).")
        if failed_targets:
            print(f"[!] Failed targets:")
            for u in failed_targets:
                print(f"    - {u}")

    # Final checkpoint save.
    if checkpoint:
        checkpoint.save()
        if args.checkpoint or args.resume:
            print(f"[*] Checkpoint saved: {checkpoint.path}")

    # CI exit-code gate: if --exit-code is set and total findings >= threshold,
    # exit with non-zero so CI pipelines can fail the build.
    if args.exit_code > 0 and total_findings >= args.exit_code:
        print(f"\n[!] CI gate: {total_findings} findings >= threshold "
              f"{args.exit_code} -- exiting with code 1.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
