"""Scan execution for the CLI (Phase 43 split from __main__.py).

Hosts the single-target scan runner, the async single/batch runners, the
pre-scan login helper, the progress factory, and the report writer.  The
``__main__`` module re-exports these names so existing tests and imports
(``xssentinel.__main__._run_async_batch``) keep working.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from .core.requester import Requester  # noqa: F401  (shared with cli_commands)
from .core.budget import BudgetExhausted, CircuitOpen
from .core.scanner import Scanner
from .core import report as reportmod
from .core.progress import ConsoleProgress, NullProgress
from .core.session import SessionManager, login_with_csrf
from .core.logger import get_logger

_log = get_logger("cli")


def load_target_urls(batch_file=None, batch_stdin=False, url=None,
                     stdin=None) -> tuple[list[str], str | None]:
    """Phase 88: resolve target URL list from --batch FILE, --batch-stdin
    or -u URL, applying comment/blank stripping and duplicate suppression.

    Returns ``(urls, error)`` -- ``error`` is a human message when the
    caller should abort (missing file, empty stdin, no target, TTY stdin
    without piped input, mutually-exclusive flags already handled by
    argparse), else None.

    ``stdin`` is injectable for tests (defaults to ``sys.stdin``).
    Duplicate keys are ``scheme://netloc/path?query`` so identical recon
    lines (e.g. httpx + same URL twice) collapse to one scan.
    """
    import sys as _sys
    urls: list[str] = []
    if batch_file and batch_stdin:
        return [], "--batch and --batch-stdin are mutually exclusive"
    if batch_file:
        if not os.path.isfile(batch_file):
            return [], f"Batch file not found: {batch_file}"
        with open(batch_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f
                    if line.strip() and not line.startswith("#")]
    elif batch_stdin:
        src = stdin if stdin is not None else _sys.stdin
        try:
            is_tty = src.isatty()
        except Exception:
            is_tty = False
        if is_tty:
            return [], ("--batch-stdin needs piped input (stdin is a TTY). "
                        "Example: type urls.txt | xssentinel --batch-stdin "
                        "-o out/")
        urls = [line.strip() for line in src
                if line.strip() and not line.startswith("#")]
        if not urls:
            return [], "No URLs read from stdin"
    elif url:
        urls = [url]
    else:
        return [], None  # caller prints usage

    if len(urls) > 1:
        seen: set[str] = set()
        deduped: list[str] = []
        for u in urls:
            key = u
            try:
                p = urlparse(u)
                if p.scheme and p.netloc:
                    key = f"{p.scheme}://{p.netloc}{p.path}"
                    if p.query:
                        key += "?" + p.query
            except Exception:
                pass
            if key in seen:
                _log.info("Dropping duplicate target: %s", u)
                continue
            seen.add(key)
            deduped.append(u)
        urls = deduped
    return urls, None


def _build_progress(mode: str):
    """Build a progress reporter for the given mode string."""
    if mode == "none":
        return NullProgress()
    return ConsoleProgress(show_bar=(mode == "bar"))


def _do_login(requester, args) -> "SessionManager | None":
    """Perform pre-scan authentication; return a SessionManager.

    Phase 45: SessionManager already implemented form / basic / header /
    cookie / token / OAuth (+ RFC 6749 refresh), but the CLI only ever
    called the two-step ``login_with_csrf`` helper, so every other method
    was dead code.  This wires them up and returns the manager so the scan
    loop can keep the session alive.

    Returns the manager when some auth was configured (even if it fails --
    the caller reports and continues unprotected), else None.
    """
    want = [args.login_url, getattr(args, "login_basic", None),
            getattr(args, "login_header", None),
            getattr(args, "login_token", None),
            getattr(args, "login_oauth_token", None)]
    if not any(want):
        return None

    mgr = SessionManager(requester)
    interval = getattr(args, "auth_refresh_interval", 1800.0) or 1800.0
    mgr.refresh_threshold = float(interval)
    ok = False

    try:
        if args.login_url and args.login_user:
            # Form login. Use the richer login_form when markers are given
            # (otherwise fall back to the legacy csrf helper).
            print(f"[*] Logging in at {args.login_url} ...")
            creds = {args.login_field_user: args.login_user,
                     args.login_field_pass: args.login_pass or ""}
            marker = getattr(args, "login_success_marker", None)
            fail_marker = getattr(args, "login_failure_marker", None)
            if marker or fail_marker:
                ok = mgr.login_form(args.login_url, creds, method="POST",
                                    success_marker=marker,
                                    failure_marker=fail_marker)
            else:
                ok = login_with_csrf(
                    requester, args.login_url, args.login_user,
                    args.login_pass or "",
                    username_field=args.login_field_user,
                    password_field=args.login_field_pass,
                    csrf_field=args.login_csrf_field)
                if ok:
                    mgr.logged_in = True
                    mgr.login_time = time.time()
                    mgr._login_url = args.login_url
                    mgr._login_data = creds
                    mgr._login_method = "POST"
            print("[+] Login succeeded (session cookie captured)" if ok
                  else "[!] Login failed -- continuing without auth")

        elif getattr(args, "login_basic", None):
            if ":" not in args.login_basic:
                _log.error("--login-basic expects USER:PASS")
            else:
                u, _, p = args.login_basic.partition(":")
                ok = mgr.login_basic(u, p)
                print("[+] Basic auth configured" if ok
                      else "[!] Basic auth setup failed")

        elif getattr(args, "login_header", None):
            if ":" not in args.login_header:
                _log.error("--login-header expects 'NAME: VALUE'")
            else:
                name, _, value = args.login_header.partition(":")
                ok = mgr.login_header(name.strip(), value.strip())
                print(f"[+] Auth header {name.strip()} configured" if ok
                      else "[!] Auth header setup failed")

        elif getattr(args, "login_oauth_token", None):
            ok = mgr.login_oauth_token(
                args.login_oauth_token,
                refresh_token=getattr(args, "oauth_refresh", None),
                verify_url=getattr(args, "login_verify_url", None),
                client_id=getattr(args, "oauth_client_id", None),
                client_secret=getattr(args, "oauth_client_secret", None),
                token_url=getattr(args, "oauth_token_url", None),
            )
            refresh_ready = bool(mgr._oauth_refresh)
            print("[+] OAuth token accepted" if ok else
                  "[!] OAuth token rejected")
            if ok and refresh_ready:
                print("[+]   refresh flow armed (auto-renew before expiry)")

        elif getattr(args, "login_token", None):
            ok = mgr.login_token(
                args.login_token,
                header_name=getattr(args, "login_token_header",
                                    "Authorization"),
                scheme=getattr(args, "login_token_scheme", "Bearer"),
                verify_url=getattr(args, "login_verify_url", None),
                success_marker=getattr(args, "login_verify_marker", None),
            )
            print("[+] Token accepted" if ok else "[!] Token rejected")
    except Exception as e:                       # never abort the scan
        _log.warning("Authentication setup failed: %s", e)
        return None

    if not ok:
        _log.warning("Continuing without authentication")
        return mgr
    # Phase 45: watch every response; a session dying MID-scan (single long
    # URL, thousands of requests) is re-authenticated immediately instead
    # of silently scanning anonymously after expiry.
    try:
        mgr.attach(requester)
    except Exception:
        pass
    return mgr


def _maybe_run_fast_checks(args, requester, url: str, method: str,
                           params: dict, data: dict, findings: list) -> None:
    """Phase 44 fast checks in STANDALONE mode (--sqli-check /
    --check-outdated-js without --passive).

    In passive mode these run inside ``_run_passive_proxy``'s on_scan
    hook; on a direct ``xssentinel -u URL --sqli-check`` scan they must
    piggyback on the main pipeline here -- otherwise the flags parse but
    silently do nothing.
    """
    if getattr(args, "sqli_check", False):
        try:
            from .core.sqli import run_sqli_check
            from .core.scanner import Finding
            for f in run_sqli_check(requester, url, method=method,
                                    params=params, data=data):
                findings.append(Finding(**f))
        except Exception as e:
            _log.debug("sqli-check failed for %s: %s", url, e)
    if getattr(args, "check_outdated_js", False):
        try:
            from .core.retire_js import scan_html
            from .core.scanner import Finding
            # One extra GET to read the rendered HTML (cheap, by design).
            html = requester.get(url, params=params or None).text or ""
            for f in scan_html(html, base_url=url):
                findings.append(Finding(**f))
        except Exception as e:
            _log.debug("outdated-js check failed for %s: %s", url, e)


def _base_url_keeping_fragment(parsed) -> str:
    """``scheme://host/path`` plus the fragment, if there is one.

    Phase 145.  The fragment is deliberately preserved.  An HTTP request
    never carries it -- clients strip it before sending -- so this changes
    nothing about what reaches the server, but the real-browser DOM engine
    needs it: an SPA router puts its parameters INSIDE the fragment
    (``#/search?q=``), and dropping it here pointed the browser at the site
    root instead, which made every hash-routed DOM XSS invisible.  Checked
    directly against OWASP Juice Shop: the fragment-bearing URL yields the
    finding, the stripped one does not.
    """
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.fragment:
        base += "#" + parsed.fragment
    return base


def _run_scan(args, url: str, requester, oob, progress, checkpoint,
              auth_state=None):
    """Run a single-target scan and return findings.

    ``auth_state`` is the ``(headers, cookies)`` pair replicating the
    authenticated session inside the DOM engine's browser (Phase 150) --
    see main() where it is computed.
    """
    import json as _json
    from xssentinel.__main__ import _parse_kv, apply_scan_policy

    # Phase 88 (P1): HAR imports carry per-target cookies/headers that
    # differ from the requester's global session (built from CLI flags
    # before the batch loop).  The requester is shared across targets and
    # owns the budget/breaker/proxy rotation, so we never mutate it -- we
    # derive a clone with the target's cookie jar and extra headers.  The
    # clone still shares budget/breaker/pool/on_response via clone().
    if (getattr(args, "_har_target", False)
            and (getattr(args, "cookie", None)
                 or getattr(args, "har_headers", None))):
        try:
            _req = requester.clone()
            # Replace the cookie jar wholesale with the target's cookies
            # (clone() copies the global ones).
            _req.session.cookies.clear()
            if getattr(args, "cookie", None):
                for part in args.cookie.split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        _req.session.cookies.set(k.strip(), v.strip())
            for h in getattr(args, "har_headers", []) or []:
                if ":" in h:
                    k, v = h.split(":", 1)
                    _req.session.headers[k.strip()] = v.strip()
            requester = _req
            # Phase 150: the DOM browser must see THIS target's cookies,
            # not the global jar's -- recompute the cookie half of
            # auth_state from the clone.
            if auth_state:
                auth_state = (auth_state[0],
                              [{"name": c.name, "value": c.value or "",
                                "domain": c.domain or None,
                                "path": c.path or "/"}
                               for c in _req.session.cookies],
                              *auth_state[2:])
        except Exception as e:
            _log.debug("per-target requester clone failed, using shared "
                       "requester: %s", e)

    params, data = {}, {}
    kv = _parse_kv(args.data)
    if args.method == "POST":
        data = kv
    else:
        params = kv
    parsed = urlparse(url)

    # Phase 46: JSON-body support.  A `-d` value that parses as a JSON
    # object (or an explicit --json flag) switches the body carrier: body
    # params become the LEAF paths of the document and probes are sent as
    # application/json instead of form encoding.  Previously JSON APIs --
    # the majority of modern POST endpoints -- were silently scanned with
    # a form body the server ignored (mass false negatives).
    json_body = None
    raw_data = (getattr(args, "data", "") or "").strip()
    want_json = bool(getattr(args, "json_body", False))
    if raw_data.startswith("{") or (want_json and raw_data):
        try:
            parsed_json = _json.loads(raw_data)
            if isinstance(parsed_json, dict) and args.method == "POST":
                data = {}
                json_body = parsed_json
        except ValueError:
            if want_json:
                _log.warning("--json given but -d is not valid JSON; "
                             "falling back to form encoding")
    base_url = _base_url_keeping_fragment(parsed)
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.setdefault(k, v)

    custom_pl = []
    if args.custom_payloads and os.path.isfile(args.custom_payloads):
        with open(args.custom_payloads, "r", encoding="utf-8") as f:
            custom_pl = [line.strip() for line in f
                         if line.strip() and not line.startswith("#")]

    # Phase 33: apply the scan-policy preset (explicit flags already set
    # win; the preset only fills unset policy-managed parameters).
    apply_scan_policy(args)

    # ``load_wordlist`` lives in core.param_miner; the name used to be
    # referenced here without any import, so ``--param-wordlist`` raised
    # NameError before the scan even started.
    _param_wl = None
    if getattr(args, "param_wordlist", None):
        from .core.param_miner import load_wordlist
        _param_wl = load_wordlist(args.param_wordlist)

    scanner = Scanner(
        requester=requester, use_headless=args.headless,
        max_transforms=args.max_transforms, max_payloads=args.max_payloads,
        crawl=args.crawl, crawl_depth=args.crawl_depth, scope=args.scope,
        threads=args.threads, oob=oob, dom_engine=args.dom_engine,
        verbose=args.verbose, progress=progress, checkpoint=checkpoint,
        custom_payloads=custom_pl, crawl_engine=args.crawl_engine,
        scenario_file=getattr(args, "scenarios", None),
        bav=bool(getattr(args, "bav", False)),
        param_wordlist=_param_wl,
        max_requests=getattr(args, "max_requests", None),
        max_requests_per_endpoint=getattr(
            args, "max_requests_per_endpoint", None),
        upload_fields=getattr(args, "upload_field", None),
        poc_include_auth=getattr(args, "poc_include_auth", False),
        poc_verify=getattr(args, "poc_verify", True),
        xsleak_audit=getattr(args, "xsleak_audit", False),
        auth_headers=(auth_state or (None, None, None))[0],
        auth_cookies=(auth_state or (None, None, None))[1],
        auth_local_storage=(auth_state or (None, None, None))[2])
    # Phase 46: JSON-carrier mode (see _run_scan docstring above).
    if json_body is not None:
        scanner.json_body = json_body

    # Fuzzer pre-flight (Phase 17 + Phase 22-4): if --fuzz is set, run the
    # response-difference fuzzer on the endpoint's params before the main
    # scan.  The fuzzer triages which params are worth deep payload testing.
    # Phase 22-4: the triage result now ACTUALLY filters the param list
    # passed to the Scanner, so only the top-N highest-scoring params get
    # deep payload testing -- reducing request volume on wide-attack-surface
    # endpoints from O(all_params * max_payloads) to O(top_n * max_payloads).
    fuzz_top_n = getattr(args, "fuzz_top_n", 5)
    if getattr(args, "fuzz", False):
        try:
            from .core import fuzzer as fuzzer_mod
            print(f"\n[*] Fuzzer mode: triaging params for {base_url}")
            # Phase 43: operator wordlist (--param-wordlist) is PREPENDED
            # to the built-in candidates; triage is one cheap request per
            # candidate, so the full expanded list (300+) is affordable.
            from .core.param_miner import load_wordlist, merged_candidates
            wl_path = getattr(args, "param_wordlist", None)
            extra = load_wordlist(wl_path) if wl_path else None
            candidates = merged_candidates(extra)
            fuzz_results = fuzzer_mod.fuzz_endpoint(
                requester, base_url, method=args.method,
                params=params, data=data,
                candidate_names=candidates,
                max_params=100, verbose=args.verbose)
            injectable = [r for r in fuzz_results if r.get("injectable")]
            print(f"[+] Fuzzer: {len(injectable)}/{len(fuzz_results)} "
                  f"params scored injectable (>= 30 points)")
            for r in fuzz_results[:5]:
                score = r.get("score", 0)
                name = r.get("name", "?")
                ctx_name = r.get("context", "?")
                print(f"    - {name}: score={score} ctx={ctx_name} "
                      f"injectable={r.get('injectable', False)}")
            # Attach fuzzer findings as low-severity info entries so they
            # appear in the report.
            for r in injectable:
                from .core.scanner import Finding
                scanner.findings.append(Finding(
                    url=base_url, method=args.method, param=r["name"],
                    context=r.get("context", "html_element"),
                    payload="(fuzzer triage)",
                    severity="info",
                    evidence=(
                        f"Fuzzer triage: score={r['score']}, "
                        f"context={r.get('context', '?')}, "
                        f"traces={r.get('encoding_traces', [])}"
                    ),
                    type="fuzzer_triage",
                    confidence="medium",
                ))
            # Phase 22-4: use triage result to filter the param list.
            # Only the top-N highest-scoring params are passed to the
            # Scanner for deep payload testing.  Existing user-supplied
            # params are always kept (the user explicitly asked for them).
            top_names = set(fuzzer_mod.select_top_candidates(
                fuzz_results, top_n=fuzz_top_n))
            # Keep user-supplied params + fuzzer-selected top params.
            user_params = set(params.keys()) | set(data.keys())
            kept = user_params | top_names
            if kept:
                params = {k: v for k, v in params.items() if k in kept}
                data = {k: v for k, v in data.items() if k in kept}
                # Add fuzzer-discovered params not already present.
                for r in fuzz_results:
                    name = r.get("name", "")
                    if name in top_names and name not in user_params:
                        if args.method == "POST":
                            data.setdefault(name, "xss")
                        else:
                            params.setdefault(name, "xss")
                print(f"[*] Fuzzer triage: {len(kept)} param(s) selected "
                      f"for deep payload testing (top-{fuzz_top_n} + "
                      f"user-supplied)")
        except Exception as e:
            _log.warning("Fuzzer pre-flight error: %s", e, exc_info=args.verbose)

    scanner.scan_target(base_url, method=args.method, params=params,
                        data=data, oob_collect=False)

    # Phase 44 standalone fast checks (--sqli-check / --check-outdated-js).
    _maybe_run_fast_checks(args, requester, base_url, args.method,
                           params, data, scanner.findings)

    if args.stored_inject:
        if getattr(args, "stored_dom", False):
            # Phase 152: SPA shape -- the view page renders the stored value
            # client-side, so verification happens in the real browser.
            # Phase 152b: companion fields for write APIs that demand
            # password/csrf/captcha alongside the payload field.
            extras: dict = {}
            for pair in (getattr(args, "stored_extra", None) or []):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    extras[k.strip()] = v.strip()
            scanner.scan_stored_dom(args.stored_inject,
                                    view_url=args.stored_view,
                                    param=args.stored_param,
                                    extra_fields=extras)
        else:
            scanner.scan_stored(args.stored_inject, view_url=args.stored_view,
                                param=args.stored_param,
                                fresh_session=getattr(
                                    args, "stored_fresh_session", False))

    if args.second_order_inject:
        viewers = None
        if args.second_order_viewers:
            viewers = [u.strip() for u in args.second_order_viewers.split(",")
                       if u.strip()]
        scanner.scan_second_order(
            args.second_order_inject,
            param=args.second_order_param,
            method=args.second_order_method,
            start_url=args.second_order_start,
            viewer_urls=viewers,
        )

    if oob is not None:
        scanner.oob_timeout = getattr(args, "oob_timeout", 12)
        scanner.oob_keep_listening = bool(
            getattr(args, "oob_keep_listening", False))
        scanner.collect_oob(timeout=args.oob_timeout)

    scanner.dedup()
    scanner.attach_pocs()
    return scanner


def _stealth_proxy_pool(args):
    """Parse --proxy-list once (Phase 51) so sync and async paths share it."""
    try:
        from .core.stealth import load_proxies
        return load_proxies(getattr(args, "proxy_list", None)) or None
    except Exception as e:                     # stealth must never break setup
        _log.debug("proxy pool skipped: %s", e)
        return None


def _run_async_scan(args, url: str, oob, progress, checkpoint,
                    auth_state=None):
    # Phase 85: async mode does not implement these sync-only features;
    # warn instead of silently ignoring them.
    for _flag in ("fuzz", "bav", "scenarios", "stored_inject",
                  "stored_dom", "second_order_inject"):
        if getattr(args, _flag, None):
            print(f"[!] --{_flag.replace('_', '-')} is sync-only and is "
                  "ignored in --async mode", file=sys.stderr)

    """Phase 22-1: run a scan via AsyncScanner when ``--async`` is enabled.

    The async scanner mirrors the sync pipeline (L1 reflected / L2 WAF /
    L3 DOM / L4 blind / L5 advanced / L6 CSP+JSONP) but uses aiohttp for
    high-throughput concurrent I/O.  Findings are collected into a
    lightweight Scanner-compatible shim so the same report writer works.
    """
    import asyncio
    from .core.async_scanner import AsyncScanner, is_available as async_available

    if not async_available():
        _log.warning("--async requested but aiohttp is not installed. "
                     "Install with: pip install aiohttp.  Falling back to sync scan.")
        return None  # caller falls back to _run_scan

    from xssentinel.__main__ import _parse_kv, apply_scan_policy
    # Phase 43 fix: scan-policy presets fill max_payloads/max_transforms/
    # threads (argparse defaults are None since Phase 33) -- without this
    # the AsyncScanner constructor below crashed on `args.threads > 1`.
    apply_scan_policy(args)
    params, data = {}, {}
    kv = _parse_kv(args.data)
    if args.method == "POST":
        data = kv
    else:
        params = kv
    parsed = urlparse(url)
    base_url = _base_url_keeping_fragment(parsed)
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.setdefault(k, v)

    # Phase 47: JSON-body support on the async path (sync parity).  A -d
    # value that parses as a JSON object (or an explicit --json flag)
    # switches the body carrier: body params become the LEAF paths of the
    # document and probes are sent as application/json.  The old --async
    # path never parsed JSON bodies, so JSON APIs were form-encoded and
    # silently untested.
    json_body = None
    raw_data = (getattr(args, "data", "") or "").strip()
    want_json = bool(getattr(args, "json_body", False))
    if raw_data.startswith("{") or (want_json and raw_data):
        try:
            import json as _json
            parsed_json = _json.loads(raw_data)
            if isinstance(parsed_json, dict) and args.method == "POST":
                data = {}
                json_body = parsed_json
        except ValueError:
            if want_json:
                _log.warning("--json given but -d is not valid JSON; "
                             "falling back to form encoding")

    # Parse headers (-H "Name: Value") and cookies (-b "k=v; k2=v2").
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

    # Phase 46: apply stealth UA to the async path too (previously the
    # identifying default leaked into --async scans).
    try:
        from .core.stealth import pick_user_agent
        _ua = pick_user_agent(getattr(args, "user_agent", None),
                              getattr(args, "random_agent", False))
        if _ua and "User-Agent" not in headers:
            headers["User-Agent"] = _ua
    except Exception:
        pass

    asc = AsyncScanner(
        max_concurrent=args.threads * 5 if args.threads > 1 else 20,
        max_payloads=args.max_payloads, max_transforms=args.max_transforms,
        timeout=args.timeout, headers=headers, cookies=cookies,
        proxy=args.proxy, verify_ssl=not args.no_verify_ssl,
        verbose=args.verbose, crawl=args.crawl, crawl_depth=args.crawl_depth,
        oob=oob, advanced_layers=True,
        # Phase 65: honor --dom-engine in async mode too (was hardcoded
        # to 'off', silently dropping real-browser DOM confirmation).
        dom_engine=getattr(args, "dom_engine", "auto"),
        rate_limit=getattr(args, "rate_limit", 0) or 0,
        max_requests=getattr(args, "max_requests", None),
        max_requests_per_endpoint=getattr(
            args, "max_requests_per_endpoint", None),
        breaker_threshold=getattr(args, "breaker_threshold", 0) or 0,
        json_body=json_body,
        # Phase 51 (async parity): egress rotation / header rotation /
        # pacing jitter -- same options as the sync Requester path.
        proxy_pool=_stealth_proxy_pool(args),
        rotate_headers=getattr(args, "rotate_headers", False),
        jitter_ratio=getattr(args, "jitter_ratio", 0.0) or 0.0,
        xsleak_audit=getattr(args, "xsleak_audit", False),
        upload_fields=getattr(args, "upload_field", None),
        auth_headers=(auth_state or (None, None, None))[0],
        auth_cookies=(auth_state or (None, None, None))[1],
        auth_local_storage=(auth_state or (None, None, None))[2],
    )

    # Blind/OOB: pending injections are batch-collected at the end of
    # scan() (collect_oob_async, sync collect_oob parity) -- the CLI
    # oob-timeout / keep-listening knobs must be set BEFORE scanning.
    asc.oob_timeout = getattr(args, "oob_timeout", 12)
    asc.oob_keep_listening = bool(getattr(args, "oob_keep_listening", False))

    async def _do():
        async for finding in asc.scan(base_url, method=args.method,
                                      params=params, data=data):
            if progress:
                progress.on_endpoint_done(base_url, 1)

    try:
        asyncio.run(_do())
    except (BudgetExhausted, CircuitOpen) as e:
        _log.warning("[!] Scan stopped early (%s) -- %d finding(s) so far",
                     e, len(asc.findings))
    except Exception as e:
        _log.error("async scan error: %s", e, exc_info=args.verbose)


    # Wrap the async scanner's findings in a sync Scanner shim so the
    # report writer (which expects scanner.findings / scanner.requests_made
    # / scanner.waf_name / scanner.coverage) works unchanged.
    from .core.scanner import Scanner
    shim = Scanner(requester=None, verbose=args.verbose,
                   poc_include_auth=getattr(args, "poc_include_auth", False),
                   poc_verify=getattr(args, "poc_verify", True))
    shim.findings = list(asc.findings)
    shim.requests_made = asc.requests_made
    shim.waf_name = getattr(asc, "waf_name", None)
    # Phase 98b: bridge the ASYNC session's credentials into the shim's
    # requester.  attach_pocs reads self.req.session.{cookies,headers} --
    # on a fresh Scanner(requester=None) both were EMPTY, so the PoC
    # authentication replay silently no-op'd on the whole async path
    # (Phase 48 cookies AND Phase 98 headers).  The real credentials the
    # scan used live on the AsyncScanner (CLI -H / -b, stealth UA).
    try:
        for _k, _v in (getattr(asc, "cookies", None) or {}).items():
            shim.req.session.cookies.set(_k, _v)
        for _k, _v in (getattr(asc, "headers", None) or {}).items():
            shim.req.session.headers[_k] = _v
    except Exception:
        pass
    # Phase 44 standalone fast checks on the async path (they are cheap,
    # sync HTTP calls; piggyback before dedup so they are de-duplicated
    # alongside scanner findings).
    from .core.requester import Requester as _Requester
    _sync_req = _Requester(timeout=getattr(args, "timeout", 20) or 20,
                           proxy=args.proxy)
    _maybe_run_fast_checks(args, _sync_req, parsed.geturl(),
                           args.method, params, data, shim.findings)
    shim.dedup()
    shim.attach_pocs()
    return shim


def _run_async_batch(args, urls: list[str], requester, oob, progress,
                     checkpoint, auth_state=None) -> dict[str, object]:
    """Phase 25-3: scan a batch of URLs with a SINGLE asyncio.run() call.

    The previous approach called ``_run_async_scan`` (and thus
    ``asyncio.run``) once per URL, creating and destroying a new event
    loop + aiohttp session for every target.  For a 500-URL batch that
    meant 500 event-loop teardowns and 500 DNS/cache cold starts.

    This function creates ONE ``AsyncScanner`` and runs all URLs through
    it in a single ``asyncio.run()`` call, so:
      * The event loop is created/destroyed once (not N times).
      * The aiohttp ``ClientSession`` + ``TCPConnector`` are shared
        across URLs (DNS cache, connection pool, SSL context amortized).
      * The asyncio ``Semaphore`` (concurrency limiter) is shared, so
        the global concurrency cap is respected across all URLs.

    Returns a ``{url: scanner_shim}`` dict so the batch loop can write
    a per-URL report just like the sync path.  Failed URLs are omitted
    from the dict (the caller checks for missing keys).
    """
    import asyncio
    from .core.async_scanner import AsyncScanner, is_available as async_available

    if not async_available():
        _log.warning("--async requested but aiohttp is not installed.")
        return {}

    # Phase 43 fix: same scan-policy fill as _run_async_scan -- args.threads
    # etc. are None until the preset fills them (Phase 33 defaults).
    from xssentinel.__main__ import apply_scan_policy
    apply_scan_policy(args)

    # Build shared scan config (same logic as _run_async_scan, but once).
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

    # Phase 46: stealth UA on the batch path too.
    try:
        from .core.stealth import pick_user_agent
        _ua = pick_user_agent(getattr(args, "user_agent", None),
                              getattr(args, "random_agent", False))
        if _ua and "User-Agent" not in headers:
            headers["User-Agent"] = _ua
    except Exception:
        pass

    # Phase 47: JSON-body carrier on the batch path (sync parity).  A
    # shared -d JSON document switches every POST target's body probes to
    # application/json with leaf-path params.  Kept on a variable so the
    # target pre-parse below can drop the (garbage) form-encoded dict.
    json_body = None
    raw_data = (getattr(args, "data", "") or "").strip()
    want_json = bool(getattr(args, "json_body", False))
    if raw_data.startswith("{") or (want_json and raw_data):
        try:
            import json as _json
            parsed_json = _json.loads(raw_data)
            if isinstance(parsed_json, dict) and args.method == "POST":
                json_body = parsed_json
        except ValueError:
            if want_json:
                _log.warning("--json given but -d is not valid JSON; "
                             "falling back to form encoding")

    asc = AsyncScanner(
        max_concurrent=args.threads * 5 if args.threads > 1 else 20,
        max_payloads=args.max_payloads, max_transforms=args.max_transforms,
        timeout=args.timeout, headers=headers, cookies=cookies,
        proxy=args.proxy, verify_ssl=not args.no_verify_ssl,
        verbose=args.verbose, crawl=args.crawl, crawl_depth=args.crawl_depth,
        oob=oob, advanced_layers=True,
        # Phase 65: honor --dom-engine in async mode too (was hardcoded
        # to 'off', silently dropping real-browser DOM confirmation).
        dom_engine=getattr(args, "dom_engine", "auto"),
        rate_limit=getattr(args, "rate_limit", 0) or 0,
        max_requests=getattr(args, "max_requests", None),
        max_requests_per_endpoint=getattr(
            args, "max_requests_per_endpoint", None),
        breaker_threshold=getattr(args, "breaker_threshold", 0) or 0,
        json_body=json_body,
        # Phase 51 (async parity): egress rotation / header rotation /
        # pacing jitter -- same options as the sync Requester path.
        proxy_pool=_stealth_proxy_pool(args),
        rotate_headers=getattr(args, "rotate_headers", False),
        jitter_ratio=getattr(args, "jitter_ratio", 0.0) or 0.0,
        xsleak_audit=getattr(args, "xsleak_audit", False),
        upload_fields=getattr(args, "upload_field", None),
        auth_headers=(auth_state or (None, None, None))[0],
        auth_cookies=(auth_state or (None, None, None))[1],
        auth_local_storage=(auth_state or (None, None, None))[2],
    )

    # Pre-parse each URL into (base_url, method, params, data) so the
    # async coroutine doesn't need to touch argparse.
    from xssentinel.__main__ import _parse_kv  # lazy: avoid circular import
    targets = []
    for url in urls:
        if checkpoint and checkpoint.is_scanned(url):
            continue
        params, data = {}, {}
        # JSON carrier: -d was the JSON document (stored in json_body), so
        # a form-encoded dict from _parse_kv would be garbage -- keep the
        # body empty and let the scanner rebuild it from json_body.
        if json_body is None:
            kv = _parse_kv(args.data)
            if args.method == "POST":
                data = kv
            else:
                params = kv
        parsed = urlparse(url)
        base_url = _base_url_keeping_fragment(parsed)
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params.setdefault(k, v)
        targets.append((url, base_url, params, data))

    # Track per-URL findings by recording the findings-list length before
    # each URL scan.  Findings [before, after) belong to that URL.
    findings_ranges: dict[str, tuple[int, int]] = {}
    requests_before: dict[str, int] = {}

    # Phase 85: async mode does not implement these sync-only features;
    # warn instead of silently ignoring them.
    for _flag in ("fuzz", "bav", "scenarios", "stored_inject",
                  "stored_dom", "second_order_inject"):
        if getattr(args, _flag, None):
            print(f"[!] --{_flag.replace('_', '-')} is sync-only and is "
                  "ignored in --async mode", file=sys.stderr)
    async def _do_all():
        # Blind/OOB knobs must be set before the first scan (Phase 64).
        asc.oob_timeout = getattr(args, "oob_timeout", 12)
        asc.oob_keep_listening = bool(
            getattr(args, "oob_keep_listening", False))
        for orig_url, base_url, params, data in targets:
            before = len(asc.findings)
            req_before = asc.requests_made
            try:
                async for _finding in asc.scan(base_url, method=args.method,
                                               params=params, data=data):
                    if progress:
                        progress.on_endpoint_done(base_url, 1)
                findings_ranges[orig_url] = (before, len(asc.findings))
                requests_before[orig_url] = asc.requests_made - req_before
            except (BudgetExhausted, CircuitOpen) as e:
                # Total budget / circuit breaker are GLOBAL -- stop the
                # whole batch (not just this URL) so we don't hammer a
                # protected target.
                findings_ranges[orig_url] = (before, len(asc.findings))
                requests_before[orig_url] = asc.requests_made - req_before
                _log.warning("[!] Scan stopped early (%s) -- stopping "
                             "batch after %s", e, orig_url)
                raise
            except Exception as e:
                _log.error("async batch scan failed for %s: %s",
                           orig_url, e, exc_info=args.verbose)
                # Record the range so the caller knows this URL was
                # attempted (even though it produced 0 findings).
                findings_ranges[orig_url] = (before, len(asc.findings))
                requests_before[orig_url] = asc.requests_made - req_before

    # NOTE (P1-5): per-URL failures are handled INSIDE _do_all (they must
    # not kill the batch); loop-level failures (socketpair/loop creation)
    # and BudgetExhausted (global cap) MUST propagate so callers/CI see the
    # real problem instead of an empty result dict that looks like a scan
    # with zero findings.
    try:
        asyncio.run(_do_all())
    except (BudgetExhausted, CircuitOpen) as e:
        _log.warning("[!] Batch stopped: %s; findings so far are preserved "
                     "in the per-URL reports.", e)

    # Build a per-URL Scanner shim from the shared findings list.
    from .core.scanner import Scanner
    results: dict[str, object] = {}
    for orig_url, base_url, _, _ in targets:
        rng = findings_ranges.get(orig_url)
        if rng is None:
            continue  # URL was skipped (checkpoint) or errored before tracking
        lo, hi = rng
        shim = Scanner(requester=None, verbose=args.verbose,
                   poc_include_auth=getattr(args, "poc_include_auth", False),
                   poc_verify=getattr(args, "poc_verify", True))
        shim.findings = list(asc.findings[lo:hi])
        shim.requests_made = requests_before.get(orig_url, 0)
        shim.waf_name = getattr(asc, "waf_name", None)
        # Phase 98b: same credential bridge as the single-URL async path
        # (attach_pocs reads the shim's session, which was empty).
        try:
            for _k, _v in (getattr(asc, "cookies", None) or {}).items():
                shim.req.session.cookies.set(_k, _v)
            for _k, _v in (getattr(asc, "headers", None) or {}).items():
                shim.req.session.headers[_k] = _v
        except Exception:
            pass
        shim.dedup()
        shim.attach_pocs()
        results[orig_url] = shim
        # Mark as scanned in the checkpoint.
        if checkpoint:
            checkpoint.mark_scanned(orig_url)
    return results


def ai_opts_from_args(args) -> dict:
    """Build the ``meta['ai']`` block from CLI args (Phase 176).

    Shared by the main scan path and the passive-proxy path so both get the
    same pool sharing (one pool per process => cooldowns apply across every
    target) and the same operator-facing hints.

    Never raises: an unloadable pool yields ``enabled: True`` with
    ``pool: None``, and ``report_ai`` then degrades to the template.  That way
    ``--ai-report`` still produces a section even on a machine with no config.
    """
    if not getattr(args, "ai_report", False):
        return {}
    from .core.llm_pool import LLMPool
    pool = None
    try:
        pool = LLMPool.from_file(getattr(args, "ai_config", None))
        print(f"[*] AI report on: {len(pool.candidates)} candidate(s) from "
              f"{pool.source}")
    except Exception as e:
        print(f"[!] --ai-report: cannot load the LLM pool "
              f"({type(e).__name__}: {e}); the AI section will come from the "
              f"built-in advice corpus.")
    models = None
    raw = getattr(args, "ai_model", None)
    if raw:
        models = [m.strip() for m in str(raw).split(",") if m.strip()] or None
    return {
        "enabled": True,
        "pool": pool,
        "config": getattr(args, "ai_config", None),
        "lang": getattr(args, "ai_lang", "zh"),
        "models": models,
        "max_findings": getattr(args, "ai_max_findings", 25),
        "timeout": getattr(args, "ai_timeout", None),
    }


def _attach_ai_report(scanner, target_url, meta):
    """Phase 176: attach the LLM-written narrative section to ``meta``.

    Opt-in (``--ai-report``) and never fatal: the detection results are
    authoritative and must be reported whether or not a model was reachable.
    ``report_ai`` degrades to the deterministic advice corpus on any failure,
    so this function's only job is to route the result into ``meta`` where
    the report builders pick it up.

    The pool is passed in via ``meta['ai']['pool']`` so a batch scan reuses
    ONE pool instance: cooldowns then apply across targets in the same
    process instead of each target re-discovering the same rate limit.
    """
    opts = meta.get("ai") or {}
    if not opts.get("enabled"):
        return
    try:
        from .core import report_ai
        rep = report_ai.build_ai_report(
            scanner.findings, target_url, meta,
            pool=opts.get("pool"),
            config_path=opts.get("config"),
            models=opts.get("models"),
            lang=opts.get("lang", "zh"),
            max_findings=int(opts.get("max_findings") or 25),
            timeout=opts.get("timeout"),
        )
        meta["ai_report"] = rep.to_meta()
        if rep.used_llm:
            _log.warning("AI report: written by %s (%d failover(s), %.1fs)",
                         rep.model or rep.provider, rep.failovers, rep.elapsed)
        else:
            _log.warning("AI report: degraded to template -- %s", rep.error)
    except Exception as e:
        # A narrative section is never worth failing a scan for.
        _log.warning("AI report generation failed (%s); report continues "
                     "without it", e)


def _write_report(scanner, target_url, output_path, fmt, meta=None):
    """Write scan report to file."""
    meta = meta or {}
    meta.setdefault("generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    meta.setdefault("requests", scanner.requests_made)
    meta.setdefault("waf", scanner.waf_name)
    # Phase 20-3: attach coverage tracker so HTML/JSON reports include
    # the scan-coverage section (which layers/params/payloads ran).
    if getattr(scanner, "coverage", None) is not None:
        meta.setdefault("coverage", scanner.coverage)
    # Phase 176: AI narrative -- must run BEFORE the builders read meta, and
    # after 'generated'/'requests' exist so the prompt carries real metadata.
    _attach_ai_report(scanner, target_url, meta)

    if fmt == "json":
        out = reportmod.build_json(scanner.findings, target_url, meta)
        if not output_path.endswith(".json"):
            output_path += ".json"
    elif fmt == "csv":
        out = reportmod.build_csv(scanner.findings, target_url, meta)
        if not output_path.endswith(".csv"):
            output_path += ".csv"
    elif fmt == "sarif":
        out = reportmod.build_sarif(scanner.findings, target_url, meta)
        if not output_path.endswith(".sarif"):
            output_path += ".sarif"
    elif fmt == "junit":
        out = reportmod.build_junit(scanner.findings, target_url, meta)
        if not output_path.endswith(".xml"):
            output_path += ".xml"
    elif fmt == "burp":
        # Phase 49: Burp Suite "export issue data" XML (Dradis/importers).
        out = reportmod.build_burp_xml(scanner.findings, target_url, meta)
        if not output_path.endswith(".xml"):
            output_path += ".xml"
    elif fmt == "nuclei":
        # Phase 49: one runnable nuclei template per finding -- a directory
        # artifact, so `nuclei -t <dir>` consumes it directly.
        base = output_path
        for ext in (".yaml", ".yml", ".nuclei"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        paths = reportmod.write_nuclei_dir(
            scanner.findings, target_url, meta, base)
        return base  # directory, not a single file
    elif fmt == "markdown":
        out = reportmod.build_markdown(scanner.findings, target_url, meta)
        if not output_path.endswith(".md"):
            output_path += ".md"
    else:
        out = reportmod.build_html(scanner.findings, target_url, meta)
        if not output_path.endswith(".html"):
            output_path += ".html"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(out)
    return output_path
