"""Sub-command handlers for the CLI (Phase 43 split from __main__.py).

Self-test orchestration, REST API server bootstrap, verify-fix replay, and
report diffing.  ``__main__`` re-exports these so ``cli._run_*`` attribute
access keeps working for tests.
"""
from __future__ import annotations

import json
import http.client
import os
import subprocess
import sys

from .core.requester import Requester
from .core.logger import get_logger

_log = get_logger("cli")

def _run_sandbox(args) -> int:
    """Phase 169: offline HTML sandbox -- try a payload before you send it.

    The point is the loop a scanner cannot offer: you are writing a payload for
    a reflection you have found, and you want to know *which* of the ~20 ways a
    server can reflect it the payload actually escapes, in microseconds, with no
    target and no browser.  Each cell says live / activation / inert / unknown
    and the interesting ones carry the parser's reason, so a "no" is explainable
    instead of mysterious.

    Exit code is informational (0), like --fuzz-body: the answer is the product.
    """
    from .core import sandbox

    if getattr(args, "sandbox_hosts", False):
        print("reflection contexts available to --sandbox-host:")
        for name, tpl in sorted(sandbox.HOSTS.items()):
            print(f"  {name:14s} {tpl}")
        return 0

    payload = getattr(args, "sandbox", None)
    response = getattr(args, "sandbox_response", None)
    if not payload and not response:
        print("--sandbox needs a PAYLOAD, or --sandbox-response <file|->",
              file=sys.stderr)
        return 1

    sinks = (["parser", "innerhtml"] if getattr(args, "sandbox_sink", "both") == "both"
             else [args.sandbox_sink])

    if response:
        if response == "-":
            html = sys.stdin.read()
        else:
            if not os.path.isfile(response):
                print(f"response file not found: {response}", file=sys.stderr)
                return 1
            with open(response, "r", encoding="utf-8", errors="replace") as fh:
                html = fh.read()
        token = getattr(args, "sandbox_token", "") or (payload or "")
        if not token:
            print("--sandbox-response needs --sandbox-token (or a --payload "
                  "to search for)", file=sys.stderr)
            return 1
        print(f"judging {len(html)} bytes of {response} for token "
              f"{token[:32]!r}\n")
        for sink in sinks:
            v = sandbox.judge(html, token, sink=sink)
            _print_verdict(f"sink={sink}", v)
            if getattr(args, "sandbox_roundtrip", False):
                r = sandbox.judge_roundtrip(html, token, sink=sink)
                _print_verdict(f"sink={sink} round-trip", r)
        return 0

    host = getattr(args, "sandbox_host", "all") or "all"
    hosts = sorted(sandbox.HOSTS) if host == "all" else [host]
    if host != "all" and host not in sandbox.HOSTS:
        print(f"unknown --sandbox-host {host!r}; --sandbox-hosts lists them",
              file=sys.stderr)
        return 1

    # The token is the part the server has to echo for anything to be
    # attributable to this payload.  A payload with no call syntax gets its own
    # text, which is what a real reflection would carry.
    token = getattr(args, "sandbox_token", "") or _default_token(payload)
    print(f"payload: {payload}")
    print(f"token  : {token!r}\n")
    header = "  {:<16s}".format("context") + "".join(
        f"{s[:11]:>12s}" for s in sinks)
    print(header)
    print("  " + "-" * (len(header) - 2))
    interesting = []
    for h in hosts:
        row = f"  {h:<16s}"
        for sink in sinks:
            html = sandbox.HOSTS[h].replace("__P__", payload)
            v = sandbox.judge(html, token, sink=sink)
            if getattr(args, "sandbox_roundtrip", False) and v.state != "live":
                r = sandbox.judge_roundtrip(html, token, sink=sink)
                if r.state == "live":
                    v = r
            row += f"{_CELL.get(v.state + ('A' if v.activation else ''), '?'):>12s}"
            if v.state == "live" or v.state == "unknown":
                interesting.append((h, sink, v))
        print(row)
    print("\n  " + "  ".join(f"{k}={v}" for k, v in sorted(_CELL.items())))
    if interesting:
        print("\nwhy:")
        for h, sink, v in interesting:
            gate = " (needs user activation)" if v.activation else ""
            print(f"  {h}/{sink}{gate}\n      {v.reason}")
            if v.evidence:
                print(f"      {v.evidence[:200]}")
    else:
        print("\nno context executed this payload. Either it does not escape the "
              "containers above, or the token never reaches an attribute value.")
    return 0


def _default_token(payload: str) -> str:
    """The payload's own observable marker: the argument of its first call."""
    import re as _re
    m = _re.search(r"(?:alert|prompt|confirm|eval|fetch|document\.\w+)\s*\("
                   r"\s*([^)]{1,40})", payload, _re.I)
    if m:
        return m.group(1).strip("'\"` ") or payload[:24]
    return payload[:24]


def _print_verdict(label: str, v) -> None:
    gate = "  requires user activation" if v.activation else ""
    print(f"  {label:<24s} {v.state.upper():9s} {v.reason}{gate}")
    if v.evidence:
        print(f"  {'':<24s} evidence: {v.evidence[:220]}")


_CELL = {"live": "LIVE", "liveA": "LIVE*", "inert": "inert", "unknown": "?"}


def _run_marker_fuzz(args) -> int:
    """Phase 80: --fuzz-body marker injection (DalFox FUZZ style).

    ``--fuzz-body`` accepts an inline template or ``@file``; every
    occurrence of ``--fuzz-marker`` (default FUZZ) is replaced with each
    payload from the built-in HTML corpus (strided sample of
    --fuzz-max).  Confirmed executions and bare reflections are printed;
    exit code 0 either way (findings are informational, not a gate).
    """
    from .core.marker_fuzz import fuzz_marker, fuzz_summary
    from .core import payloads as payloads_mod

    if not getattr(args, "url", None):
        print("--fuzz-body requires -u <target url>", file=sys.stderr)
        return 1
    body = args.fuzz_body
    if body.startswith("@"):
        path = body[1:]
        if not os.path.isfile(path):
            print(f"fuzz body file not found: {path}", file=sys.stderr)
            return 1
        with open(path, "r", encoding="utf-8") as fh:
            body = fh.read()
    marker = getattr(args, "fuzz_marker", None) or "FUZZ"
    if marker not in body:
        print(f"marker {marker!r} not found in --fuzz-body",
              file=sys.stderr)
        return 1

    method = getattr(args, "method", "POST") or "POST"
    pool = (payloads_mod.by_context("html_element")
            + payloads_mod.by_context("svg_context")
            + payloads_mod.by_context("event_handler"))
    poly = payloads_mod.polyglots_for("html_element")
    candidates = ([p["payload"] for p in pool]
                  + [p.get("payload", "") for p in poly])
    candidates = [c for c in candidates if c]
    max_n = int(getattr(args, "fuzz_max", 20) or 20)
    step = max(1, len(candidates) // max_n)
    chosen = candidates[::step][:max_n]

    requester = Requester(
        timeout=getattr(args, "timeout", 15),
        proxy=getattr(args, "proxy", None),
        headers={}, cookies={},
        verify_ssl=getattr(args, "verify_ssl", True),
        rate_limit=getattr(args, "rate_limit", 0))

    print(f"[*] marker-fuzz {args.url} with {len(chosen)} payloads "
          f"(marker={marker!r}, method={method})")
    results = fuzz_marker(requester, args.url, method, body, marker,
                          chosen, headers=None,
                          params=getattr(args, "params", None) or None)
    s = fuzz_summary(results)
    print(f"[+] {s['total']} payloads sent: "
          f"{s['confirmed']} confirmed, {s['reflected_only']} "
          f"reflected-only")
    for r in results:
        if r["confirmed"]:
            print(f"    [CONFIRMED] {r['payload']}")
        elif r["reflected"]:
            print(f"    [reflected] {r['payload']}")
    return 0


def _run_self_test():
    """Start the local vuln server and run the full self-test suite.

    This launches ``tests/vuln_server.py`` as a subprocess, waits for it
    to be ready, then runs ``tests/run_self_test.py`` and reports the
    result.  Used by ``--self-test`` for one-command validation of every
    detection layer without needing to manually start the server.
    """
    import time


    here = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(here, "..", "tests", "vuln_server.py")
    test_path = os.path.join(here, "..", "tests", "run_self_test.py")
    server_path = os.path.normpath(server_path)
    test_path = os.path.normpath(test_path)

    if not os.path.isfile(server_path):
        _log.error("vuln_server.py not found at %s", server_path)
        return 1
    if not os.path.isfile(test_path):
        _log.error("run_self_test.py not found at %s", test_path)
        return 1

    print("[*] Starting local vuln test server on port 8899 ...")
    server_proc = subprocess.Popen(
        [sys.executable, server_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for the server to be ready (max 10 seconds).
    ready = False
    for _ in range(20):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 8899, timeout=1)
            conn.request("GET", "/safe?q=ping")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.5)

    if not ready:
        server_proc.terminate()
        _log.error("Vuln server did not start within 10 seconds")
        return 1

    print("[+] Vuln server ready. Running self-test suite ...\n")
    # Phase 73: bound the self-test run.  On a degraded-loopback host the
    # full suite can hang forever (intermittently killed connections make
    # layer probes block); without a timeout, --self-test never returns and
    # the operator cannot tell "still running" from "wedged".
    timeout = int(os.environ.get("XSSentinel_SELFTEST_TIMEOUT", "900"))
    try:
        result = subprocess.run(
            [sys.executable, test_path],
            capture_output=False, timeout=timeout)
        return result.returncode
    except subprocess.TimeoutExpired:
        print(f"[!] self-test exceeded {timeout}s and was terminated.  "
              "On a host that kills loopback connections this is expected "
              "-- run the per-file pytest suites instead (they retry and "
              "skip individually), e.g.:  python -m pytest tests/test_pipeline.py",
              file=sys.stderr)
        return 2
    finally:
        # Phase 25-2: guard the server shutdown so a slow-to-die child
        # process cannot raise subprocess.TimeoutExpired and mask the
        # actual test result we just obtained above.
        try:
            server_proc.terminate()
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # terminate() didn't take effect within 5s -- force kill.
            try:
                server_proc.kill()
                server_proc.wait(timeout=2)
            except Exception:
                pass
        except Exception:
            # Best-effort cleanup; never let teardown mask the test result.
            pass


def _run_serve(args):
    """Start the REST API server (Phase 27-4 microservice mode)."""
    from .api.server import run_stdio
    return run_stdio(
        host=args.host, port=args.port,
        api_key=args.api_key, verbose=args.verbose,
        max_jobs=args.max_jobs, use_flask=args.use_flask,
        db_path=args.db_path,
        webhook_urls=args.webhook_urls or None,
        webhook_secret=args.webhook_secret,
    )


def _run_verify_fix(args):
    """Replay findings from a historical JSON report and emit a verify report.

    Loads each finding, re-sends the original payload against the original
    (url, method, param), and reports whether the vulnerability is fixed,
    still exploitable, or inconclusive.
    """
    from .core import verify_fix as vf

    src = args.verify_fix
    if not os.path.isfile(src):
        _log.error("Report file not found: %s", src)
        return 2

    try:
        findings = vf.load_findings(src)
    except Exception as e:
        _log.error("Failed to load report '%s': %s", src, e)
        return 2

    if not findings:
        _log.error("No findings found in '%s'.", src)
        return 2

    # Try to read the original target from the report envelope.
    target = None
    try:
        with open(src, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            target = raw.get("target")
    except Exception:
        pass

    print(f"[*] Loaded {len(findings)} finding(s) from {src}")
    print(f"[*] Re-verifying each finding (replays original payload) ...")

    # Build a requester with the user's HTTP options.
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

    requester = Requester(timeout=args.timeout, proxy=args.proxy,
                          headers=headers or None, cookies=cookies or None,
                          verify_ssl=not args.no_verify_ssl,
                          rate_limit=args.rate_limit)

    # Pre-scan login (the target may require auth to reach the endpoint).
    from .cli_runner import _do_login
    _do_login(requester, args)

    results = vf.verify_findings(findings, requester, verbose=args.verbose)
    s = vf.summarize(results)
    c = s["counts"]

    print(f"\n[+] Verification complete:")
    print(f"    Fixed:            {c['fixed']}")
    print(f"    Still vulnerable: {c['still_vuln']}")
    print(f"    Error:            {c['error']}")
    print(f"    Skipped:          {c['skipped']}")

    # Write the output report.
    out_path = args.output or "verify_fix.html"
    fmt = args.format if args.format in ("html", "json") else "html"
    if fmt == "json":
        out = vf.build_json(results, src, target)
        if not out_path.endswith(".json"):
            out_path += ".json"
    else:
        out = vf.build_html(results, src, target)
        if not out_path.endswith(".html"):
            out_path += ".html"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"\n[+] Verify-fix report written to: {out_path}")

    # Exit non-zero if any finding is still vulnerable (CI gate).
    if c["still_vuln"] > 0:
        print(f"\n[!] {c['still_vuln']} finding(s) still exploitable -- "
              f"exiting with code 1.")
        return 1
    return 0


def _run_diff(args):
    """Compare two JSON scan reports and emit a diff report.

    Loads baseline and current findings, computes the diff (new / fixed /
    regressed / unchanged / improved), and writes an HTML or JSON diff
    report.  CI verdict: FAIL (exit 1) if any new or regressed findings.
    """
    from .core import diff_report as dr

    baseline_path, current_path = args.diff
    for p in (baseline_path, current_path):
        if not os.path.isfile(p):
            _log.error("Report file not found: %s", p)
            return 2

    try:
        baseline = dr.load_report(baseline_path)
        current = dr.load_report(current_path)
    except Exception as e:
        _log.error("Failed to load reports: %s", e)
        return 2

    print(f"[*] Baseline: {len(baseline)} finding(s) from {baseline_path}")
    print(f"[*] Current:  {len(current)} finding(s) from {current_path}")

    diff = dr.diff_findings(baseline, current)
    s = diff["summary"]

    print(f"\n[+] Diff summary:")
    print(f"    New:        {s['new']}")
    print(f"    Fixed:      {s['fixed']}")
    print(f"    Regressed:  {s['regressed']}")
    print(f"    Improved:   {s['improved']}")
    print(f"    Unchanged:  {s['unchanged']}")

    # Derive target label from the current report's target field.
    target = ""
    try:
        with open(current_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            target = raw.get("target") or ""
    except Exception:
        pass

    out_path = args.output or "diff_report.html"
    fmt = args.format if args.format in ("html", "json") else "html"
    if fmt == "json":
        out = dr.diff_report_json(baseline, current, target=target,
                                  baseline_label=baseline_path,
                                  current_label=current_path)
        if not out_path.endswith(".json"):
            out_path += ".json"
    else:
        out = dr.diff_report_html(baseline, current, target=target,
                                  baseline_label=baseline_path,
                                  current_label=current_path)
        if not out_path.endswith(".html"):
            out_path += ".html"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"\n[+] Diff report written to: {out_path}")

    # CI gate: fail if new or regressed findings.
    if s["new"] > 0 or s["regressed"] > 0:
        print(f"\n[!] CI verdict: FAIL -- {s['new']} new, "
              f"{s['regressed']} regressed finding(s).")
        return 1
    print(f"\n[+] CI verdict: PASS -- no new or regressed findings.")
    return 0


def _run_passive_proxy(args):
    """Phase 44: run as a passive HTTP proxy scanner (xray/w13scan-style).

    Browser traffic flows through the proxy; captured GET/POST endpoints are
    de-duplicated by signature and fed into the normal Scanner pipeline in a
    background worker.  Findings accumulate and a summary + JSON report are
    written on shutdown (Ctrl+C).

    HTTPS: blind CONNECT tunnel by default (no inspection).  Phase 50: with
    --mitm-ca, HTTPS is intercepted -- TLS is terminated with per-host certs
    signed by the local CA (auto-generated) and HTTPS params/cookies are
    captured exactly like HTTP.  The CA certificate (<ca>-cert.pem) must be
    installed in the browser trust store.
    """
    import threading
    import time

    from .core.passive_proxy import PassiveProxy, drain_captures
    from .core.scanner import Scanner
    from .core.scanner import Finding
    from .core.sqli import run_sqli_check
    from .core.retire_js import scan_html

    # This mode runs BEFORE the main() scan-policy/verify_ssl plumbing, so
    # fill the policy-managed args and SSL flag locally.
    from xssentinel.__main__ import apply_scan_policy
    apply_scan_policy(args)
    args.verify_ssl = not getattr(args, "no_verify_ssl", False)

    wl = None
    if getattr(args, "param_wordlist", None):
        from .core.param_miner import load_wordlist
        wl = load_wordlist(args.param_wordlist)

    # --validate-ssl is honoured through Requester's verify_ssl.
    requester = Requester(
        timeout=args.timeout, proxy=args.proxy,
        headers={}, cookies={},
        verify_ssl=args.verify_ssl, rate_limit=args.rate_limit)

    proxy = PassiveProxy(
        port=args.proxy_port, host=args.proxy_host,
        scope=args.scope, requester=requester,
        mitm_ca=getattr(args, "mitm_ca", None))

    scanner = Scanner(
        requester=requester, use_headless=args.headless,
        max_transforms=args.max_transforms, max_payloads=args.max_payloads,
        crawl=False, scope=args.scope, threads=args.threads,
        dom_engine=args.dom_engine, verbose=args.verbose,
        custom_payloads=(_load_custom_payloads(args)
                         if getattr(args, "custom_payloads", None) else None),
        crawl_engine=args.crawl_engine,
        scenario_file=getattr(args, "scenarios", None),
        param_wordlist=wl,
        xsleak_audit=getattr(args, "xsleak_audit", False))

    stop = threading.Event()

    def on_scan(method, url, params, data):
        # Fast checks piggyback on captured traffic.
        try:
            if getattr(args, "sqli_check", False):
                for f in run_sqli_check(
                        requester, url, method=method,
                        params=params, data=data):
                    scanner.findings.append(Finding(**f))
        except Exception:
            pass
        try:
            if getattr(args, "check_outdated_js", False):
                html = requester.get(url).text or ""
                for f in scan_html(html, base_url=url):
                    scanner.findings.append(Finding(**f))
        except Exception:
            pass

    worker = threading.Thread(
        target=drain_captures,
        args=(proxy, scanner, 1.0, stop, on_scan),
        daemon=True)
    proxy.start()
    worker.start()

    host, port = proxy.server_address
    print(f"\n[+] Passive proxy listening on {host}:{port}  "
          f"(scope={args.scope or '*'})")
    if proxy.mitm is not None:
        # Phase 50: interception is on -- tell the operator how to trust it.
        cert_only = proxy.mitm.cert_only_path
        print(f"[+] HTTPS interception ENABLED: install the CA certificate "
              f"into the browser/OS trust store")
        print(f"    {cert_only}")
        print(f"[+] (Out-of-scope hosts stay blind tunneled.)")
    else:
        print(f"[+] HTTPS: blind CONNECT tunnel (no interception). Add "
              f"--mitm-ca <ca>.pem to capture HTTPS traffic.")
    print(f"[+] Point your browser/system proxy here, then browse. "
          f"Ctrl+C to stop and write the report.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        proxy.stop()

    n = len(scanner.findings)
    mitm_n = proxy.stats.get("mitm", 0)
    print(f"\n[+] Captures: {proxy.stats['captures']} unique endpoints "
          f"({proxy.stats['requests']} requests, "
          f"{proxy.stats['skipped_dup']} dup-skipped, "
          f"{proxy.stats['tunnels']} HTTPS tunnels"
          + (f", {mitm_n} intercepted" if mitm_n else "") + ")")
    print(f"[+] Scans run: {proxy.stats['scans']}  Findings: {n}")

    if n == 0:
        print("[*] No findings captured. Nothing to report.")
        return 0

    out_path = args.output
    fmt = args.format or "html"
    # Phase 49: give the directory (nuclei) / xml (burp) formats honest
    # default names instead of an html-shaped fallback.
    if out_path is None:
        if fmt == "nuclei":
            out_path = "xssentinel-nuclei"
        elif fmt == "burp":
            out_path = "xssentinel-burp.xml"
        else:
            out_path = "passive_report.html"
    from .cli_runner import _write_report
    try:
        _write_report(scanner, "passive://proxy", out_path, fmt,
                      meta={"passive": True, "stats": proxy.stats})
        print(f"[+] Report written to: {out_path}")
    except Exception as e:
        _log.error("report write failed: %s", e)
        return 1
    return 0


def _load_custom_payloads(args):
    import os
    if not getattr(args, "custom_payloads", None) or not os.path.isfile(args.custom_payloads):
        return None
    with open(args.custom_payloads, "r", encoding="utf-8") as f:
        return [line.strip() for line in f
                if line.strip() and not line.startswith("#")]
