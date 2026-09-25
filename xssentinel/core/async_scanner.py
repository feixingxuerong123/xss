"""Async scanner using aiohttp.

A high-throughput async scanner that mirrors the full detection pipeline
of the synchronous Scanner.  Useful for large-scale audits (crawl depth
5+, hundreds of endpoints) where the sync ThreadPoolExecutor becomes
I/O-bound.

Phase 17 (this version) integrates ALL detection layers from the sync
scanner, not just L1 reflected:
  * L1 reflected + context-aware payloads (original)
  * L2 WAF detection + adaptive bypass chains (new)
  * L3 DOM static analysis (new)
  * L4 blind/OOB injection + auto-confirm (new)
  * L5 advanced layers: postMessage / prototype / SW / worker / redirect
      / framework / header / path / cookie / error / markdown (new)
  * L6 CSP analysis + JSONP + polyglot + mXSS + template (new)
  * L7 crawl with BFS (new)

Detection modules run in ``asyncio.to_thread`` so CPU-bound parsing
(BeautifulSoup, regex matching) does not block the event loop.  I/O
(requests) stays fully async via aiohttp.

Falls back gracefully if aiohttp is not installed: importing this module
won't fail, but ``scan()`` will report "aiohttp not available".
"""
from __future__ import annotations
import asyncio
import copy
import time
import secrets
from typing import Any, AsyncIterator
from urllib.parse import urlparse, urljoin, urlencode

from .scanner import Finding, json_leaf_paths, _set_json_leaf
from .findings import (EVIDENCE_BROWSER_EXECUTED, EVIDENCE_MODEL,
                       EVIDENCE_NO_BROWSER, EVIDENCE_OOB)
from .scanner_layers import AdvancedLayerMixin
from .scanner_crawl import CrawlMixin
from .requester import JsonBody, CountingRequester
from . import payloads as payloads_mod
from . import context as ctx
from . import layer_guard
from . import verifier
from . import waf as wafmod
from . import polyglot as poly_mod
from . import bypass as bypass_mod
# Phase 35: pre-encoding pipeline parity with the sync scanner (Phase 34).
from . import pre_encode as pre_mod
# Phase 37: reflection-profile + generator parity (sync Phases 31/32).
from . import reflection_profile as rp_mod
from . import generator as gen_mod
from . import cors_check as cors_mod   # Phase 54: sync CORS audit parity
from . import csp as csp_mod           # Phase 100: CSP nonce-leak parity
from . import dom_engine as dom_engine_mod  # Phase 65: DOM-dynamic parity
from . import xs_leaks as xsleak_mod   # Phase 54: sync XS-Leaks audit parity
# Phase 86: budget/circuit stops must be catchable by name at every layer --
# _throttle() raises them, and the generic ``except Exception`` handlers that
# surround every probe used to swallow them (see _probe_param).
from .budget import BudgetExhausted, CircuitOpen
from .findings import _DEFAULT_TRANSFORMS
from . import transform as transform_mod
from .logger import get_logger
from .parser_utils import bs_parser as _bs_parser
from .stealth import (marker as _stem_marker, HeaderRotator as _HeaderRotator, ProxyPool as _ProxyPool,
                      jitter_interval, load_proxies as _load_proxies)

_log = get_logger("async_scanner")

# JSONP callback parameter names probed by the async JSONP layer.  Kept
# at module level so it is created once instead of per-scan.
_JSONP_CALLBACK_NAMES = ("callback", "cb", "jsonp", "jsonpCallback",
                         "fn", "function", "handler")


class AsyncScanner:
    """Async XSS scanner with full detection pipeline.

    Construct with the same options as Scanner; call ``await scan(url, ...)``
    to get an async iterator of Finding objects.
    """

    def __init__(self, *, max_concurrent: int = 20,
                 per_host_delay: float = 0.0,
                 jitter: float = 0.0,
                 max_payloads: int = 14,
                 max_transforms: int = 8,
                 timeout: int = 15,
                 headers: dict | None = None,
                 cookies: dict | None = None,
                 proxy: str | None = None,
                 verify_ssl: bool = True,
                 verbose: bool = False,
                 crawl: bool = False,
                 crawl_depth: int = 2,
                 oob=None,
                 advanced_layers: bool = True,
                 dom_engine: str = "off",
                 waf_name: str | None = None,
                 rate_limit: float = 0.0,
                 max_requests: int | None = None,
                 max_requests_per_endpoint: int | None = None,
                 breaker_threshold: int = 0,
                 json_body: dict | None = None,
                 proxy_pool: list | None = None,
                 rotate_headers: bool = False,
                 jitter_ratio: float = 0.0,
                 xsleak_audit: bool = False,
                 upload_fields: list[str] | None = None,
                 auth_headers: dict | None = None,
                 auth_cookies: list | None = None,
                 auth_local_storage: dict | None = None):
        self.max_concurrent = max_concurrent
        self.per_host_delay = per_host_delay
        # Phase 93: default jitter 0.0 (was 0.1).  Unlike the sync engine,
        # where jitter is a RATIO of the rate-limit interval and therefore
        # costs nothing without --rate-limit, this is an ABSOLUTE
        # per-request sleep of jitter*(0.5+rand) seconds in _throttle().
        # With the 0.1 default every --async request waited 50-150ms that
        # sync did not: neg-escape-03 spent 22 of its 23s asleep
        # (cProfile: 0.33s of scanner work, 22.9s parked in
        # GetQueuedCompletionStatus), which is the entire async-vs-sync
        # throughput gap.  cli_runner never passed it, so the CLI had no
        # way to turn it off.  Pacing is opt-in now, exactly like sync.
        self.jitter = jitter
        # Phase 46 (pentest-readiness): --rate-limit previously never
        # reached this constructor (cli_runner bug) and async traffic had
        # no budget guard.  rate_limit = global max requests/sec;
        # max_requests / max_requests_per_endpoint stop the scan when spent.
        self.rate_limit = max(0.0, float(rate_limit or 0))
        self._min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0.0
        self._last_global_request = 0.0
        self._ep_counts: dict[str, int] = {}
        self.max_requests = max_requests if (max_requests is None or max_requests > 0) else None
        self.max_requests_per_endpoint = max_requests_per_endpoint \
            if (max_requests_per_endpoint is None or max_requests_per_endpoint > 0) else None
        # Phase 46: circuit breaker (0 = disabled).  Consecutive 5xx/429
        # responses within a 2-minute window trip it; _throttle() then
        # raises CircuitOpen so the scan stops hammering a dead target.
        self.breaker_threshold = max(0, int(breaker_threshold or 0))
        self._fail_times: list[float] = []
        self.budget_exhausted_reason: str | None = None
        # Phase 47: JSON-body carrier (async parity with the sync scanner).
        # When set, body params are the LEAF paths of this document
        # (dot/index notation, e.g. "user.name", "tags[0]") and every body
        # probe is sent as application/json -- the old async path only ever
        # sent form-encoded bodies, so JSON APIs -- the majority of modern
        # POST endpoints -- could not be tested in --async mode at all.
        self.json_body = json_body
        self.max_payloads = max_payloads
        self.max_transforms = max_transforms
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        # Phase 51 (async parity): rotate egress across a proxy pool
        # instead of one static proxy; dead relays are evicted.
        self.proxy_pool = _ProxyPool(_load_proxies(proxy_pool)) \
            if proxy_pool else None
        # Phase 51: per-request header rotation (async parity with the sync
        # Requester).  Headers are passed per call, so nothing is persisted.
        self.rotate_headers = bool(rotate_headers)
        self.header_rotator = _HeaderRotator(headers.get("User-Agent")) \
            if (rotate_headers and isinstance(headers, dict)) else None
        # Phase 51: jitter the GLOBAL pacing interval (a fixed cadence is a
        # WAF/SIEM fingerprint, same rationale as the sync path).
        self.jitter_ratio = max(0.0, min(1.0, float(jitter_ratio or 0.0)))
        # Phase 54: XS-Leaks surface audit parity with the sync Scanner
        # (opt-in; OFF keeps async scans byte-for-byte as before).
        self.xsleak_audit = bool(xsleak_audit)
        # Phase 150: authenticated session state for the real-browser DOM
        # layer (see sync Scanner for the full rationale).
        self.auth_headers: dict = dict(auth_headers or {})
        self.auth_cookies: list = list(auth_cookies or [])
        self.auth_local_storage: dict = dict(auth_local_storage or {})
        # Phase 58: multipart upload-filename probing parity (sync Phase 48).
        self.upload_fields: list[str] = list(upload_fields or [])
        # Phase 64: blind OOB state -- sync parity (pending injections are
        # attributed per param and collected in batch at the end of scan()).
        self._oob_pending: list = []
        self._oob_started = False
        self.oob_timeout = 12
        self.oob_keep_listening = False
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.crawl_depth = crawl_depth
        self.oob = oob
        self.advanced_layers = advanced_layers
        self.dom_engine = dom_engine
        self.waf_name = waf_name
        self.requests_made = 0
        self.findings: list[Finding] = []
        self._semaphore: asyncio.Semaphore | None = None
        self._last_request_time: dict[str, float] = {}
        # py3.9: asyncio.Lock() binds whatever loop is current at
        # construction.  Built HERE it would either raise (host thread
        # without a loop: pytest, --serve, library embedding) or -- if
        # this code first installed a loop of its own -- bind to a loop
        # the caller's asyncio.run() never uses, which turns a clean
        # error into a HANG.  So: create it lazily, inside the loop that
        # is actually running us.
        self._lock: asyncio.Lock | None = None
        self._aiohttp_available = self._check_aiohttp()

    def _get_lock(self) -> asyncio.Lock:
        """The scan-wide lock, created inside the running loop.

        See __init__: constructing it eagerly bound it to whatever loop
        happened to be current (or raised in a host thread), and a lock
        bound to a dead loop hangs every ``async with`` on it.
        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _next_proxy(self) -> str | None:
        """Next proxy from the pool, or the static --proxy."""
        if self.proxy_pool is None:
            return self.proxy
        p = self.proxy_pool.next()
        return p if p is not None else self.proxy

    def _req_headers(self, headers: dict | None = None) -> dict:
        """Per-request headers: rotated browser bundle + caller overrides."""
        base = dict(headers or {})
        if self.header_rotator is not None:
            merged = self.header_rotator.next_headers()
            merged.update(base)          # caller wins
            return merged
        return base

    @staticmethod
    def _check_aiohttp() -> bool:
        try:
            import aiohttp  # noqa: F401
            return True
        except ImportError:
            return False

    async def scan(self, url: str, method: str = "GET",
                   params: dict | None = None,
                   data: dict | None = None) -> AsyncIterator[Finding]:
        """Scan a single URL asynchronously. Yields Finding objects.

        Raises RuntimeError if aiohttp is not installed.
        """
        if not self._aiohttp_available:
            raise RuntimeError(
                "aiohttp is not installed. Install with: pip install aiohttp"
            )
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

        import aiohttp

        params = params or {}
        data = data or {}

        # Phase 142: hidden-parameter mining used to run HERE, before the
        # baseline.  It is the most request-hungry step in the scan, so at a
        # small --max-requests it spent the whole cap before the baseline was
        # even attempted, `_throttle` then rejected the baseline, and the
        # scan exited without ever building `page_tasks`.  The miner does not
        # read the baseline response, so it now runs right after it -- still
        # before the page tasks, which is all the ordering it ever needed.

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=50)
        # Phase 86: a budget/circuit stop is NOT a scan failure -- it is a
        # deliberate early stop.  Capture it, log it once, and still emit the
        # findings collected before the cap was hit (sync parity: scanner.py
        # catches the same pair in scan_target and keeps its findings).
        stop: BaseException | None = None
        try:
            async with aiohttp.ClientSession(timeout=timeout,
                                             connector=connector,
                                             cookies=self.cookies) as session:
                # 1) Baseline: get the page for reflection + DOM + advanced.
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        # Phase 47: JSON-carrier baseline -- a POST baseline
                        # in JSON mode must carry the document (as
                        # application/json) or the reflected text used for
                        # DOM/context analysis is a misleading empty/error
                        # body.
                        _dkw = _body_kwargs(
                            JsonBody(dict(self.json_body))
                            if (self.json_body is not None
                                and method.upper() != "GET")
                            else data)
                        async with session.request(
                            method, url, params=params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(), **_dkw,
                        ) as resp:
                            text = await resp.text()
                            status = getattr(resp, "status", 200)
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(status)
                except (BudgetExhausted, CircuitOpen):
                    raise          # Phase 86: stop the scan, never "retry"
                except Exception as e:
                    _log.warning("async baseline error: %s", e,
                                 exc_info=self.verbose)
                    return

                # 2) Hidden-parameter mining (Phase 133 sync parity, moved
                #    after the baseline by Phase 142 -- see the note above).
                #    Sync enriches the endpoint's params before probing it;
                #    without this, an endpoint whose interesting parameter has
                #    no UI hint was only probed with the params already in the
                #    URL (sync TP / async FN on pos-pmmine-01).  Discoveries
                #    override existing names, matching sync's
                #    ``{**ep_params, **extra_params}`` merge.  It stays ahead
                #    of the page tasks so the L1 probes see the new names.
                if self.advanced_layers:
                    _extra = await self._mine_hidden_params_async(url, method,
                                                                  params, data)
                    if _extra:
                        params = {**params, **_extra}

                # 3) L2 WAF detection (runs in thread -- CPU light but sync API).
                waf_info = None
                try:
                    waf_info = await asyncio.to_thread(
                        wafmod.detect, _FakeResp(text, status, resp_headers))
                    if waf_info.get("waf"):
                        self.waf_name = waf_info["waf"]
                        _log.info("async WAF detected: %s", self.waf_name)
                except Exception as e:
                    _log.debug("async WAF detect error: %s", e)

                # 3) Launch page-level detection layers in parallel.
                #    Each runs in a thread to avoid blocking the event loop.
                #    Phase 94: (name, agen) pairs so an isolated failure can
                #    be attributed to the layer that raised it.
                page_tasks = []

                # L1 reflected: per-param probe (original async behavior).
                page_tasks.append(("L1_reflected", self._scan_reflected(
                    session, url, method, params, data, text)))

                # L3 DOM static analysis.
                # Phase 176t: pass method+params.  The real-browser pass reads
                # the page, so it must be pointed at a URL that carries the
                # user-controlled query -- sync re-attaches them for exactly
                # this reason (scanner.py:479-486).  Async keeps `url` and
                # `params` apart internally, so handing the browser the bare
                # url showed it an empty location.search and made every
                # source-read DOM vector structurally unconfirmable
                # (measured: pos-dom-02 async FN / sync TP).
                if self.advanced_layers:
                    page_tasks.append(("L3_dom", self._scan_dom_async(
                        url, text, method, params)))

                # L5 advanced page layers (postMessage / prototype / SW / etc).
                # Phase 87: pass the endpoint params -- run_page_layers uses
                # them for user-controlled reflection sub-layers (import map,
                # CSSI, dangling markup); the old call left them at None so
                # those sub-layers saw no params in async mode.
                if self.advanced_layers:
                    page_tasks.append(("L5_advanced_page", self._scan_advanced_page(
                        url, text, params)))

                # Phase 87: L8 request-injection layers (header / path /
                # cookie / error-page XSS).  Async mode never called
                # run_request_layers, so these four carrier classes went
                # completely untested in --async scans.
                if self.advanced_layers:
                    page_tasks.append(("L8_request", self._scan_request_layers(
                        url, method, params, data)))

                # L6 CSP analysis.
                if self.advanced_layers:
                    page_tasks.append(("L6_csp", self._scan_csp_async(
                        url, resp_headers)))

                # L6 JSONP callback detection.
                if self.advanced_layers:
                    page_tasks.append(("L6_jsonp", self._scan_jsonp_async(
                        url, method, params, data)))

                # Phase 54: sync parity -- L7 CORS origin-reflection audit and
                # the opt-in XS-Leaks surface audit.
                if self.advanced_layers:
                    page_tasks.append(("L7_cors", self._scan_cors_async(
                        session, url, method)))
                if self.advanced_layers and self.xsleak_audit:
                    page_tasks.append(("L7_xsleaks", self._scan_xsleak_audit_async(
                        url, resp_headers)))

                # Phase 58/63: multipart upload-filename probing parity (sync
                # Phase 48) -- body-carrying endpoints without a JSON carrier
                # (POST, plus PUT/PATCH RESTful uploads), matching the sync
                # trigger.
                if self.advanced_layers and self.upload_fields \
                        and method.upper() in ("POST", "PUT", "PATCH") \
                        and self.json_body is None:
                    self._upload_method = method.upper()
                    page_tasks.append(("L9_upload", self._probe_upload_async(
                        session, url, params, data)))

                # L4 blind/OOB injection (if listener configured).
                if self.oob:
                    page_tasks.append(("L4_blind", self._inject_blind_async(
                        session, url, method, params, data)))

                # Stream findings as they complete.  NOTE (Phase 43 fix): the
                # old code passed async generators to asyncio.as_completed(),
                # which requires awaitables -- async generators are NOT
                # awaitables, so every scan() raised TypeError here (silently
                # swallowed upstream, leaving async mode with zero findings).
                # Drain via tasks instead: layers stay concurrent, per-layer
                # exceptions stay isolated, and results come back in
                # completion order.
                sink: list = []
                drain_tasks = [asyncio.create_task(
                                   _drain_agen(g, sink, name=name))
                               for name, g in page_tasks]
                if drain_tasks:
                    # Phase 86: gather with return_exceptions so one layer's
                    # budget stop does not orphan its siblings (plain gather
                    # re-raises immediately and leaves the rest running), then
                    # re-raise the stop AFTER the findings already collected
                    # in ``sink`` have been emitted below.
                    results = await asyncio.gather(*drain_tasks,
                                                   return_exceptions=True)
                    stop = next((r for r in results
                                 if isinstance(r, (BudgetExhausted,
                                                   CircuitOpen))), None)
                for finding in sink:
                    await self._add_finding(finding)
                    yield finding
                if stop is not None:
                    raise stop

                # 4) Optional crawl: discover more endpoints and scan them.
                if self.crawl:
                    async for finding in self._crawl_and_scan(session, url, text):
                        await self._add_finding(finding)
                        yield finding
        except (BudgetExhausted, CircuitOpen) as e:
            # Phase 86: graceful early stop (sync parity: scanner.py logs and
            # keeps its findings).  Findings already yielded above stay with
            # the caller; the pending OOB poll below still runs because a
            # callback is proof of execution we must not throw away.
            stop = e

        if stop is not None:
            self._log_budget_stop(stop)
        # 5) L4 blind: batch-collect OOB callbacks after ALL injections
        # (sync collect_oob parity).  Only callbacks become findings.
        if self.oob and self._oob_pending:
            async for finding in self.collect_oob_async():
                await self._add_finding(finding)
                yield finding

    async def _scan_reflected(self, session, url: str, method: str,
                              params: dict, data: dict,
                              baseline_text: str
                              ) -> AsyncIterator[Finding]:
        """L1 reflected XSS: probe each parameter with context-aware payloads."""
        # Phase 47: JSON-carrier mode -- body params are the LEAF paths of
        # the document (sync scan_endpoint parity), so nested API bodies get
        # full payload coverage in async mode too.  The old code only ever
        # probed top-level ``data`` keys, so {user:{name:..}} endpoints were
        # scanned against zero body params.
        if self.json_body is not None:
            param_items = [(p, False) for p in params] + \
                          [(path, True)
                           for path in json_leaf_paths(self.json_body)]
        else:
            param_items = [(p, False) for p in params] + \
                          [(p, True) for p in data]
        # Phase 43 fix: _probe_param returns async GENERATORS, which
        # asyncio.as_completed() rejects (not awaitables) -- the whole L1
        # layer silently produced nothing under scan().  Drain via tasks.
        sink: list = []
        tasks = []
        for param, is_body in param_items:
            tasks.append(asyncio.create_task(_drain_agen(
                self._probe_param(session, url, method, param, params, data,
                                  is_body, baseline_text), sink,
                name=f"L1_param:{param}")))
        stop = None
        if tasks:
            # Phase 86: return_exceptions so one param's budget stop does not
            # orphan its siblings; the stop is re-raised (below) only after
            # the findings collected so far have been yielded.
            results = await asyncio.gather(*tasks, return_exceptions=True)
            stop = next((r for r in results
                         if isinstance(r, (BudgetExhausted, CircuitOpen))),
                        None)
        for finding in sink:
            yield finding
        if stop is not None:
            raise stop

    async def _probe_param(self, session, url: str, method: str,
                           param: str, params: dict, data: dict,
                           is_body: bool, baseline_text: str
                           ) -> AsyncIterator[Finding]:
        """Probe a single parameter for XSS. Yields findings."""
        stem = _stem_marker("xssentinel_async_")
        marker = f"{stem}{param}_{secrets.token_hex(2)}"
        probe_params, probe_data = self._probe_kv(
            params, data, param, marker, is_body)
        try:
            async with self._semaphore:
                await self._throttle(url)
                async with session.request(
                    method, url, params=probe_params or None,
                    headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                    **_body_kwargs(probe_data),
                ) as resp:
                    text = await resp.text()
                    # Phase 100: keep this response's headers AND body --
                    # the CSP nonce-leak exploit (sync _try_csp_nonce
                    # parity) runs on the marker-reflection response.  The
                    # loop below overwrites ``text`` on every variant, so
                    # without this snapshot the exploit inspects the LAST
                    # payload's response, where the marker (and thus the
                    # nonce-proximity check) is gone.
                    probe_headers = dict(getattr(resp, "headers", None) or {})
                    probe_text = text
                    self.requests_made += 1
                    self._record_status(getattr(resp, "status", 200))
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: never treated as "this param failed"
        except Exception:
            return
        if marker not in text:
            return

        # Classify context (CPU-bound) -- run in thread.
        # `ctx.classify` never existed: this call raised AttributeError on every
        # parameter and the bare `except` swallowed it, so the async engine
        # selected payloads from "html_element" ALWAYS -- the url_href / cdata /
        # css sibling corpora were never consulted, which is why it could spend
        # 104 requests and still miss pos-url-04 and pos-cdata-01 that sync
        # confirms with 59.  Now uses the same function sync uses, with NO
        # swallow: a broken wiring must surface as a failed layer, not as a
        # silently degraded scan (`core/layer_guard.py` exists because this
        # pattern hid the async L1 outage in Phase 63).
        # Phase 177: classify EVERY reflection point (sync parity via the
        # same shared analyzer) -- the first byte-stream occurrence is
        # frequently an inert comment/nav highlight while the live sink
        # comes later; picking by execution priority is the whole fix.
        # Single-reflection pages keep exactly the old answer.
        _sel = await asyncio.to_thread(ctx.analyze_all, text, marker)
        context = _sel["context"]
        _extra_contexts = [c for c in _sel["contexts"] if c != context][:2]

        # Phase 93: escaped-reflection convergence (sync parity).  When the
        # marker reflects but the input around it is HTML-encoded, the
        # server is doing context-aware output encoding and almost every
        # payload variant will be encoded too.  The sync engine has shrunk
        # its budget for this case since Phase 27-1 (3 payloads x 2
        # transforms instead of max_payloads x max_transforms); async had
        # no equivalent, so once the Phase 91/92 verifier stopped
        # wrongly confirming those reflections the async path paid the
        # whole 168-request budget -- neg-escape-03 went from ~2s to ~23s.
        marker_escaped = await asyncio.to_thread(
            ctx.is_marker_escaped, text, marker)

        # Phase 35: structured-param pre-encoding (parity with the sync
        # scanner).  Container values (base64/JWT/JSON) never see raw
        # payloads -- fire container-wrapped probes first; a hit ends the
        # param, a miss falls through to the plain-text loop.
        orig_value = (data.get(param) if is_body else params.get(param)) or ""
        enc_struct = pre_mod.detect_structure(orig_value)
        if enc_struct != "none":
            async for f in self._try_pre_encoded_async(
                    session, url, method, param, params, data, is_body,
                    orig_value, enc_struct, context, marker):
                yield f
            return

        # Build payload candidates (CPU-bound) -- run in thread.
        # Phase 43: multi-corpus cross-context sampling (sync _scan_param
        # parity) -- primary corpus stride-sample + sibling corpora +
        # polyglots.  The old single-corpus slice missed payloads like the
        # recursive <sscriptcript> strip (neg-filter-01 FN).
        # Phase 93: on an escaped reflection the sync engine drops the
        # candidate budget to 2 (``primary_budget``) and only fires 3 of
        # them -- a small probe set that still catches double-encoding
        # bugs and attribute-context escapes without burning 168 requests
        # on a param that is almost certainly safe.
        cand_budget = 3 if marker_escaped else self.max_payloads
        try:
            cands = await asyncio.to_thread(
                payloads_mod.cross_context_candidates, context,
                cand_budget)
        except Exception:
            cands = payloads_mod.for_context("html_element")[:cand_budget]
        # Phase 177: multi-reflection parity with sync -- append a small
        # slice for each additional reflection context after the primary
        # queue; the payload-loop budget decides whether they ever fire.
        if _extra_contexts:
            _seen = set(cands)
            for _xc in _extra_contexts:
                for p in payloads_mod.for_context(_xc):
                    if p not in _seen:
                        _seen.add(p)
                        cands.append(p)

        # Phase 37: reflection profile + generative payloads (sync parity).
        # One sandwich probe reveals surviving characters; payloads whose
        # critical characters are gone move to the back, and payloads built
        # ONLY from surviving characters lead the queue (dedup'd).
        # Phase 93: skipped on an escaped reflection, like the sync
        # `_prioritize_bases` does -- the sandwich probe costs a request and
        # generative payloads cannot help when the encoder eats them.
        prof = None
        if not marker_escaped:
            try:
                ptok = "xssap_" + secrets.token_hex(3)
                pval = rp_mod.build_probe(ptok)
                sp, sd = self._probe_kv(params, data, param, pval, is_body)
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=sp or None,
                        headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                        **_body_kwargs(sd),
                    ) as resp2:
                        ptext = await resp2.text()
                        self.requests_made += 1
                        self._record_status(getattr(resp2, "status", 200))
                prof = await asyncio.to_thread(rp_mod.profile_reflection,
                                               ptext, ptok)
            except (BudgetExhausted, CircuitOpen):
                raise  # Phase 86: the sandwich probe was stopped on purpose
            except Exception:
                prof = None
            if prof is not None and not prof.get("full_reflection"):
                try:
                    cands = await asyncio.to_thread(rp_mod.prioritize_payloads,
                                                    prof, cands)
                except Exception:
                    pass
                try:
                    gen_pls = await asyncio.to_thread(gen_mod.generate, prof,
                                                      context)
                    gen_strs = [g["payload"] for g in gen_pls]
                    known = set(cands)
                    cands = [g for g in gen_strs if g not in known] + cands
                except Exception:
                    pass
                # Phase 95: profile-backed escape convergence (sync parity).
                # ``is_marker_escaped`` cannot fire for a plain alphanumeric
                # marker echoed inside an element body (its neighbours are
                # the page's own structural characters, never encoded), so
                # escaped endpoints paid the full budget.  When the sandwich
                # probe proves every breakout-critical character comes back
                # encoded, converge to the small probe set.  Must run BEFORE
                # the WAF-bypass prepend below so the capped path stays clean.
                try:
                    converged = await asyncio.to_thread(
                        rp_mod.profile_says_encoded, prof, context)
                except Exception:
                    converged = False
                if converged:
                    marker_escaped = True
                    del cands[3:]

        # Phase 96: RCDATA breakout surfacing (sync parity).  When the
        # sandwich marker reflected inside <textarea>/<title>/<xmp>,
        # direct injections are inert while the closing-tag breakout is
        # the one vector that fires on raw echo.  Deliberately OUTSIDE
        # the ``not full_reflection`` branch: a raw-echoing RCDATA
        # endpoint keeps EVERY probed character (full reflection), yet
        # the breakout is exactly what must be tried there.  Only on the
        # non-converged path -- an escaping encoder mangles the closing
        # tag exactly like any other markup, so the breakout is dead
        # weight there and must not re-widen the converged list.  Runs
        # BEFORE the WAF-bypass prepend: on a raw-echoing RCDATA endpoint
        # the breakout outranks everything else.
        if prof is not None and not marker_escaped:
            try:
                cands, _rcd_tag = await asyncio.to_thread(
                    rp_mod.surface_rcdata_breakout_strs, prof, cands)
            except Exception:
                _rcd_tag = None
            if _rcd_tag:
                _log.debug(
                    f"[rcdata] reflection inside <{_rcd_tag}> -> "
                    "breakout variants lead the queue")

        # If WAF detected, prepend WAF-specific bypass chains.
        # Phase 93: not on an escaped reflection -- sync bounds these by
        # the small transform cap instead, and generative bypass bases
        # cannot help when the encoder eats their special characters.
        if self.waf_name and not marker_escaped:
            try:
                bypass_chains = await asyncio.to_thread(
                    bypass_mod.chains_for_waf, self.waf_name)
                bypass_payloads = [base for _, base, _, _ in bypass_chains[:3]]
                cands = bypass_payloads + cands
            except Exception:
                pass

        # Phase 132: ``return`` on the first confirmed payload used to end
        # ``_probe_param`` outright, so the position shift, the CSP-nonce
        # exploit AND the L7 parameter layers were all skipped on exactly
        # the endpoints that were easiest to confirm -- async reported the
        # reflected hit and nothing else (13 requests vs sync's 45 on
        # pos-clobber-01, where sync also reports dom_clobber).  Sync breaks
        # out of its loop and keeps going (scanner.py:667 gates the loop on
        # ``not confirmed`` and reaches _run_advanced_layers unconditionally),
        # so this mirrors that: flag + break, later stages gated on the flag.
        param_confirmed = False
        for payload in cands:
            if param_confirmed:
                break
            marked = verifier.mark(payload, marker)
            # Phase 86: WAF/filter evasion parity with the sync _try_payload.
            # Until now the async path fired only the bare marked payload plus
            # one polyglot, so every evasion variant the sync engine tries
            # (mixed case, entity/percent encoding, comment breaks, ...) was
            # never sent -- self.max_transforms was stored but unused, which
            # left async with a large false-negative gap on filtered targets.
            variants = await asyncio.to_thread(
                self._build_variants, marked, context, marker,
                2 if marker_escaped else None)
            try:
                # Polyglot probe for unknown contexts.
                poly = poly_mod.build_polyglot(marker)
                if not any(v == poly for _, v in variants):
                    variants.append((["polyglot"], poly))
            except Exception:
                pass

            for tchain, variant in variants:
                send_params, send_data = self._probe_kv(
                    params, data, param, variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            text = await resp.text()
                            # Phase 43: capture headers for the verifier's
                            # CSP gate (sync parity) -- without them the
                            # CSP-blocks-inline check is skipped and strict
                            # CSP endpoints false-positive.  Defensive
                            # getattr: fake sessions in tests may omit
                            # headers entirely.
                            resp_headers = dict(getattr(resp, "headers", None) or {})
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next variant"
                except Exception:
                    continue
                # Verify execution (CPU-bound) -- run in thread.
                v = await asyncio.to_thread(verifier.verify_semantic,
                                            text, marker,
                                            response_headers=resp_headers)
                # Phase 165 (sync parity, scanner._try_payload): the token
                # survived -- did the PAYLOAD?  Keep looking otherwise.
                if v["confirmed"] and verifier.payload_survived(text, variant):
                    yield Finding(
                        url=url, method=method, param=param,
                        context=v.get("context") or context,
                        payload=variant,
                        severity="high",
                        evidence=text[max(0, text.find(marker)-30):
                                      text.find(marker)+len(marker)+30],
                        type="reflected",
                        confidence="high",
                        transform=tchain,
                        # Phase 164 (sync parity, scanner._record): record
                        # WHERE the payload rode so the PoC replays the same
                        # carrier instead of guessing it from the method.
                        param_in="body" if is_body else "query",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    param_confirmed = True
                    break  # leave the variant loop; outer loop re-checks

            # Phase 166 (sync parity, scanner._try_payload:1112): the plain
            # stamp confirmed nothing for THIS payload.  A keyword filter
            # rewrites a LITERAL callable (``alert(`` -> ``blocked(``) while
            # letting the concatenated form through, so retry with the CONCAT
            # stamp -- bounded to two requests, exactly like sync pays them
            # per base payload.  This used to exist only inside the
            # position-shift block below, which requires a WAF *fingerprint*;
            # a WAF-less keyword filter never gets there (neg-filter-05:
            # sync confirms via the concat stamp, async paid 106 requests
            # and reported nothing).
            # Skipped when the marker came back HTML-escaped: the encoder
            # eats the concat variant just as dead as the plain one, and the
            # Phase 27-1 convergence budget must not grow by 2/payload
            # (test_async_escaped_convergence pins that ceiling).
            if not param_confirmed and not marker_escaped:
                concat_marked = verifier.mark(payload, marker, style="concat")
                if concat_marked != marked:
                    concat_retry: list = [([], concat_marked)]
                    for tchain, _v in variants[:1]:
                        v2 = concat_marked
                        for t in tchain:
                            v2 = await asyncio.to_thread(transform_mod.apply,
                                                         t, v2)
                        concat_retry.append(
                            (list(tchain) + ["concat_stamp"], v2))
                    for tchain, variant in concat_retry:
                        if marker not in variant:
                            continue
                        send_params, send_data = self._probe_kv(
                            params, data, param, variant, is_body)
                        try:
                            async with self._semaphore:
                                await self._throttle(url)
                                async with session.request(
                                    method, url, params=send_params or None,
                                    headers=self._req_headers(self.headers),
                                    proxy=self._next_proxy(),
                                    **_body_kwargs(send_data),
                                ) as resp:
                                    text = await resp.text()
                                    resp_headers = dict(getattr(
                                        resp, "headers", None) or {})
                                    self.requests_made += 1
                                    self._record_status(
                                        getattr(resp, "status", 200))
                        except (BudgetExhausted, CircuitOpen):
                            raise
                        except Exception:
                            continue
                        v = await asyncio.to_thread(
                            verifier.verify_semantic, text, marker,
                            response_headers=resp_headers)
                        if (v["confirmed"]
                                and verifier.payload_survived(text, variant)):
                            idx = text.find(marker)
                            param_confirmed = True
                            yield Finding(
                                url=url, method=method, param=param,
                                context=v.get("context") or context,
                                payload=variant,
                                severity="high",
                                evidence=text[max(0, idx - 30):
                                              idx + len(marker) + 30],
                                type="reflected",
                                confidence="high",
                                transform=tchain,
                                param_in="body" if is_body else "query",
                                evidence_class=EVIDENCE_MODEL,
                            )
                            break

        # Phase 37: parameter position shift (sync parity).  WAFs often
        # guard only the ORIGINAL parameter location -- re-fire the top
        # payloads with the param cloned into the OTHER location.
        # Phase 132: gated on ``not param_confirmed`` -- sync's call site
        # (scanner.py:693) has the same guard, and re-firing after a
        # confirmed hit would only add requests.
        if not param_confirmed:
            for payload in cands[:3]:
                marked = verifier.mark(payload, marker)
                # Phase 47: flipped is_body routes through _probe_kv so a
                # JSON-mode query->body shift lands in the JSON document
                # instead of a form body the server ignores.
                sp, sd = self._probe_kv(params, data, param, marked,
                                        not is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=sp or None,
                            headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                            **_body_kwargs(sd),
                        ) as resp:
                            text = await resp.text()
                            resp_headers = dict(getattr(resp, "headers", None) or {})  # CSP gate parity
                            self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise            # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                v = await asyncio.to_thread(verifier.verify_semantic,
                                            text, marker,
                                            response_headers=resp_headers)
                if (v["confirmed"]
                        and verifier.payload_survived(text, marked)):
                    idx = text.find(marker)
                    yield Finding(
                        url=url, method=method, param=param,
                        context=v.get("context") or context,
                        payload=marked,
                        severity="high",
                        evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                        type="reflected",
                        confidence="high",
                        transform=["position_shift"],
                        # Phase 164: the shift re-fires the parameter into the
                        # OTHER location, so the carrier here is the FLIPPED
                        # one -- exactly the value the PoC needs.
                        param_in="query" if is_body else "body",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    param_confirmed = True
                    break

            # Phase 166 (sync parity, scanner._try_payload): the plain stamp
            # confirmed nothing.  A keyword filter rewrites a LITERAL callable
            # while letting the concatenated form through, so retry with the
            # CONCAT stamp -- the only form that survives such a filter AND can
            # carry the marker.  Bounded to two requests, reached only when
            # everything above failed.
            if not param_confirmed:
                concat_marked = verifier.mark(payload, marker, style="concat")
                retry: list = [([], concat_marked)]
                for tchain, _v in variants[:1]:
                    v2 = concat_marked
                    for t in tchain:
                        v2 = await asyncio.to_thread(transform_mod.apply, t, v2)
                    retry.append((list(tchain) + ["concat_stamp"], v2))
                for tchain, variant in retry:
                    if marker not in variant:
                        continue
                    send_params, send_data = self._probe_kv(
                        params, data, param, variant, is_body)
                    try:
                        async with self._semaphore:
                            await self._throttle(url)
                            async with session.request(
                                method, url, params=send_params or None,
                                headers=self._req_headers(self.headers),
                                proxy=self._next_proxy(),
                                **_body_kwargs(send_data),
                            ) as resp:
                                text = await resp.text()
                                resp_headers = dict(
                                    getattr(resp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(resp, "status", 200))
                    except (BudgetExhausted, CircuitOpen):
                        raise
                    except Exception:
                        continue
                    v = await asyncio.to_thread(verifier.verify_semantic,
                                                text, marker,
                                                response_headers=resp_headers)
                    if (v["confirmed"]
                            and verifier.payload_survived(text, variant)):
                        idx = text.find(marker)
                        param_confirmed = True
                        yield Finding(
                            url=url, method=method, param=param,
                            context=v.get("context") or context,
                            payload=variant,
                            severity="high",
                            evidence=text[max(0, idx - 30):
                                          idx + len(marker) + 30],
                            type="reflected",
                            confidence="high",
                            transform=tchain,
                            param_in="body" if is_body else "query",
                            evidence_class=EVIDENCE_MODEL,
                        )
                        break

        # Phase 100: CSP nonce-leak exploitation (sync _try_csp_nonce
        # parity).  A nonce CSP blocks plain inline payloads, so the loop
        # above ends unconfirmed -- but when the nonce itself is echoed
        # into the page (the classic "nonce in a template/JSON blob" leak)
        # a script carrying the REAL nonce executes.  The async path had no
        # equivalent, so --async silently missed every nonce-leak endpoint
        # that sync reported (pos-csp-01: sync TP, async FN).
        #
        # The verifier allowlists the nonce against the response's own CSP
        # header, so a server that rotates nonces per request still cannot
        # be falsely confirmed.
        csp_hdr = ""
        try:
            csp_hdr = probe_headers.get("Content-Security-Policy") or ""
        except Exception:
            csp_hdr = ""
        # Phase 132: also gated on ``not param_confirmed`` -- sync's nonce
        # step (scanner.py:656) carries the same guard, and the block is
        # only reached on an unconfirmed param anyway.
        if not param_confirmed and csp_hdr:
            try:
                _nonces = csp_mod.extract_nonces_from_csp(csp_hdr)
            except Exception:
                _nonces = []
            if _nonces:
                try:
                    _near = csp_mod.detect_nonce_near_marker(
                        csp_hdr, probe_text or text or "", marker)
                except Exception:
                    _near = {}
                if _near.get("nonce_exposed_near_marker"):
                    _n = _near.get("nonce_value") or _nonces[0]
                    _ntok = "xssv_" + secrets.token_hex(4)
                    _npay = (f"<script nonce='{_n}'>"
                             f"alert('{_ntok}')</script>")
                    _nparams, _ndata = self._probe_kv(
                        params, data, param, _npay, is_body)
                    try:
                        async with self._semaphore:
                            await self._throttle(url)
                            async with session.request(
                                method, url, params=_nparams or None,
                                headers=self._req_headers(self.headers),
                                proxy=self._next_proxy(),
                                **_body_kwargs(_ndata),
                            ) as nresp:
                                _ntext = await nresp.text()
                                _nhdrs = dict(
                                    getattr(nresp, "headers", None) or {})
                                self.requests_made += 1
                                self._record_status(
                                    getattr(nresp, "status", 200))
                    except (BudgetExhausted, CircuitOpen):
                        raise
                    except Exception:
                        _ntext = ""
                        _nhdrs = {}
                    if _ntext:
                        _nv = await asyncio.to_thread(
                            verifier.verify_semantic, _ntext, _ntok,
                            response_headers=_nhdrs)
                        if (_nv.get("confirmed") and
                                verifier.payload_survived(_ntext, _npay)):
                            _idx = _ntext.find(_ntok)
                            yield Finding(
                                url=url, method=method, param=param,
                                context=_nv.get("context") or context,
                                payload=_npay,
                                severity="high",
                                evidence=_ntext[max(0, _idx - 30):
                                                _idx + len(_ntok) + 30],
                                type="reflected",
                                confidence="high",
                                transform=["csp_nonce"],
                                param_in="body" if is_body else "query",
                                evidence_class=EVIDENCE_MODEL,
                            )

        # Phase 132: L7 parameter layers (mutation / DOM clobber / template
        # / polyglot / markdown).  Sync reaches these at the end of
        # ``_scan_param``; async stopped after the CSP-nonce block, so the
        # whole family was async-only FN.  Reached only when the marker
        # actually reflected, matching the sync call site.
        async for _f in self._scan_advanced_param_layers(
                url, method, params, data, param, is_body, marker,
                probe_text or text or ""):
            yield _f

        # Phase 176s: time-based (OOB) fallback -- sync parity with
        # scanner.py:1122.  The marker reflected but nothing confirmed, so
        # a strict CSP is the prime suspect; resource-fetch payloads prove
        # the markup was parsed as HTML even when inline script is blocked.
        # Reached only when this param produced no confirmed finding, and
        # only with an OOB listener configured (same guards as sync).
        if self.oob and self.advanced_layers and not param_confirmed:
            async for _f in self._scan_time_based(url, method, params, data,
                                                  param, is_body):
                yield _f

    def _build_variants(self, marked: str, context: str, marker: str,
                        cap_override: int | None = None
                        ) -> list[tuple[list[str], str]]:
        """Phase 86: build the WAF/filter evasion variants of ``marked``.

        Mirror of the sync ``Scanner._try_payload`` variant ladder (the
        async path previously had none, so ``max_transforms`` was dead
        config).  Same sources, same order, same cap:

          1. the static ``_DEFAULT_TRANSFORMS`` ladder (base first);
          2. context-aware mutations from ctx_mutation (Phase 13b);
          3. multi-encoding chains (Phase 13c) -- WAF detected only;
          4. WAF-specific bypass chains (Phase 29-2) -- WAF detected only.

        The token stays inside ``marked``: transforms are applied to the
        whole MARKED payload exactly like the sync engine does, so the
        verifier can still attribute the hit to this param.  Duplicate
        variants are dropped -- they cost a request and can prove nothing.

        Phase 93: ``cap_override`` reproduces the sync
        ``max_transforms_override=2`` for escaped reflections.
        """
        cap = max(1, int(cap_override or self.max_transforms or 1))
        variants: list[tuple[list[str], str]] = []

        def _add(chain, variant):
            if len(variants) >= cap:
                return
            if variant and not any(v == variant for _, v in variants):
                variants.append((chain, variant))

        # Source 1: static transform ladder (always, cheapest first).
        for tset in _DEFAULT_TRANSFORMS[:cap]:
            variant = marked
            for t in tset:
                variant = transform_mod.apply(t, variant)
            _add(list(tset), variant)

        # Source 2: context-aware mutations (Phase 13b parity).
        if len(variants) < cap:
            try:
                from . import ctx_mutation as ctx_mut
                for chain, variant in ctx_mut.mutate_for_context(
                        marked, context,
                        max_variants=max(4, cap - len(variants))):
                    if len(variants) >= cap:
                        break
                    _add(chain, variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async ctx_mutation error: %s", e)

        waf = self.waf_name
        if waf and len(variants) < cap:
            # Source 3: multi-encoding chains (Phase 13c parity).
            try:
                from . import multi_encode as me_mod
                for name, steps, variant in me_mod.all_chain_variants(
                        marked, context, waf,
                        max_variants=max(2, cap - len(variants))):
                    if len(variants) >= cap:
                        break
                    _add([f"me:{name}"], variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async multi_encode error: %s", e)
            # Source 4: WAF-specific bypass chains (Phase 29-2 parity).
            try:
                for _waf, base, chain, _why in bypass_mod.chains_for_waf(waf):
                    if len(variants) >= cap:
                        break
                    try:
                        variant = bypass_mod.apply_chain(
                            verifier.mark(base, marker), chain)
                    except Exception:
                        variant = base
                    _add([f"bp:{waf}"], variant)
            except Exception as e:
                if self.verbose:
                    _log.debug("    [!] async bypass_chain error: %s", e)

        return variants

    async def _try_pre_encoded_async(self, session, url, method, param,
                                     params, data, is_body, orig_value,
                                     struct, context, marker
                                     ) -> AsyncIterator[Finding]:
        """Phase 35: container-encoded probes (base64/JWT/JSON), parity
        with the sync scanner's _try_pre_encoded (Phase 34).  The base
        payload is token-marked first, then re-wrapped into the container
        the original value used; no transform chains -- the container
        encoding IS the transformation."""
        for base in pre_mod.PRE_ENCODE_BASES:
            marked = verifier.mark(base, marker)
            enc = await asyncio.to_thread(
                pre_mod.encode_payload, orig_value, struct, marked)
            if not enc:
                continue
            send_params, send_data = self._probe_kv(
                params, data, param, enc, is_body)
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with session.request(
                        method, url, params=send_params or None,
                        headers=self._req_headers(self.headers), proxy=self._next_proxy(),
                        **_body_kwargs(send_data),
                    ) as resp:
                        text = await resp.text()
                        resp_headers = dict(getattr(resp, "headers", None) or {})  # CSP gate parity
                        self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise            # Phase 86: stop instead of "next base"
            except Exception:
                continue
            v = await asyncio.to_thread(verifier.verify_semantic,
                                        text, marker,
                                        response_headers=resp_headers)
            if v["confirmed"] and verifier.payload_survived(text, enc):
                idx = text.find(marker)
                yield Finding(
                    url=url, method=method, param=param,
                    context=v.get("context") or context,
                    payload=enc,
                    severity="high",
                    evidence=text[max(0, idx - 30):idx + len(marker) + 30],
                    type="reflected",
                    confidence="high",
                    transform=[f"pre_encode:{struct}"],
                    param_in="body" if is_body else "query",
                    evidence_class=EVIDENCE_MODEL,
                )
                return

    def _resolve_dom_engine(self):
        """Phase 65: mirror the sync _resolve_dom_engine for L6 parity."""
        de = self.dom_engine
        if de == "static":
            return None
        if de == "auto" and not dom_engine_mod.DynamicDomAnalyzer.available():
            return None
        try:
            return dom_engine_mod.DynamicDomAnalyzer(
                auth_headers=self.auth_headers,
                auth_cookies=self.auth_cookies,
                auth_local_storage=self.auth_local_storage)
        except Exception:
            return None

    async def _scan_dom_async(self, url: str, page_text: str,
                              method: str = "GET",
                              params: dict | None = None
                              ) -> AsyncIterator[Finding]:
        """L3 static + L6 real-browser DOM layer -- sync _scan_dom parity.

        Phase 65 fixes two divergences from the sync layer: the static
        analysis was invoked with the URL as the ``is_html`` flag (an
        accidental truthy pass-through that broke for empty URLs), and the
        real-browser dynamic confirmation (dom_dynamic) never ran in async
        mode at all.

        Phase 176t adds the third one, and it is the kind that cannot be
        spotted from a finding count: the browser was navigated to ``url``,
        which in async does NOT contain the endpoint's query string (the
        engine keeps ``url`` and ``params`` apart -- see _scan_reflected).
        So ``location.search`` was empty at read time, and every DOM vector
        whose source is the query string was structurally unconfirmable --
        reported as a clean page, not as a degraded scan.  Sync already
        re-attaches params before this call (scanner.py:479-486); the guard
        below is copied from there, including the GET-only condition.
        """
        try:
            from . import dom as dom_mod
            static_results = await asyncio.to_thread(
                dom_mod.analyze, page_text, is_html=True)
            engine = await asyncio.to_thread(self._resolve_dom_engine)
            dyn_findings: list = []
            # Phase 154 (sync parity, scanner_layers.py): page_has_client_js
            # alone lets pages with JS but no possible sink pay for a whole
            # browser session; page_can_run_sink keeps every external-script
            # page (SPA bundles) so this only skips provably dead passes.
            # Phase 159: that function is "is the page provably inert?", not
            # "did we recognise a sink" -- the whitelist version silently
            # disabled browser verification for unlisted sinks (srcdoc).
            # Keep both call sites identical: this is a sync/async parity pair.
            if engine is not None and await asyncio.to_thread(
                    lambda t: (dom_engine_mod.page_has_client_js(t)
                               and dom_engine_mod.page_can_run_sink(t)),
                    page_text):
                page_url = url
                if method == "GET" and params:
                    try:
                        qs = urlencode(params)
                        if qs:
                            page_url = url + ("&" if "?" in url
                                              else "?") + qs
                    except Exception:
                        pass
                dyn_findings = await asyncio.to_thread(engine.analyze,
                                                       page_url)

            dyn_sinks: set = set()
            for d in dyn_findings:
                s = (d.get("sink") or "").lower()
                dyn_sinks.add(s)
                dyn_sinks.add(s.split(".")[-1])

            def _suppressed(r) -> bool:
                hay = ((r.get("type") or "") + " " + (r.get("context") or "")
                       + " " + (r.get("detail") or "")).lower()
                if not hay:
                    return False
                return any(s and s in hay for s in dyn_sinks)

            for r in static_results:
                if _suppressed(r):
                    continue  # confirmed dynamically; dynamic finding covers it
                yield Finding(
                    url=url, method="GET", param=None,
                    context=r.get("type"),
                    payload=r.get("snippet", ""),
                    severity="medium" if r.get("confidence") == "medium"
                    else "low",
                    confidence=r.get("confidence", "low"),
                    detail=r.get("detail", ""),
                    type="dom",
                    evidence_class=EVIDENCE_NO_BROWSER,
                )
            for d in dyn_findings:
                yield Finding(
                    url=url, method="GET", param=None,
                    context=d.get("sink"),
                    payload=d.get("snippet", ""),
                    severity="high",
                    confidence=d.get("confidence", "high"),
                    detail=d.get("detail", ""),
                    type="dom_dynamic",
                    headless={"available": True, "confirmed": True,
                              "outcome": "fired",
                              "detail": "marker executed in real browser sink"},
                    proof=d.get("snippet", ""),
                    evidence_class=EVIDENCE_BROWSER_EXECUTED,
                )
        except Exception as e:
            _log.warning("async DOM layer error: %s", e, exc_info=self.verbose)

    async def _scan_advanced_page(self, url: str, page_text: str,
                                  params: dict | None = None
                                  ) -> AsyncIterator[Finding]:
        """L5 advanced page-level layers (postMessage / prototype / SW / etc).

        Delegates to the sync ``advanced_layers.run_page_layers`` in a
        thread, then streams any findings produced.

        Phase 87: forward the endpoint params -- import map / CSSI /
        dangling markup sub-layers use them to detect user-controlled
        reflection; the old call left them at None (sync parity:
        scanner.py passes ``params=params``).

        Phase 176s: pass a REAL requester instead of ``None``.  Several page
        layers need a follow-up GET -- most visibly cookie tossing, which
        reads the ``Set-Cookie`` response headers (``layers/content_layers.py``
        does ``req.get(url)`` then ``resp.raw.headers.getlist``).  With
        ``req=None`` that call raised AttributeError, the layer's own
        ``except Exception: pass`` swallowed it, and the layer went on with
        an empty header list -- so it could never report the one thing it
        exists to report.  The shim's old comment called this "degrades
        gracefully"; it degrades *silently*, which is how the gap survived
        until a benchmark case (pos-ctoss-01) measured it.
        """
        try:
            from . import advanced_layers
            # Create a lightweight sync scanner shim to collect findings.
            shim = _AsyncScannerShim(self)
            # CountingRequester, not the bare requester: some sub-layers bump
            # the scanner themselves and some do not, and either way the
            # traffic has to land in the scan's request accounting instead of
            # sailing past it (Phase 142).
            shim.req = CountingRequester(self._get_sync_requester(),
                                         shim._bump)
            await asyncio.to_thread(
                advanced_layers.run_page_layers, shim, shim.req, url,
                page_text, params=params)
            self.requests_made += shim.requests_made
            for f in shim._findings:
                yield f
        except Exception as e:
            _log.warning("async advanced page layers error: %s", e, exc_info=self.verbose)

    async def _scan_time_based(self, url: str, method: str, params: dict,
                               data: dict, param: str, is_body: bool
                               ) -> AsyncIterator[Finding]:
        """Phase 176s: time-based (OOB resource-fetch) fallback.

        Sync reaches this at the end of ``_scan_param`` (scanner.py:1122):
        the marker reflected, every standard payload failed to confirm, so a
        strict CSP is the prime suspect.  ``<style>@import</style>`` /
        ``<img src>`` / onerror-fetch payloads make the browser fetch a
        resource whether or not inline script is allowed, and the OOB
        listener turns that fetch into proof of execution.

        Async never had this step at all.  It matters precisely because it
        is the ONLY thing that fires on a CSP-locked endpoint -- without it
        those are silent false negatives, not degraded detections.
        """
        shim = None
        try:
            from . import time_xss as tx_mod
            shim = _AsyncScannerShim(self)
            # Same requester wiring as the other thread-offloaded sync
            # layers: a real one, wrapped so its traffic is counted.
            shim.req = CountingRequester(self._get_sync_requester(),
                                         shim._bump)
            await asyncio.to_thread(
                tx_mod.scan_time_based, shim, shim.req, url, method,
                params, data, param, is_body)
            self.requests_made += shim.requests_made
            for f in shim._findings:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # a budget stop is not a layer bug
        except Exception as e:
            # Same failed-row rule as _scan_request_layers above: silence
            # here reads as "this param had no CSP fallback", not "it died".
            if shim is not None:
                shim.coverage.record_layer(
                    url, "L7_time_based", status="failed",
                    detail=f"{type(e).__name__}: {str(e)[:140]}")
            _log.warning("async time-based fallback error: %s", e,
                         exc_info=self.verbose)

    async def _scan_request_layers(self, url: str, method: str,
                                   params: dict, data: dict
                                   ) -> AsyncIterator[Finding]:
        """L8 request-injection layers (header / path / cookie / error XSS).

        Phase 87: async mode never called
        ``advanced_layers.run_request_layers``, so four whole XSS carrier
        classes (User-Agent/Referer/XFF header injection, URL path segment
        XSS, cookie value XSS, error page XSS) were never tested in
        --async scans -- an entire layer of missed findings.  Mirror the
        sync scan_endpoint wiring: run the sync layer in a thread against
        a real sync Requester (the transport layers issue blocking
        ``requests`` calls), then stream the shim's findings.

        Budget/circuit semantics (Phase 86): a BudgetExhausted /
        CircuitOpen raised inside the thread is a deliberate scan stop,
        not a layer bug -- it propagates (through _drain_agen) like every
        other layer instead of being swallowed.
        """
        shim = None
        try:
            from . import advanced_layers
            shim = _AsyncScannerShim(self)
            req = self._get_sync_requester()
            await asyncio.to_thread(
                advanced_layers.run_request_layers,
                shim, req, url, method, params, data)
            # Coverage visibility: the shim's NullCoverage only records in
            # memory, but tests/debugging inspect shim.coverage.touched to
            # prove the L8 request layers ran -- which is exactly why the
            # touch happens AFTER the call now.  Recorded before it, an
            # entry-time failure still left "L8_request: touched" behind, so
            # the introspection that exists to catch a silently dead layer was
            # itself fooled by one.  (sync: scanner.py L7_time_based, same
            # fix, same reason.)
            shim.coverage.touch_layer(url, "L8_request", method,
                                      "async request-injection layers")
            for f in shim._findings:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: a budget/circuit stop is NOT a layer bug
        except Exception as e:
            # Phase 176u: a swallowed failure must leave a failed row, not
            # silence -- "no row" reads as "this endpoint had no such layer",
            # which is exactly how a dead layer stayed invisible.  shim is
            # None precisely when the failure was on entry (bad import /
            # constructor), which is the case this row exists to reveal.
            if shim is not None:
                shim.coverage.record_layer(
                    url, "L8_request", status="failed",
                    detail=f"{type(e).__name__}: {str(e)[:140]}")
            _log.warning("async request layers error: %s", e,
                         exc_info=self.verbose)

    async def _scan_advanced_param_layers(self, url: str, method: str,
                                          params: dict, data: dict,
                                          param: str, is_body: bool,
                                          marker: str,
                                          resp_text: str
                                          ) -> AsyncIterator[Finding]:
        """L7 parameter layers (mutation / DOM clobber / template /
        polyglot / markdown).

        Phase 132: ``--async`` never ran these.  ``_probe_param`` did the
        payload loop, the position shift and the CSP-nonce exploit, then
        stopped -- so five whole detection families (mutation XSS, DOM
        clobbering, client-side template injection, polyglot, and the
        markdown/BBCode markup layers) were reported by sync and silently
        missed by async.

        These sub-layers issue blocking ``requests`` calls, so this mirrors
        ``_scan_request_layers``: a real sync Requester plus the
        ``AdvancedLayerMixin``-backed shim, run in a worker thread, with
        the shim's findings streamed back.

        Unlike the payload loop this is a *step* the sync engine always
        takes once the marker reflected -- even when the reflection is
        HTML-escaped.  It is deliberately NOT gated on ``marker_escaped``
        so the two engines stay in step (see scanner.py ``_scan_param``,
        which reaches ``_run_advanced_layers`` unconditionally).
        """
        shim = _AsyncScannerShim(self)
        try:
            req = self._get_sync_requester()
            shim.req = req
            await asyncio.to_thread(
                shim._run_advanced_layers,
                req, url, method, params, data, param, is_body, marker,
                resp_text)
            # The sub-layers bump the shim's own counter; fold it in so the
            # scan's request accounting stays honest.
            self.requests_made += shim.requests_made
            for f in shim._findings:
                yield f
        except (BudgetExhausted, CircuitOpen):
            raise        # a budget/circuit stop is NOT a layer bug
        except Exception as e:
            _log.warning("async advanced param layers error: %s", e,
                         exc_info=self.verbose)

    async def _mine_hidden_params_async(self, url: str, method: str,
                                        params: dict, data: dict) -> dict:
        """Phase 133: hidden-parameter mining (sync parity).

        Sync merges ``param_miner``'s discoveries into the endpoint's
        params *before* probing it (scanner.py:302-324).  Async never had
        an equivalent, so an endpoint whose interesting parameter has no
        UI hint was only ever probed with the parameters already in the
        URL -- benchmark case pos-pmmine-01 was a clean sync TP / async FN
        (sync 46 requests, async 10).

        ``param_miner`` issues blocking requests, so this runs the sync
        miner in a worker thread against the shared sync Requester.

        BAV is deliberately NOT enabled here: the CLI documents ``--bav`` as
        sync-only, and half-implementing it would be worse than not
        claiming it.
        """
        shim = _AsyncScannerShim(self)
        try:
            # Counting proxy: the miner never bumps a counter itself, so
            # without this its ~N probe requests would not show up at all.
            shim.req = CountingRequester(self._get_sync_requester(),
                                     shim._bump)
            found = await asyncio.to_thread(
                shim._mine_hidden_params, url, method, params, data, False)
            self.requests_made += shim.requests_made
            return dict(found or {})
        except (BudgetExhausted, CircuitOpen) as e:
            # Phase 142: a budget stop while mining must NOT abort the scan.
            # The page tasks created afterwards include layers that cost no
            # requests at all (L6 CSP header analysis, L3 DOM static), and
            # re-raising here meant they never ran -- a bypassable CSP went
            # unreported purely because the miner had spent the cap first.
            # Record the reason and fall through; the request-driven layers
            # still raise on their own through _throttle, which propagates
            # out of _drain_agen exactly as before.
            _log.debug("async hidden-param mining stopped early: %s", e)
            return {}
        except Exception as e:
            _log.warning("async hidden-param mining error: %s", e,
                         exc_info=self.verbose)
            return {}

    def _get_sync_requester(self):
        """Lazily-built sync Requester for thread-offloaded sync layers.

        The transport layers (header/path/cookie/error XSS) need a
        blocking ``requests`` client.  The async scanner has none -- the
        shim's ``req`` is None and those layers' own try/except used to
        degrade to no-ops.  Build one sharing the scan's timeout / headers
        / cookies / proxy / TLS / rate-limit settings, once per scan.
        """
        req = getattr(self, "_sync_requester", None)
        if req is None:
            from .requester import Requester
            req = Requester(
                timeout=self.timeout,
                proxy=self._next_proxy(),
                headers=dict(self.headers),
                cookies=dict(self.cookies),
                verify_ssl=self.verify_ssl,
                rate_limit=self.rate_limit,
                jitter=self.jitter_ratio,
            )
            self._sync_requester = req
        return req

    async def _scan_csp_async(self, url: str, resp_headers: dict
                              ) -> AsyncIterator[Finding]:
        """L6 CSP analysis (runs in thread) -- sync _scan_csp parity.

        Phase 62: the previous version treated the CSPReport OBJECT returned
        by csp_mod.analyze as a dict (results.get('bypassable')), so every
        async scan logged a TypeError and async mode NEVER reported a
        bypassable CSP.  Mirror the sync layer: read report.bypassable /
        report.weak and emit the same medium csp_bypass finding.
        """
        try:
            from . import csp as csp_mod
            # Run CSP analysis in a thread.
            report = await asyncio.to_thread(
                csp_mod.analyze,
                resp_headers.get("Content-Security-Policy", ""))
            if not report.bypassable:
                return
            best = await asyncio.to_thread(
                csp_mod.best_bypass,
                resp_headers.get("Content-Security-Policy", "")) or {}
            yield Finding(
                url=url, method="GET", param="(header)",
                context="csp_header",
                payload=best.get("payload", ""),
                severity="medium",
                evidence="; ".join(report.weak),
                type="csp_bypass",
                confidence="medium",
                csp_header=resp_headers.get("Content-Security-Policy", ""),
                bypass_type=best.get("type", ""),
                bypass_reason=best.get("reason", ""),
                evidence_class=EVIDENCE_NO_BROWSER,
            )
        except Exception as e:
            _log.warning("async CSP layer error: %s", e, exc_info=self.verbose)

    async def _scan_cors_async(self, session, url: str, method: str
                               ) -> AsyncIterator[Finding]:
        """Phase 54: CORS origin-reflection audit -- sync _scan_cors parity.

        One finding per origin (dedup set on the scanner), two cheap probes
        (GET with the attacker Origin, then an OPTIONS preflight when the
        GET did not reflect).  Runs whenever advanced_layers is on, exactly
        like the sync L7 CORS layer.
        """
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
        evil = cors_mod.EVIL_ORIGIN
        for probe_method, extra in cors_mod.PROBES:
            resp_headers = {}
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    headers = self._req_headers(self.headers)
                    headers.update(extra)
                    async with session.request(
                        probe_method, url, params=None, headers=headers,
                        proxy=self._next_proxy(),
                    ) as resp:
                        await resp.read()          # drain (headers enough)
                        resp_headers = dict(resp.headers)
                        self.requests_made += 1
                        self._record_status(getattr(resp, "status", 200))
            except (BudgetExhausted, CircuitOpen):
                raise        # Phase 86: stop instead of "next probe"
            except Exception:
                continue
            acao = resp_headers.get("Access-Control-Allow-Origin") or ""
            acac = resp_headers.get("Access-Control-Allow-Credentials") or ""
            verdict = cors_mod.classify(acao, acac, evil)
            if verdict is None:
                continue
            sev, reason = verdict
            evidence = (f"probe: {probe_method} {url}\n"
                        f"Origin: {evil}\n"
                        f"-> Access-Control-Allow-Origin: {acao or '(absent)'}\n"
                        f"-> Access-Control-Allow-Credentials: "
                        f"{acac or '(absent)'}")
            yield Finding(
                url=url, method=probe_method, param="", payload=evil,
                context="cors_header", severity=sev,
                type="cors_misconfig", confidence="firm",
                evidence=evidence, detail=reason,
                evidence_class=EVIDENCE_NO_BROWSER,
            )
            return  # one finding per origin is enough

    async def _scan_xsleak_audit_async(self, url: str, resp_headers: dict
                                       ) -> AsyncIterator[Finding]:
        """Phase 54: XS-Leaks surface audit -- sync _scan_xsleak_audit parity.

        Opt-in (self.xsleak_audit); reuses the baseline response headers
        already fetched by scan() (zero extra requests); one low
        xs_leak_surface finding per origin.
        """
        if not self.xsleak_audit:
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
            verdict = xsleak_mod.audit_mitigations(resp_headers or {})
        except Exception:
            return
        if verdict is None:
            return
        yield Finding(
            url=url, method="GET", param="", payload="",
            context=verdict.get("context", "response_headers"),
            severity=verdict.get("severity", "low"),
            type=verdict.get("type", "xs_leak_surface"),
            confidence=verdict.get("confidence", "firm"),
            evidence=verdict.get("evidence", ""),
            detail=verdict.get("detail", ""),
            evidence_class=EVIDENCE_NO_BROWSER,
        )

    async def _probe_upload_async(self, session, url: str, params: dict,
                                  data: dict) -> AsyncIterator[Finding]:
        """Phase 58: multipart upload-filename XSS probing -- sync
        upload_probe.probe_upload parity over aiohttp.

        Fires on POST scans when the operator named upload fields
        (upload_fields).  Weaponised filenames are uploaded for each field;
        an immediate filename echo in an executable context confirms
        upload_xss, otherwise a marker-bearing stored URL from the response
        is fetched once to confirm stored_upload.  Mirrors the sync logic
        candidate-for-candidate so the dual engines report the same.
        """
        from .upload_probe import _first_url_with, _name_candidates
        from urllib.parse import urljoin
        if not self.upload_fields:
            return
        for field in self.upload_fields:
            marker = f"{_stem_marker('xssup_')}{field}_{secrets.token_hex(2)}"
            for filename in _name_candidates(marker):
                text = ""
                resp_headers = {}
                try:
                    # Raw multipart body, NOT aiohttp.FormData: FormData
                    # percent-encodes the filename (%3Cimg...) and a server
                    # echoing the raw name then shows encoded markup that
                    # verify_semantic cannot confirm.  Mirror the sync
                    # requests wire instead: boundary is a bare token, the
                    # filename is verbatim except double quotes -> %22
                    # (urllib3 does the same), which is what the Phase-48
                    # sync probe sends.
                    boundary = secrets.token_hex(8)
                    safe_name = filename.replace('"', "%22")
                    body = (f"--{boundary}\r\n"
                            f'Content-Disposition: form-data; name="{field}"; '
                            f'filename="{safe_name}"\r\n'
                            "Content-Type: text/plain\r\n\r\n"
                            "xssentinel upload probe\r\n"
                            f"--{boundary}--\r\n").encode("utf-8")
                    hdrs = self._req_headers(self.headers)
                    hdrs["Content-Type"] = \
                        f"multipart/form-data; boundary={boundary}"
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            getattr(self, "_upload_method", "POST"), url,
                            params=params or None, data=body,
                            headers=hdrs, proxy=self._next_proxy(),
                        ) as resp:
                            text = await resp.text()
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next filename"
                except Exception:
                    continue
                if not text or marker not in text:
                    continue
                try:
                    v = await asyncio.to_thread(
                        verifier.verify_semantic, text, marker,
                        response_headers=resp_headers)
                except Exception:
                    v = {"confirmed": False}
                idx = text.find(marker)
                evidence = text[max(0, idx - 60):idx + len(marker) + 120] \
                    if idx >= 0 else ""
                if v.get("confirmed"):
                    yield Finding(
                        url=url, method="POST",
                        param=f"{field}[filename]",
                        type="upload_xss", context="multipart_filename",
                        payload=filename, severity="high", confidence="high",
                        detail=(v.get("detail") or "") +
                               " (filename echoed in upload response)",
                        evidence=evidence,
                        transform=["multipart_filename"],
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return  # one confirmed filename echo is enough
                stored_url = _first_url_with(text, marker)
                if not stored_url:
                    continue
                target = urljoin(url, stored_url)
                try:
                    async with self._semaphore:
                        await self._throttle(target)
                        async with session.get(
                            target, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as sresp:
                            stext = await sresp.text()
                            s_headers = dict(sresp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(sresp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next filename"
                except Exception:
                    continue
                if marker in stext:
                    try:
                        sv = await asyncio.to_thread(
                            verifier.verify_semantic, stext, marker,
                            response_headers=s_headers)
                    except Exception:
                        sv = {"confirmed": False}
                    if sv.get("confirmed"):
                        yield Finding(
                            url=target, method="GET",
                            param=f"{field}[filename]",
                            type="stored_upload", context="uploaded_file",
                            payload=filename, severity="high",
                            confidence="high",
                            detail=(sv.get("detail") or "") +
                                   f" (stored file {stored_url} served "
                                   "attacker markup)",
                            evidence=stext[max(0, stext.find(marker) - 60):
                                           stext.find(marker)
                                           + len(marker) + 120],
                            transform=["multipart_filename", "stored"],
                            evidence_class=EVIDENCE_MODEL,
                        )
                        return

            # Phase 90 (P2): filename vectors exhausted on this field --
            # probe weaponised file CONTENT (HTML/SVG whose handler fires
            # alert(marker)) served back at a stored URL.  Mirrors the
            # sync probe_upload_content one candidate at a time.
            from .upload_probe import _content_candidates as _cc
            cmarker = f"{_stem_marker('xssupc_')}{secrets.token_hex(2)}"
            for filename, content, mime in _cc(cmarker):
                text = ""
                resp_headers = {}
                try:
                    boundary = secrets.token_hex(8)
                    body = (f"--{boundary}\r\n"
                            f'Content-Disposition: form-data; name="{field}"; '
                            f'filename="{filename}"\r\n'
                            f"Content-Type: {mime}\r\n\r\n"
                            .encode("utf-8") + content +
                            f"\r\n--{boundary}--\r\n".encode("utf-8"))
                    hdrs = self._req_headers(self.headers)
                    hdrs["Content-Type"] = \
                        f"multipart/form-data; boundary={boundary}"
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            getattr(self, "_upload_method", "POST"), url,
                            params=params or None, data=body,
                            headers=hdrs, proxy=self._next_proxy(),
                        ) as resp:
                            text = await resp.text()
                            resp_headers = dict(resp.headers)
                            self.requests_made += 1
                            self._record_status(
                                getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next file"
                except Exception:
                    continue
                if not text or cmarker not in text:
                    continue
                stored_url = _first_url_with(text, cmarker)
                if not stored_url:
                    continue
                target = urljoin(url, stored_url)
                try:
                    async with self._semaphore:
                        await self._throttle(target)
                        async with session.get(
                            target, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as sresp:
                            stext = await sresp.text()
                            s_headers = dict(sresp.headers)
                            self.requests_made += 1
                            self._record_status(getattr(sresp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next file"
                except Exception:
                    continue
                if cmarker not in stext:
                    continue
                try:
                    sv = await asyncio.to_thread(
                        verifier.verify_semantic, stext, cmarker,
                        response_headers=s_headers)
                except Exception:
                    sv = {"confirmed": False}
                if sv.get("confirmed"):
                    yield Finding(
                        url=target, method="GET",
                        param=f"{field}[content]",
                        type="stored_upload",
                        context="uploaded_file_content",
                        payload=filename, severity="high",
                        confidence="high",
                        detail=(sv.get("detail") or "") +
                               f" (stored file {stored_url} serves weaponised "
                               "HTML/SVG content)",
                        evidence=stext[max(0, stext.find(cmarker) - 60):
                                       stext.find(cmarker)
                                       + len(cmarker) + 120],
                        transform=["uploaded_file_content", "stored"],
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return

    async def _scan_jsonp_async(self, url: str, method: str,
                                params: dict, data: dict
                                ) -> AsyncIterator[Finding]:
        """L6 JSONP callback XSS detection (fully async, no sync fallback).

        Phase 24-1: rewritten to use the aiohttp ClientSession directly
        instead of spinning up a synchronous Requester in a thread.
        The old implementation negated the async throughput advantage
        because each of the 7 callback-name probes blocked a thread on
        ``requests.request()``.
        """
        try:
            import aiohttp  # type: ignore
        except ImportError:
            return
        # Build a query string carrying the existing params so the JSONP
        # endpoint sees the same context the reflection layer saw.
        for cb_name in _JSONP_CALLBACK_NAMES:
            if cb_name in params or cb_name in data:
                continue  # already being tested by the reflection layer
            marker = f"xsjsonp_{secrets.token_hex(3)}"
            probe_params = dict(params)
            probe_params[cb_name] = marker
            try:
                async with self._semaphore:
                    await self._throttle(url)
                    async with aiohttp.ClientSession(
                        cookies=self.cookies, headers=self._req_headers(self.headers),
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as sess:
                        async with sess.get(
                            url, params=probe_params, proxy=self._next_proxy(),
                        ) as resp:
                            text = await resp.text()
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                if marker not in text:
                    continue
                # Reflection found -- check if it lands in a JS-executable
                # context (callback function position).  verify_semantic
                # is CPU-bound but fast; run inline.
                v = verifier.verify_semantic(text, marker,
                                             response_headers=dict(resp.headers))
                if v["confirmed"]:
                    yield Finding(
                        url=url, method="GET", param=cb_name,
                        context="jsonp_callback",
                        payload=marker,
                        severity="high",
                        evidence=f"JSONP callback reflection: {v['detail']}",
                        type="jsonp_xss",
                        confidence="high",
                        evidence_class=EVIDENCE_MODEL,
                    )
                    return  # one confirmed JSONP finding is enough
            except (BudgetExhausted, CircuitOpen):
                raise    # Phase 86: stop instead of "next callback name"
            except Exception as e:
                _log.debug("JSONP probe failed for %s: %s", cb_name, e)
                continue

    async def _inject_blind_async(self, session, url: str, method: str,
                                  params: dict, data: dict
                                  ) -> AsyncIterator[Finding]:
        """L4 blind XSS injection -- sync _inject_blind parity (Phase 64).

        The old async version fired a hardcoded payload at EVERY parameter
        unconditionally (no reflection gate -> wasted probes on escaped
        endpoints), used ONE token for the whole endpoint (callbacks could
        not be attributed to a parameter) and a stray "');fetch" fragment.
        It now mirrors the sync layer exactly:

        * one reflection probe per param -- the real OOB payload is only
          fired where an UNESCAPED executable tag came back;
        * payloads come from the blind_oob corpus with __OOB__ replaced by
          a per-param token callback;
        * injections are recorded in _oob_pending and attributed by
          collect_oob_async() at the end of the scan (batch poll, same
          Finding shape as the sync collect_oob).
        """
        try:
            if not self.oob:
                return
            if self._semaphore is None:
                self._semaphore = asyncio.Semaphore(self.max_concurrent)
            blind_bases = payloads_mod.by_context("blind_oob")
            if not blind_bases:
                return
            raw_tags = ("<script", "<svg", "<img", "<iframe", "<body ")
            # JSON mode: blind payloads ride the document leaves (Phase 47).
            if self.json_body is not None:
                blind_items = [(p, False) for p in params] + \
                              [(path, True)
                               for path in json_leaf_paths(self.json_body)]
            else:
                blind_items = [(p, False) for p in params] + \
                              [(p, True) for p in data]
            probe_variant = (blind_bases[0]["payload"]
                             .replace("https://__OOB__",
                                      self.oob.callback_url("__T__"))
                             .replace("http://__OOB__",
                                      self.oob.callback_url("__T__")))
            for param, is_body in blind_items:
                send_params, send_data = self._probe_kv(
                    params, data, param, probe_variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            text = await resp.text()
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                if not any(t in text for t in raw_tags):
                    continue  # escaped echo can never execute -- skip
                if not self._oob_started:
                    try:
                        self.oob.start()
                        self._oob_started = True
                    except Exception as e:
                        _log.warning("OOB listener failed to start: %s", e,
                                     exc_info=self.verbose)
                        return
                # One blind payload per (url, param): N payloads on the same
                # parameter all beacon to the same sink -- duplicates only.
                token = self.oob.token()
                cb = self.oob.callback_url(token)
                variant = (blind_bases[0]["payload"]
                           .replace("https://__OOB__", cb)
                           .replace("http://__OOB__", cb))
                send_params, send_data = self._probe_kv(
                    params, data, param, variant, is_body)
                try:
                    async with self._semaphore:
                        await self._throttle(url)
                        async with session.request(
                            method, url, params=send_params or None,
                            headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                            **_body_kwargs(send_data),
                        ) as resp:
                            await resp.text()
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop instead of "next param"
                except Exception:
                    continue
                async with self._get_lock():
                    self._oob_pending.append({
                        "token": token, "url": url, "method": method,
                        "param": param, "payload": variant,
                        "context": "blind_oob",
                    })
        except (BudgetExhausted, CircuitOpen):
            raise        # Phase 86: do not swallow the inner stop
        except Exception as e:
            _log.warning("async blind layer error: %s", e, exc_info=self.verbose)
        # Injection-only: this stays an async GENERATOR (page tasks drain
        # generators via _drain_agen); findings come from collect_oob_async.
        return
        yield  # pragma: no cover -- generator marker

    async def collect_oob_async(self, timeout: float | None = None
                                ) -> AsyncIterator[Finding]:
        """Batch-poll the OOB listener and emit confirmed blind findings.

        Mirrors the sync collect_oob: only callbacks count (a real browser
        executed the payload), injections are attributed to their param via
        the per-param token, oob_keep_listening re-arms late candidates, and
        the poll runs in a thread so the event loop never blocks.
        """
        if not self.oob:
            return
        timeout = float(timeout if timeout is not None
                        else getattr(self, "oob_timeout", 12))
        async with self._get_lock():
            expected = {p["token"] for p in self._oob_pending}
        if not expected:
            return
        try:
            received = await asyncio.to_thread(
                self.oob.poll, expected, timeout=timeout) or set()
        except Exception as e:
            _log.warning("OOB poll failed: %s", e, exc_info=self.verbose)
            received = set()
        async with self._get_lock():
            pending = list(self._oob_pending)
            self._oob_pending = []
        confirmed = {t for t in received if t in expected}
        by_token = {p["token"]: p for p in pending}
        for tok in sorted(confirmed):
            p = by_token.get(tok)
            if not p:
                continue
            yield Finding(
                url=p["url"], method=p["method"], param=p["param"],
                type="blind", context="blind_oob",
                payload=p["payload"], transform=[],
                severity="high", confidence="high",
                detail=(f"Blind XSS CONFIRMED via out-of-band callback. The "
                        f"injected payload beaconed to the callback host "
                        f"('{self.oob.name}'); a victim's browser executed it, "
                        f"proving the input renders in an executable context "
                        f"(classic blind/stored flow)."),
                headless=None,
                proof={"callback": self.oob.callback_url(tok)},
                evidence_class=EVIDENCE_OOB,
            )
        unconfirmed = [p for p in pending if p["token"] not in confirmed]
        if getattr(self, "oob_keep_listening", False):
            async with self._get_lock():
                self._oob_pending.extend(unconfirmed)
            if unconfirmed:
                _log.info("[*] blind: %d payload(s) still armed -- the "
                          "listener stays up", len(unconfirmed))
        elif unconfirmed and self.verbose:
            _log.debug(f"[*] blind: {len(unconfirmed)} OOB payload(s) never "
                       f"beaconed within {timeout}s")

    async def _poll_oob(self, token: str) -> bool:
        """Poll the OOB listener for a callback with the given token.

        Phase 24-1: replaced the fixed 1s sleep with exponential backoff
        (0.5, 1.0, 2.0, 4.0, 8.0 = 15.5s total) and removed the
        unnecessary ``asyncio.to_thread(getattr, ...)`` for a plain
        attribute read.
        """
        if not self.oob:
            return False
        delay = 0.5
        for _ in range(5):
            try:
                callbacks = getattr(self.oob, "callbacks", []) or []
                if any(token in str(c) for c in callbacks):
                    return True
            except Exception as e:
                _log.debug("OOB poll error: %s", e)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8.0)  # exponential backoff, cap 8s
        return False

    async def _crawl_mine_endpoints(self, text: str, url: str, depth: int
                                    ) -> list[tuple[str, str, dict, dict]]:
        """Phase 176s: form + JS endpoint mining (sync parity).

        ``_extract_links`` collects ``<a href>`` and bare form *actions* --
        with no fields attached.  Two whole discovery classes were therefore
        missing from ``--async`` crawls:

          * forms: ``form_miner`` also recovers textarea / select /
            checkbox / radio / hidden inputs, so the endpoint gets probed
            with the fields the server actually reads
            (scanner_crawl.py:250).
          * JS routes: endpoints referenced in inline or external script but
            never linked via ``<a href>`` -- the common SPA case
            (scanner_crawl.py:300).

        Either way an endpoint discovered without its parameters cannot
        reflect anything, so these were silent false negatives rather than
        merely thinner coverage (pos-formmine-01 / pos-jsmine-01).

        External scripts are fetched at depth 0 only, mirroring sync's
        request-volume guard.
        """
        found: list[tuple[str, str, dict, dict]] = []
        origin = urlparse(url).netloc
        # 1) forms -> endpoint with the fields the markup declares.
        try:
            from . import form_miner
            for f_url, f_method, f_params, f_data in (
                    form_miner.forms_to_endpoints(text, url) or []):
                if urlparse(f_url).netloc != origin:
                    continue
                found.append((f_url, f_method or "GET", dict(f_params or {}),
                              dict(f_data or {})))
        except Exception as e:
            # Wiring defects escalate before the swallow.  Sync does the
            # same at scanner_crawl.py:349-352 ("silent layer loss is worse
            # than a noisy crawl") -- a debug-level catch here would hide a
            # renamed layer function as "this page had no forms", which is
            # the exact shape that cost the async engine its ctx.classify
            # outage (see tests/test_async_wiring.py).
            if layer_guard.is_wiring_error(e):
                _log.warning("[layer:async_form_miner] %s: %s",
                             type(e).__name__, e)
            _log.debug("async form mining failed on %s: %s", url, e)
        # 2) routes defined in JS rather than in markup.
        try:
            from . import js_miner
            res = js_miner.mine_html(text, url) or {}
            eps = list(res.get("inline_endpoints") or [])
            if depth == 0:
                for s_url in (res.get("external_scripts") or [])[:8]:
                    try:
                        # _throttle FIRST, then send, then count -- the
                        # ordering every other async send uses.  Without it
                        # this mining traffic sailed past --max-requests and
                        # inflated the total, which is Phase 142's bug in a
                        # new place.
                        await self._throttle(s_url)
                        req = self._get_sync_requester()
                        sj = await asyncio.to_thread(req.get, s_url)
                        self.requests_made += 1
                        eps.extend(
                            (js_miner.mine_js_file(sj.text or "") or {})
                            .get("endpoints", []))
                    except (BudgetExhausted, CircuitOpen):
                        raise    # a budget stop is not a mining bug
                    except Exception:
                        continue
            for ep_url, _kind in eps:
                resolved = urljoin(url, ep_url)
                if urlparse(resolved).netloc != origin:
                    continue
                params: dict = {}
                if "?" in resolved:
                    q = resolved.split("?", 1)[1]
                    params = {k.split("=")[0]: "xss"
                              for k in q.split("&") if k}
                    resolved = urljoin(
                        resolved, urlparse(resolved).path or "/")
                found.append((resolved, "GET", params, {}))
        except Exception as e:
            if layer_guard.is_wiring_error(e):
                _log.warning("[layer:async_js_miner] %s: %s",
                             type(e).__name__, e)
            _log.debug("async JS mining failed on %s: %s", url, e)
        return found

    async def _crawl_and_scan(self, session, start_url: str,
                              start_text: str) -> AsyncIterator[Finding]:
        """L7 crawl: discover linked endpoints and scan them.

        Uses BFS with the configured ``crawl_depth``.  Link extraction
        runs in a thread (BeautifulSoup parse).

        Phase 24-1: switched from ``list.pop(0)`` (O(n) per pop) to
        ``collections.deque.popleft()`` (O(1)) so large crawl frontiers
        don't suffer quadratic slowdown.
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return
        from collections import deque

        visited: set[str] = {start_url}
        # Phase 176s: mined endpoints are keyed by (method, url, fields)
        # because the same URL reached with different fields is a different
        # target -- and the bare form action is already in `visited`.
        mined_seen: set[tuple] = set()
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        while queue:
            current_url, depth = queue.popleft()
            if depth >= self.crawl_depth:
                continue
            # Fetch the page (or reuse start_text for the seed).
            if current_url == start_url:
                text = start_text
            else:
                try:
                    async with self._semaphore:
                        await self._throttle(current_url)
                        async with session.get(
                            current_url, headers=self._req_headers(self.headers),
                            proxy=self._next_proxy(),
                        ) as resp:
                            text = await resp.text()
                            self.requests_made += 1
                            self._record_status(getattr(resp, "status", 200))
                except (BudgetExhausted, CircuitOpen):
                    raise        # Phase 86: stop crawling instead of skipping
                except Exception as e:
                    _log.debug("crawl fetch failed for %s: %s", current_url, e)
                    continue
            # Extract links (CPU-bound) -- run in thread.
            links = await asyncio.to_thread(_extract_links, text, current_url)
            for link in links:
                if link in visited:
                    continue
                visited.add(link)
                queue.append((link, depth + 1))
                # Scan the discovered endpoint for reflected XSS.  Phase 46:
                # a link carrying query params (?q=hi&debug=1) is scanned as
                # a GET endpoint with those params in the params dict and the
                # URL de-parameterised -- the old call passed ({}, {}) so the
                # query never reached the reflection probe and every crawled
                # query-param endpoint was silently skipped (sync crawler
                # parity: scanner_crawl.py).
                cparams: dict = {}
                if "?" in link:
                    fu = urlparse(link)
                    q = link.split("?", 1)[1]
                    cparams = {k.split("=")[0]: "xss"
                               for k in q.split("&") if k}
                    link = urljoin(link, fu.path or "/")
                async for finding in self._scan_reflected(
                        session, link, "GET", cparams, {}, text):
                    yield finding

            # Phase 176s: form + JS mining, in addition to <a href> links.
            # These arrive WITH their parameters, so unlike the link loop
            # above they can actually carry a payload.
            for m_url, m_method, m_params, m_data in await (
                    self._crawl_mine_endpoints(text, current_url, depth)):
                m_base = m_url.split("?", 1)[0]
                key = (m_method, m_base,
                       tuple(sorted(set(m_params) | set(m_data))))
                if key in mined_seen:
                    continue
                mined_seen.add(key)
                async for finding in self._scan_reflected(
                        session, m_base, m_method, m_params, m_data, text):
                    yield finding

    async def _add_finding(self, finding: Finding) -> None:
        """Thread-safe append to the findings list."""
        async with self._get_lock():
            self.findings.append(finding)

    def _log_budget_stop(self, exc: BaseException) -> None:
        """Phase 86: record + report a budget/circuit stop exactly once.

        ``_throttle()`` already filled ``budget_exhausted_reason``; before
        Phase 86 nothing ever read it, so an operator hitting --max-requests
        got a normal-looking scan with no explanation.  Mirror the sync
        scanner's warning (scanner.py) and keep the reason on the instance
        so callers/reports can surface it.
        """
        reason = str(exc) or exc.__class__.__name__
        self.budget_exhausted_reason = reason
        _log.warning("[!] Async scan stopped early (%s) -- findings so far: "
                     "%d", reason, len(self.findings))

    def _record_status(self, status: int) -> None:
        """Feed one response status into the circuit breaker (Phase 46).

        Called inline right after each response is read; a failure streak
        of ``breaker_threshold`` 5xx/429 responses within 120s trips the
        breaker and _throttle() starts raising CircuitOpen.
        """
        if self.breaker_threshold <= 0:
            return
        if status >= 500 or status == 429:
            now = time.monotonic()
            self._fail_times = [t for t in self._fail_times
                                if now - t <= 120.0]
            self._fail_times.append(now)
        else:
            self._fail_times.clear()

    def _probe_kv(self, params: dict, data: dict, param: str, value,
                  is_body: bool) -> tuple[dict, dict]:
        """Clone the endpoint inputs and set ``param`` to ``value`` on the
        right carrier (sync Scanner._set_param parity, Phase 47).

        Form mode: a body param lands in the form dict.  JSON mode: a body
        ``param`` is a LEAF PATH of the document ("user.name", "tags[0]")
        -- the value is set inside a deep copy and the result wrapped in
        JsonBody so the request goes out as application/json.
        """
        p = dict(params)
        if is_body and self.json_body is not None:
            try:
                obj = copy.deepcopy(self.json_body)
                _set_json_leaf(obj, param, value)
            except Exception:
                obj = dict(self.json_body)
                obj[param] = value
            return p, JsonBody(obj)
        d = dict(data)
        if is_body:
            d[param] = value
        else:
            p[param] = value
        return p, d

    async def _throttle(self, url: str) -> None:
        """Apply global rate limiting, per-host delay, jitter, and the
        request budget.  Raises BudgetExhausted / CircuitOpen when a cap
        is spent / the breaker tripped."""
        from urllib.parse import urlparse
        import random

        # -- budget + breaker check (always runs, even with no delay) -----
        async with self._get_lock():
            if self.max_requests is not None \
                    and self.requests_made >= self.max_requests:
                self.budget_exhausted_reason = (
                    f"total request budget exhausted "
                    f"(>={self.max_requests} requests)")
                raise BudgetExhausted(self.budget_exhausted_reason)
            if self.breaker_threshold > 0 \
                    and len(self._fail_times) >= self.breaker_threshold:
                self.budget_exhausted_reason = (
                    f"circuit open: {len(self._fail_times)} recent "
                    f"5xx/429 responses from the target")
                raise CircuitOpen(self.budget_exhausted_reason)
            if self.max_requests_per_endpoint is not None:
                p = urlparse(url)
                key = f"{p.scheme}://{p.netloc}{p.path}"
                count = self._ep_counts.get(key, 0)
                if count >= self.max_requests_per_endpoint:
                    self.budget_exhausted_reason = (
                        f"per-endpoint request budget exhausted for "
                        f"{key} (>={self.max_requests_per_endpoint} requests)")
                    raise BudgetExhausted(self.budget_exhausted_reason)
                self._ep_counts[key] = count + 1
            # -- global rate limit (token-interval style) ------------------
            if self._min_interval > 0:
                now = time.monotonic()
                wait = self._min_interval - (now - self._last_global_request)
                if wait > 0:
                    if self.jitter_ratio > 0:
                        wait = jitter_interval(wait, self.jitter_ratio)
                    await asyncio.sleep(wait)
                self._last_global_request = time.monotonic()

        # -- per-host delay + jitter (best-effort, no lock needed) --------
        if self.per_host_delay <= 0 and self.jitter <= 0:
            return
        host = urlparse(url).netloc
        now = time.monotonic()
        last = self._last_request_time.get(host, 0.0)
        elapsed = now - last
        wait = self.per_host_delay - elapsed
        if self.jitter > 0:
            wait += self.jitter * (0.5 + random.random())
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_time[host] = time.monotonic()


# =============================================================================
# Helper shims for delegating async -> sync detection modules
# =============================================================================

def _body_kwargs(data):
    """Translate a body value into aiohttp request kwargs.

    A JsonBody wrapper (the sync Requester convention) must leave as
    ``application/json`` -- aiohttp needs ``json=`` for that and would
    otherwise form-encode the dict subclass.  A plain dict keeps the
    default form encoding.  Returns a dict to splat with ``**`` so request
    call sites stay one line.
    """
    if isinstance(data, JsonBody):
        return {"data": None, "json": dict(data)}
    return {"data": data or None}


async def _drain_agen(agen, sink: list, name: str = "layer") -> None:
    """Consume an async generator into ``sink``, isolating its exceptions.

    asyncio.as_completed() requires awaitables -- async generators are NOT
    awaitables, so the old ``as_completed([agen, ...])`` pattern raised
    TypeError on every scan() call (silently swallowed upstream, leaving
    async mode with zero findings).  Draining via tasks keeps the layers
    concurrent while making results collectable; per-layer exceptions stay
    isolated so one broken layer cannot kill the batch.

    Phase 94: failures are attributed to ``name``, and wiring-class
    exceptions (ImportError / NameError / ...) escalate to a WARNING that
    names the layer -- those can never be the target's fault.
    """
    try:
        async for f in agen:
            sink.append(f)
    except (BudgetExhausted, CircuitOpen):
        raise        # Phase 86: a budget/circuit stop is NOT a layer bug
    except Exception as e:
        if layer_guard.is_wiring_error(e):
            _log.warning("[layer:%s] %s: %s -- this layer is OFF until the "
                         "defect is fixed; the remaining layers still run",
                         name, type(e).__name__, e)
            return
        _log.warning("async layer %s error: %s", name, e)


class _FakeResp:
    """Lightweight response object for sync WAF detection module."""

    def __init__(self, text: str, status: int, headers: dict):
        self.text = text
        self.status_code = status
        self.headers = headers


class _AsyncScannerShim(AdvancedLayerMixin, CrawlMixin):
    """Minimal scanner-like object for sync detection modules.

    The sync ``advanced_layers`` / ``jsonp`` / ``csp`` modules expect a
    scanner with ``_add()``, ``_bump()``, ``verbose``, ``findings``,
    ``_lock``, and ``waf_name`` attributes.  This shim provides them so
    we can reuse the sync detection code without rewriting it.

    Phase 63: every page-level sub-layer in ``layers/*.py`` starts with
    ``scanner.coverage.touch_layer(...)`` (58 call sites).  The shim had no
    ``coverage`` attribute at all, so the very first sub-layer
    (postMessage) raised AttributeError, the whole ``run_page_layers``
    aborted, and async mode silently reported NONE of the page-level
    layers -- postMessage, prototype pollution, service worker, web
    worker, open redirect, framework, GraphQL, WebSocket, Trusted Types,
    CSP nonce, cookie tossing, SRI, import map, sanitizer bypass, CSSI,
    dangling markup, SVG.  A no-op coverage facade keeps the sync code
    path intact while still recording layer touches for debugging.
    """

    class _NullCoverage:
        """Stand-in for scanner.coverage (the async scanner has none)."""

        def __init__(self):
            self.touched: list[tuple] = []

        def touch_layer(self, url, layer_id, method="GET", detail=""):
            self.touched.append((url, layer_id, method, detail))

        def record_layer(self, url, layer_id, status="ran", detail=""):
            self.touched.append((url, layer_id, status, detail))

        def record_request(self, url, method="GET"):
            pass

        def record_param(self, url, param, in_body=False):
            pass

        def record_finding(self, url, method="GET"):
            pass

        def start_endpoint(self, url, method="GET", crawled=False):
            pass

        def end_endpoint(self, url, method="GET"):
            pass

    def __init__(self, async_scanner: AsyncScanner):
        self._async = async_scanner
        self._findings: list[Finding] = []
        self.verbose = async_scanner.verbose
        self.findings = self._findings  # alias for advanced_layers
        self.waf_name = async_scanner.waf_name
        self.requests_made = 0
        self.coverage = _AsyncScannerShim._NullCoverage()
        # Page layers also reach for the requester (GraphQL / cookie
        # tossing follow-up probes).  Default None; callers that run
        # request-driven page layers must set a real one.
        #
        # Phase 176s: this used to be justified as "the layers' own
        # try/except degrades gracefully".  It does not -- it degrades
        # SILENTLY.  Cookie tossing needs a follow-up GET to read
        # Set-Cookie; with req=None it raised, swallowed the exception,
        # and proceeded with no headers, so it could never fire.  Async
        # has had a sync requester since Phase 87 (_get_sync_requester);
        # the note simply predated it and nobody re-read it.  Do not
        # reintroduce "it degrades gracefully" reasoning here.
        #
        # Annotated `Any` because the layers assign a real Requester over it;
        # left bare, mypy infers `req: None` from this line and every
        # `shim.req = CountingRequester(...)` becomes an assignment error.
        self.req: Any = None
        # Phase 132: the L7 parameter layers (mutation / DOM clobber /
        # template / polyglot / markup) read these two off the scanner.
        # Without them ``_run_advanced_layers`` would raise on the JSON
        # carrier path and skip the markup sub-layer entirely.
        # getattr: tests build the scanner with __new__ to skip __init__.
        self.json_body = getattr(async_scanner, "json_body", None)
        self._advanced_layers = True
        # Phase 176s: the OOB-aware layers (time-based) read ``scanner.oob``
        # and ``scanner._oob_started`` directly.  Async owns both -- it runs
        # its own listener -- so proxy them instead of letting the layer see
        # nothing and bail out.  Without this the time-based fallback raised
        # AttributeError on entry and every CSP-locked endpoint stayed a
        # silent false negative (pos-tb-01).
        self.oob = getattr(async_scanner, "oob", None)
        self._oob_started = bool(getattr(async_scanner, "_oob_started", False))
        # Phase 133: CrawlMixin._mine_hidden_params reads these.
        self.max_payloads = getattr(async_scanner, "max_payloads", 14)
        self.param_wordlist = None      # --param-wordlist stays sync-only
        self.bav = False                # --bav is documented sync-only
        import threading
        self._lock = threading.Lock()

    def _add(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def _bump(self) -> None:
        """Count one request the shim's sync layers are about to send.

        Phase 142.  This traffic used to be *counted but not constrained*:
        it sailed straight past ``--max-requests`` while inflating the scan
        total, which then made ``_throttle`` refuse the very next async
        request.  At a small budget the effect was that the baseline got
        rejected, ``page_tasks`` was never built, and every zero-cost layer
        (L6 CSP analysis, L3 DOM static) silently never ran -- so a
        bypassable CSP went unreported.  Found via
        tests/test_async_budget.py::test_scan_keeps_findings_collected_before_the_stop,
        failing since Phase 133 added the miner.

        The cap lives on the *scanner*, and its counter is only reconciled
        with this shim's afterwards, so the decision uses the sum of both.
        Check-then-count, mirroring ``_throttle``: ``requests_made`` never
        exceeds the cap and a rejected request is never sent.
        """
        scanner = self._async
        cap = getattr(scanner, "max_requests", None)
        if cap is not None:
            spent = getattr(scanner, "requests_made", 0) + self.requests_made
            if spent >= cap:
                scanner.budget_exhausted_reason = (
                    f"total request budget exhausted (>={cap} requests)")
                raise BudgetExhausted(scanner.budget_exhausted_reason)
        self.requests_made += 1


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract all links from an HTML page (runs in thread)."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, _bs_parser())
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                links.add(urljoin(base_url, href))
        # Also extract form actions.
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not action.startswith(("javascript:", "mailto:")):
                links.add(urljoin(base_url, action))
        return list(links)
    except Exception:
        return []


def is_available() -> bool:
    """Whether async scanning is available (aiohttp installed)."""
    try:
        import aiohttp  # noqa: F401
        return True
    except ImportError:
        return False
