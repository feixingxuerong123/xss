"""XSS scanner core: orchestrates reflection probing, context-aware payload
selection, adaptive WAF evasion, and confirmation.

Detection layers (this is what makes it "comprehensive" vs. single-technique
tools):
  L1 Reflected  - probe reflection, classify context, fire context payloads.
  L2 WAF-evade  - on block / non-confirm, mutate with transform families.
  L3 DOM        - static source->sink taint analysis of client code.
  L4 Stored     - inject then re-fetch a "view" page to catch persisted XSS.
  L5 Blind/OOB  - (optional) inject out-of-band callback payloads with unique
                  tokens, then poll a callback listener to CONFIRM blind XSS.
  L6 Headless   - optional real-browser dialog capture for proof + DOM XSS.
"""
from __future__ import annotations

import copy
import json as _json
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

from . import payloads, transform
from .budget import BudgetExhausted
from . import context as ctx
from . import waf as wafmod
from . import verifier
from . import dom as dommod
from . import dom_engine
from . import poc as pocmod
from .oob import OOBListener
from .requester import Requester, JsonBody, CountingRequester
# New detection modules (Phase 1+): mXSS, DOM clobber, template SSTI,
# JSONP callback, CSP analysis, polyglot, WAF bypass chains.
from . import mutation as mxss_mod
from . import dom_clobber as clobber_mod
from . import template as tpl_mod
from . import jsonp as jsonp_mod
from . import csp as csp_mod
from . import polyglot as poly_mod
from . import bypass as bypass_mod
# Phase 13: advanced payload engineering.
#   - ctx_mutation: context-aware mutation engine (replaces the static
#     _DEFAULT_TRANSFORMS list with per-context mutation variants).
#   - multi_encode: multi-encoding chains (URL x2 + HTML + JS unicode, etc.)
#     for bypassing WAFs that decode specific encodings.
from . import ctx_mutation as ctx_mut
from . import multi_encode as me_mod
# Phase 31: reflection profile (DalFox-style sandwich probe + ZAP strip
# feedback) -- prioritizes payloads/transforms from observed filtering.
from . import reflection_profile as rp_mod
# Phase 32: generative payload builder (XSStrike-inspired) -- constructs
# payloads from SURVIVING characters only.
from . import generator as gen_mod
# Phase 34: pre-encoding pipeline (DalFox-inspired) -- re-wraps payloads
# into base64/JWT/JSON containers detected from the original param value.
from . import pre_encode as pre_mod
# Crawler enhancements (Phase 3): JS miner, form miner, param miner.
from . import js_miner, form_miner, param_miner
# Phase 18: SPA headless crawler (Playwright-driven, replaces BS4 for SPAs).
from . import spa_crawler as spa_mod
# Reporting enhancements (Phase 6): CVSS scoring + replay PoC.
from . import cvss as cvss_mod
from . import replay as replay_mod
from . import verify_fix as verifyfix_mod
# Phase 20-3: scan coverage tracker -- records which layers/params/payloads
# were exercised per endpoint so the report can prove comprehensiveness.
from . import coverage as cov_mod
from .logger import get_logger
from .parser_utils import bs_parser as _bs_parser

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

_log = get_logger("scanner")

# A small, high-yield transform combo set used when a payload is blocked.
# Combinations are ordered by realistic bypass payoff; the engine stops at
# `max_transforms` entries (default 12) so coverage scales with the flag.

from .findings import (Finding, _DEFAULT_TRANSFORMS,
                       _grade_evidence, _norm, _proof,
                       _safe_snippet)  # noqa: F401
from .scanner_stored import StoredBlindMixin
from .scanner_layers import AdvancedLayerMixin
from .scanner_crawl import CrawlMixin
from .stealth import marker as _stem_marker


def json_leaf_paths(obj, prefix: str = "") -> list[str]:
    """Dotted/index paths of every scalar leaf in a JSON document.

    ``{"user": {"name": "a"}, "tags": ["x"]}`` ->
    ``["user.name", "tags[0]"]``
    """
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out.extend(json_leaf_paths(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(json_leaf_paths(v, f"{prefix}[{i}]"))
    else:
        if prefix:
            out.append(prefix)
    return out


def _set_json_leaf(obj, path: str, value) -> None:
    """Set a scalar leaf at a dotted/index path (``a.b[0].c``), in place."""
    tokens: list = []
    for tok in path.split("."):
        m = re.match(r"^([^\[\]]*)((?:\[\d+\])*)$", tok)
        base, idxs = m.group(1), m.group(2)
        if base:
            tokens.append(base)
        tokens.extend(int(i) for i in re.findall(r"\[(\d+)\]", idxs))
    cur = obj
    for t in tokens[:-1]:
        cur = cur[t]
    cur[tokens[-1]] = value


class Scanner(StoredBlindMixin, AdvancedLayerMixin, CrawlMixin):
    def __init__(self, requester: Requester | None = None,
                 use_headless: bool = False, max_transforms: int = 12,
                 max_payloads: int = 14, crawl: bool = False,
                 crawl_depth: int = 2, scope: str | None = None,
                 threads: int = 1, oob: OOBListener | None = None,
                 dom_engine: str = "auto", verbose: bool = False,
                 progress=None, checkpoint=None,
                 custom_payloads: list[str] | None = None,
                 advanced_layers: bool = True,
                 crawl_engine: str = "auto",
                 scenario_file: str | None = None,
                 param_wordlist: list[str] | None = None,
                 max_requests: int | None = None,
                 max_requests_per_endpoint: int | None = None,
                 upload_fields: list[str] | None = None,
                 bav: bool = False,
                 poc_include_auth: bool = False,
                 poc_verify: bool = True,
                 xsleak_audit: bool = False,
                 auth_headers: dict | None = None,
                 auth_cookies: list | None = None,
                 auth_local_storage: dict | None = None,
                 skip_params: set | None = None):
        self.req = requester or Requester()
        # Phase 184: parameters the operator asked to skip entirely
        # (--skip-param).  Applied to the L1 probe loop AND hidden-param
        # mining; deliberately NOT to scenario matching (an operator who
        # named a stored-XSS scenario for a param overrides the skip).
        self.skip_params = {str(p).strip().lower()
                            for p in (skip_params or ()) if str(p).strip()}
        self.use_headless = use_headless
        self.max_transforms = max_transforms
        self.max_payloads = max_payloads
        self.crawl = crawl
        self.crawl_depth = max(0, int(crawl_depth))
        # Scope: when set, only crawl URLs that start with this prefix (in
        # addition to the same-origin check).  None -> same-origin only.
        self.scope = scope
        self.threads = max(1, int(threads))
        self.oob = oob
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.requests_made = 0
        self.waf_name = None
        self._lock = threading.Lock()
        # Phase 48: upload-file field names to multipart-probe on POST
        # endpoints (multipart filename XSS).  Empty -> no upload probing.
        self.upload_fields: list[str] = list(upload_fields or [])
        # Phase 82: BAV follow-up probes on hidden-param miner findings.
        self.bav = bool(bav)
        # Phase 48: whether generated PoCs may embed the session cookies /
        # auth headers used during the scan (OFF by default -- reports are
        # often shared with people who should not receive the tester's
        # authenticated session).
        self.poc_include_auth = bool(poc_include_auth)
        # Phase 135: replay each finding's own PoC once, so "reproducible"
        # is measured rather than asserted.  ON by default -- it is one
        # request per *confirmed finding* (findings are rare) and it is the
        # only thing that distinguishes a PoC that works from one that does
        # not.  --no-poc-verify turns it off.
        self._poc_verify = bool(poc_verify)
        # Phase 53: target XS-Leaks surface audit (OFF by default; enabled
        # with --audit-xs-leaks).  Records a low xs_leak_surface finding for
        # pages that set none of the cross-origin isolation / framing
        # headers.  Opt-in so ordinary scans don't gain an info/low note on
        # every headerless site.
        self.xsleak_audit = bool(xsleak_audit)
        # Phase 150: authenticated session state for the real-browser DOM
        # layer.  Without it the browser confirms sinks on authenticated
        # routes as an anonymous visitor (401/login wall), while every
        # requests-based layer scans them logged-in -- the layers DISAGREE
        # on what page they looked at.
        self.auth_headers: dict = dict(auth_headers or {})
        self.auth_cookies: list = list(auth_cookies or [])
        self.auth_local_storage: dict = dict(auth_local_storage or {})
        # Phase 48: per-thread request context (params/data of the endpoint
        # currently being probed) -- lets the _add funnel attach the original
        # form fields (hidden CSRF tokens etc.) to confirmed findings so the
        # generated PoC replays against CSRF-protected endpoints.  Thread-
        # local because _scan_param runs in a thread pool.
        self._tl = threading.local()
        # Dynamic DOM engine: 'auto' uses a real browser when Playwright is
        # installed, 'playwright' forces it, 'static' disables it (heuristic
        # only). Confirmed dynamic hits are high-confidence; static-only
        # candidates are kept as medium/low hints.
        self._dom_mode = dom_engine
        self._dom_engine = self._resolve_dom_engine()
        # Pending blind injections awaiting an OOB callback: each entry holds
        # the unique token + where it was injected, so collect_oob() can map a
        # received beacon back to a confirmed finding.
        self._oob_pending: list[dict] = []
        self._oob_started = False
        # Phase 46 (pentest-readiness): blind payloads often fire only when
        # an admin views a page minutes later -- a fixed 12s window missed
        # everything.  oob_timeout feeds collect_oob()'s default poll
        # window; oob_keep_listening keeps the listener armed after the
        # first collect so late beacons can still be attributed.
        self.oob_timeout: float = 12.0
        self.oob_keep_listening: bool = False
        # Progress reporter (Phase 7): optional callback-based progress.
        self._progress = progress
        # Checkpoint (Phase 7): optional save/resume support.
        self._checkpoint = checkpoint
        # Custom payloads (Phase 7): user-supplied payload list appended to
        # the built-in corpus so users can extend coverage without editing
        # payloads.json.
        self._custom_payloads = custom_payloads or []
        # Advanced layers (Phase 9-11): postMessage, prototype pollution,
        # service worker, web worker, open redirect, framework DOM XSS,
        # header/path/cookie/error injection.  Enabled by default.
        self._advanced_layers = advanced_layers
        # Phase 18: SPA headless crawler engine selection.
        #   "auto"   -> use SpaCrawler if Playwright is available, else BS4
        #   "spa"    -> force SpaCrawler (degrades to BS4 if unavailable)
        #   "static" -> always use the BS4 _crawl() (legacy behavior)
        self.crawl_engine = crawl_engine
        # Phase 20-3: coverage tracker.  Always instantiated; the report
        # builder picks it up via ``scanner.coverage``.  Layer/param/payload
        # events are recorded from each detection method below.
        self.coverage = cov_mod.CoverageTracker()
        # Phase 41: declarative multi-step scenarios (Nuclei-inspired).
        # Param-level, reflection-independent (stored write endpoints often
        # never echo); loaded once, executed per matching param in
        # scan_endpoint.
        self.scenarios: list[dict] = []
        if scenario_file:
            try:
                from . import scenarios as sc_mod
                self.scenarios = sc_mod.load_scenarios(scenario_file)
            except Exception as e:
                _log.warning("scenario file could not be loaded: %s", e)
        # Phase 43: operator-supplied hidden-parameter candidates
        # (--param-wordlist).  Prepended to the built-in list by
        # param_miner.merged_candidates during crawl-time param mining.
        self.param_wordlist: list[str] = list(param_wordlist or [])
        # Phase 46: JSON-body carrier.  When set, body params are the LEAF
        # paths of this document (dot/index notation, e.g. "user.name",
        # "tags[0]") and every body probe is sent as application/json
        # (Requester translates the JsonBody wrapper).  Previously the
        # main reflection loop only ever sent form-encoded bodies, so
        # JSON APIs -- the majority of modern POST endpoints -- could not
        # be tested at all (pentest audit P0).
        self.json_body: dict | None = None
        # Phase 180: cooperative cancellation.  jobs.py sets this to the
        # Job's _cancel_requested event; _check_cancel() raises at every
        # request boundary.  (Phase 129's comment promised this wiring --
        # it was never implemented, so cancel only took effect when the
        # scan ENDED; a dying target delayed cancellation by minutes.)
        self.cancel_event: threading.Event | None = None
        # Phase 46: request budget (pentest-readiness).  A shared Budget
        # object is attached to the requester so every worker clone spends
        # against the same caps; BudgetExhausted stops scan_target
        # gracefully (findings so far are still reported).
        from .budget import Budget
        # Prefer a budget already attached to the requester (main() creates
        # ONE shared Budget for the whole run, batch mode included).
        self.budget = getattr(self.req, "budget", None) or Budget(
            max_total=max_requests,
            max_per_endpoint=max_requests_per_endpoint)
        if (max_requests or max_requests_per_endpoint) \
                and getattr(self.req, "budget", None) is None:
            self.req.budget = self.budget

    def _resolve_dom_engine(self):
        de = self._dom_mode
        if isinstance(de, dom_engine.DynamicDomAnalyzer):
            return de
        if de == "static":
            return None
        # 'auto': only if Playwright is importable; 'playwright': force (will
        # degrade gracefully inside analyze() if the browser can't launch).
        if de == "auto" and not dom_engine.DynamicDomAnalyzer.available():
            return None
        try:
            return dom_engine.DynamicDomAnalyzer(
                auth_headers=self.auth_headers,
                auth_cookies=self.auth_cookies,
                auth_local_storage=self.auth_local_storage)
        except Exception:
            return None

    # -- public API --------------------------------------------------------
    def scan_target(self, url: str, method: str = "GET",
                    params: dict | None = None, data: dict | None = None,
                    oob_collect: bool = True):
        """Scan a single endpoint, plus (optionally) crawled sub-endpoints.

        When an OOB listener is configured, blind payloads are injected during
        scanning; `collect_oob()` is called automatically at the end unless
        `oob_collect=False` (use that when you will also call `scan_stored`
        and want to finalize blind findings once, after both passes).
        """
        endpoints = [(url, method, params or {}, data or {})]
        if self.crawl:
            # Phase 18: dispatch to SPA headless crawler or legacy BS4
            # crawler based on the configured engine.  SpaCrawler falls
            # back to _crawl() internally when Playwright is unavailable.
            engine = (self.crawl_engine or "auto").lower()
            if engine in ("auto", "spa"):
                endpoints.extend(self._crawl_spa(url))
            else:
                endpoints.extend(self._crawl(url))
            # Phase 32: signature-level endpoint dedup (DalFox-style).
            # Crawl output like /search?q=1, /search?q=2, ... shares one
            # signature (method + host + path + param-name sets) and only
            # needs ONE scan pass, so paginated crawl sets can't exhaust
            # the request budget.  The user entry point always survives.
            endpoints = self._dedupe_endpoint_signatures(endpoints)
        # Phase 21-2: probe each endpoint for hidden parameters that the
        # server accepts but aren't visible in the UI (debug, redirect,
        # callback, ...).  Discovered params are merged into the endpoint's
        # param dict so the reflection layer tests them.  Only the first
        # `max_payloads` candidates per endpoint are probed to keep the
        # request budget bounded.
        if self._advanced_layers:
            try:
                merged: list = []
                enriched = False
                for ep_url, ep_method, ep_params, ep_data in endpoints:
                    # Phase 21-2 coverage: record param_miner activation.
                    self.coverage.touch_layer(
                        ep_url, "L9_param_miner", ep_method,
                        detail=f"probing {len(ep_params or {})} known + "
                               f"hidden candidates")
                    extra_params = self._mine_hidden_params(
                        ep_url, ep_method, ep_params, ep_data,
                        bav=self.bav)
                    if extra_params:
                        new_params = {**ep_params, **extra_params}
                        merged.append((ep_url, ep_method, new_params, ep_data))
                        enriched = True
                    else:
                        merged.append((ep_url, ep_method, ep_params, ep_data))
                if enriched:
                    endpoints = merged
                    if self.verbose:
                        _log.debug(f"[*] param_miner: enriched endpoints with "
                              f"hidden parameters")
            except Exception as e:
                _log.warning("param_miner integration error: %s", e,
                             exc_info=self.verbose)
        # Checkpoint resume: skip endpoints already scanned in a prior run.
        if self._checkpoint:
            endpoints = [ep for ep in endpoints
                         if not self._checkpoint.is_scanned(ep[0])]
        # Phase 33: audit-priority ordering (Burp-style) -- high-value
        # endpoints (many params / POST / interesting paths) are scanned
        # first so long runs surface findings as early as possible.
        endpoints = self._audit_priority(endpoints)
        total = len(endpoints)
        if self._progress:
            self._progress.on_start(total)
        if self.threads > 1 and len(endpoints) > 1:
            from .budget import BudgetExhausted, CircuitOpen
            try:
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    futures = []
                    for i, ep in enumerate(endpoints):
                        if self._progress:
                            self._progress.on_endpoint_start(ep[0], i + 1, total)
                        futures.append(ex.submit(self.scan_endpoint, *ep,
                                                 req=self.req.clone()))
                    for f in futures:
                        f.result()  # propagate exceptions
            except (BudgetExhausted, CircuitOpen) as e:
                _log.warning("[!] Scan stopped early (%s) -- findings so "
                             "far: %d", e, len(self.findings))
        else:
            from .budget import BudgetExhausted, CircuitOpen
            for i, ep in enumerate(endpoints):
                if self._progress:
                    self._progress.on_endpoint_start(ep[0], i + 1, total)
                before = len(self.findings)
                try:
                    self.scan_endpoint(*ep)
                except (BudgetExhausted, CircuitOpen) as e:
                    _log.warning("[!] Scan stopped early (%s) -- findings "
                                 "so far: %d", e, len(self.findings))
                    break
                after = len(self.findings)
                if self._checkpoint:
                    self._checkpoint.mark_scanned(ep[0])
                    self._checkpoint.add_findings(self.findings[before:after])
                    self._checkpoint.requests_made = self.requests_made
                    self._checkpoint.waf_name = self.waf_name
                    self._checkpoint.save()
                if self._progress:
                    self._progress.on_endpoint_done(ep[0], after - before)
        if self.oob and oob_collect:
            self.collect_oob()
        if self._progress:
            self._progress.on_done(len(self.findings), self.requests_made)
        return self.findings

    def scan_endpoint(self, url, method="GET", params=None, data=None,
                      req: Requester | None = None):
        req = req or self.req
        params = dict(params or {})
        data = dict(data or {})
        # Phase 20-3: mark endpoint scan start for coverage tracking.
        self.coverage.start_endpoint(url, method)
        param_items = [(p, False) for p in params] + \
                      [(p, True) for p in data]
        # Phase 46: JSON-body mode -- body params are the LEAF paths of the
        # JSON document (deep traversal, e.g. "user.profile.name",
        # "tags[0]"), so nested API bodies get full payload coverage.
        if self.json_body is not None:
            param_items = [(p, False) for p in params] + \
                          [(path, True)
                           for path in json_leaf_paths(self.json_body)]
        # Phase 184: operator --skip-param.  Case-insensitive; getattr for
        # __new__-built scanners (tests skip __init__).
        _skip = getattr(self, "skip_params", None) or set()
        if _skip:
            param_items = [(p, b) for p, b in param_items
                           if str(p).lower() not in _skip]
        # L1/L2/L5 over each reflected parameter (parallel when threads>1).
        if self.threads > 1 and len(param_items) > 1:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = []
                for p, is_body in param_items:
                    futures.append(ex.submit(
                        self._scan_param, req.clone(), url, method,
                        params, data, p, is_body))
                for f in futures:
                    f.result()
        else:
            for p, is_body in param_items:
                self._scan_param(req, url, method, params, data, p, is_body)
        # Phase 48/63: multipart upload probing.  Only when the operator
        # named upload fields (--upload-field) AND this is a body-carrying
        # endpoint (POST, or PUT/PATCH for RESTful uploads) -- upload XSS
        # rides the *filename*, a carrier the text-param loop above can
        # never reach.  Skipped in JSON-carrier mode (an upload endpoint
        # does not parse JSON bodies).
        if self.upload_fields and method.upper() in ("POST", "PUT", "PATCH") \
                and self.json_body is None:
            from .upload_probe import probe_upload
            for uf in self.upload_fields:
                self.coverage.touch_layer(
                    url, "L9_upload_filename", method,
                    detail=f"field='{uf}'")
                try:
                    for f in probe_upload(req, url, uf, method=method,
                                          data=data, params=params):
                        self._add(f)
                except Exception as e:
                    if self.verbose:
                        _log.debug("upload probe failed for %s: %s", uf, e)
        # Phase 41: declarative multi-step scenarios.  Param-level and
        # reflection-independent (stored write endpoints often never echo)
        # -- each matching scenario runs once per param after the regular
        # probe loop.  A transport/confirm failure never aborts the scan.
        if self.scenarios:
            from . import scenarios as sc_mod
            for p, p_is_body in param_items:
                for sc in self.scenarios:
                    if not sc_mod.scenario_matches(sc, p):
                        continue
                    self.coverage.touch_layer(
                        url, "L9_scenario", method, detail=sc.get("id", ""))
                    try:
                        sc_mod.run_scenario(self, req, url, p, p_is_body, sc)
                    except Exception as e:
                        if self.verbose:
                            _log.debug("scenario %s failed: %s",
                                       sc.get("id"), e)
        # L3 DOM analysis on the rendered page -- returns the fetched
        # page HTML AND response so the page-level advanced layers below
        # can reuse them instead of issuing duplicate GETs on the same URL.
        # Phase 28-4: build the full URL with query params so page-level
        # layers (e.g. import map analysis) can detect user-controlled
        # reflection in the page HTML.
        page_url = url
        if method == "GET" and params:
            try:
                from urllib.parse import urlencode
                qs = urlencode(params)
                if qs:
                    page_url = url + ("&" if "?" in url else "?") + qs
            except Exception:
                pass
        page_text, page_resp = self._scan_dom(req, page_url)
        # L7 Advanced detection layers (Phase 1+):
        #   - JSONP callback injection (probes common callback param names).
        #   - CSP analysis (parses Content-Security-Policy header, reports
        #     bypass paths).  Always runs -- it's a single header parse.
        #     Phase 21-3: reuse the response already fetched by _scan_dom
        #     to avoid a redundant duplicate GET for the same URL.
        #   - mXSS / DOM clobber / template SSTI are tied to reflection, so
        #     they run inside _scan_param when a marker is reflected.
        self._scan_jsonp(req, url, method, params, data)
        self._scan_csp(req, url, resp=page_resp)
        # Phase 51: target-level CORS audit (once per origin, two probes).
        self._scan_cors(req, url)
        # Phase 53: XS-Leaks surface audit (opt-in, reuses page_resp).
        if str(method).upper() == "GET":
            self._scan_xsleak_audit(url, resp=page_resp)
        # L8 Modern XSS vectors (Phase 9-11): postMessage, prototype
        # pollution, service worker, web worker, open redirect, framework
        # DOM XSS, header/path/cookie/error injection.  Each layer is
        # guarded internally so a bug in one never breaks the main scan.
        if self._advanced_layers:
            try:
                from . import advanced_layers
                # Page-level layers share one fetched HTML to avoid
                # re-fetching the same page 6 times.  Reuse the HTML
                # already fetched by _scan_dom above (one GET per endpoint
                # instead of two).
                if not page_text:
                    try:
                        page_resp = req.get(page_url)
                        self._bump()
                        page_text = page_resp.text or ""
                    except Exception:
                        page_text = ""
                # Pass the original url (without query params) for finding
                # creation so finding URLs stay clean, but pass params
                # separately so layers like import_map can detect
                # user-controlled reflection.
                advanced_layers.run_page_layers(self, req, url, page_text,
                                                params=params)
                advanced_layers.run_request_layers(self, req, url, method,
                                                    params, data)
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] advanced layers error: {e}")
        # Phase 20-3: mark endpoint scan end.
        self.coverage.end_endpoint(url, method)

    # -- reflection layer --------------------------------------------------
    def _scan_param(self, req, url, method, params, data, param, is_body):
        if self.verbose:
            _log.debug(f"[*] probing param '{param}' ({'POST' if is_body else 'GET'})")
        # Phase 48: remember the endpoint's original inputs for this thread
        # so any confirmed finding can carry the CSRF/hidden fields the PoC
        # replay needs (see AdvancedLayerMixin._add).
        try:
            self._tl.reqctx = {
                "url": url,
                "method": method,
                "params": dict(params or {}),
                "data": dict(data or {}),
            }
        except Exception:
            pass
        self._check_cancel()
        # Phase 20-3: record L1 reflection probe for this param.
        self.coverage.touch_layer(url, "L1_reflected", method,
                                  detail=f"probing param '{param}'")
        self.coverage.record_param(url, param, in_body=is_body, method=method)
        marker = _stem_marker("xssm_") + secrets.token_hex(4)
        probe = self._set_param(params, data, param, marker, is_body)
        try:
            resp = req.request(method, url, params=probe["params"],
                               data=probe["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception as e:
            if self.verbose:
                _log.debug(f"    request failed: {e}")
            # Phase 180: a run of FAILING requests (a dying target -- the
            # #1 cancel trigger) must not outflank the cancel checkpoint,
            # which otherwise only exists on the success path (_bump).
            self._check_cancel()
            return
        if marker not in resp.text:
            # Phase 178c: a container param whose endpoint echoes only the
            # DECODED value shows nothing for a plain marker probe -- and
            # this early return ran before the pre-encode pipeline ever
            # saw the parameter.  Range3 /gob64 measured: base64 param,
            # decode-then-echo, 0 probes, silent FN.  Detect the container
            # from the ORIGINAL value and try wrapped payloads first.
            orig_value0 = (data.get(param) if is_body
                           else params.get(param)) or ""
            enc0 = (pre_mod.detect_structure(orig_value0)
                    if orig_value0 else "none")
            if enc0 != "none" and self._try_pre_encoded(
                    req, url, method, params, data, param, is_body,
                    orig_value0, enc0, "html_element"):
                self.coverage.record_param(url, param, in_body=is_body,
                                           method=method, confirmed=True)
                self.coverage.record_finding(url, method)
            return  # not reflected -> skip
        # Phase 177: classify EVERY reflection point of the marker, not
        # just the first.  A parameter echoed in a nav highlight AND inside
        # a script block used to be classified by whichever came first in
        # the byte stream -- typically the inert one -- so payloads shaped
        # for the live context were never sent.  `ctx.rank_contexts`
        # existed for this from the start but had zero callers; analyze_all
        # wraps it with the execution-priority tiebreak.  Single-reflection
        # pages get exactly the old answer.
        sel = ctx.analyze_all(resp.text, marker)
        context = sel["context"]
        extra_contexts = [c for c in sel["contexts"] if c != context][:2]
        # Phase 27-1: early-stop optimization.  When the marker is reflected
        # but HTML-ENCODED (e.g. &lt; instead of <), the server is applying
        # context-aware output encoding.  In that case, the vast majority of
        # payload variants will also be encoded and cannot execute.  We still
        # send a SMALL probe set (2 payloads) to catch encoding bugs (double
        # encoding, broken encoders, attribute-context escapes), but we skip
        # the full max_payloads * max_transforms budget that would otherwise
        # generate ~168 requests for a param that is almost certainly safe.
        # This cuts scan time on well-defended endpoints (like /safe) from
        # ~90s to ~2s without sacrificing detection on vulnerable ones.
        marker_escaped = self._is_marker_escaped(resp.text, marker)
        waf_info = wafmod.detect(resp)
        if waf_info["waf"]:
            with self._lock:
                if not self.waf_name:
                    self.waf_name = waf_info["waf"]
            # Phase 20-3: record L2 WAF-evade layer when a WAF is present
            # (the transform loop below dispatches WAF-evasion variants).
            self.coverage.touch_layer(url, "L2_waf_evade", method,
                                      detail=f"waf={waf_info['waf']}")
        if self.verbose:
            _log.debug(f"    reflected in context '{context}'")
        # Phase 20-3: update param coverage with reflection result + context.
        self.coverage.record_param(url, param, in_body=is_body, method=method,
                                   reflected=True, context=context)

        # Build candidate payloads for this context + cross-context polyglots.
        candidates, polies = self._build_candidates(context, marker_escaped)
        # Phase 31: reflection profile -- ONE sandwich probe reveals which
        # special characters survive the filter/encoder.  Payloads whose
        # critical characters are gone move to the back (stable reorder)
        # and transform chains that can restore them are tried first.
        transform_priority = None
        bases = candidates + polies
        # Phase 177: queue a small candidate slice for each additional
        # reflection context AFTER the primary queue.  The payload-loop cap
        # (effective_max) is untouched, so single-reflection behaviour and
        # request counts are identical; extras only fire when the primary's
        # payloads leave budget unspent.
        if extra_contexts:
            _seen = {b.get("payload") for b in bases if isinstance(b, dict)}
            for _xc in extra_contexts:
                for p in self._build_candidates(_xc, marker_escaped)[0]:
                    if isinstance(p, dict) and p.get("payload") not in _seen:
                        _seen.add(p.get("payload"))
                        bases.append(p)
        bases, transform_priority, profile = self._prioritize_bases(
            req, url, method, params, data, param, is_body,
            bases, context, marker_escaped)
        # Phase 96: RCDATA breakout surfacing.  When the marker reflected
        # inside <textarea>/<title>/<xmp>, direct injections are inert
        # (the verifier correctly rejects them) while the closing-tag
        # breakout is the one vector that actually fires on raw echo.
        # The corpus has no breakout payloads, so prepend generated
        # variants built from the top candidates -- zero extra probe
        # requests, the profile already knows.
        bases, _rcd_tag = rp_mod.surface_rcdata_breakouts(profile, bases)
        if _rcd_tag and self.verbose:
            _log.debug(f"    [rcdata] reflection inside <{_rcd_tag}> -> "
                       "breakout variants lead the queue")
        # Phase 95: profile-backed escape convergence.  ``is_marker_escaped``
        # looks at the characters ADJACENT to the marker, but for a plain
        # alphanumeric marker echoed inside an element body those neighbours
        # are the page's own structural characters, which no server encodes
        # -- so the Phase 27-1 check returned False on exactly the endpoints
        # it was written for and the convergence budget never kicked in
        # (escaped cases paid ~203 requests instead of ~10).  The sandwich
        # probe is authoritative: a working encoder must reflect the probed
        # characters as entities, and when every character REQUIRED to break
        # out of this context comes back encoded, converge exactly as if the
        # adjacent-entity check had fired.
        if (not marker_escaped
                and rp_mod.profile_says_encoded(profile, context)):
            marker_escaped = True
            if self.verbose:
                _log.debug("    [converge] sandwich profile proves the "
                           "encoder is solid -> shrinking budget")
        # Phase 27-1: when the marker is escaped, also cap the total payload
        # budget at 3 (2 candidates + 1 polyglot) so we don't iterate through
        # the full max_payloads budget on an encoded reflection.
        # Phase 34: structured-param pre-encoding (DalFox-style).  Values
        # carried in base64 / double-base64 / JSON / JWT containers never
        # see raw payloads -- the container must be re-wrapped or the app
        # decodes garbage.  A hit here skips the plain-text loop entirely.
        orig_value = (data.get(param) if is_body else params.get(param)) or ""
        enc_struct = pre_mod.detect_structure(orig_value)
        confirmed = False
        if enc_struct != "none":
            if self.verbose:
                _log.debug(f"    [pre-encode] param '{param}' uses {enc_struct}")
            confirmed = self._try_pre_encoded(
                req, url, method, params, data, param, is_body,
                orig_value, enc_struct, context)
            if confirmed:
                self.coverage.record_param(url, param, in_body=is_body,
                                           method=method, confirmed=True)
                self.coverage.record_finding(url, method)
        # Phase 35: CSP-aware budget gating.  A strict CSP (inline scripts
        # blocked and the analyzer found NO bypass path) makes inline
        # reflection payloads futile -- cut the budget to a small probe set
        # (same rationale as the Phase 27-1 encoded-marker early-stop) and
        # skip the position-shift fallback.  Bypassable / absent CSP keeps
        # the full budget.
        # Phase 35/36: CSP header extraction shared by the budget gate
        # and the nonce-leak exploitation below.
        csp_hdr = ""
        try:
            csp_hdr = resp.headers.get("Content-Security-Policy") or ""
        except Exception:
            csp_hdr = ""
        csp_strict = bool(csp_hdr) and csp_mod.is_strict_inline(csp_hdr)
        if csp_strict:
            self.coverage.touch_layer(url, "L1_csp_gate", method,
                                      detail="strict CSP -> inline budget cut")
            if self.verbose:
                _log.debug("    [csp] strict CSP detected -> budget cut")
        # Phase 36: CSP nonce-leak exploitation.  When a nonce CSP is in
        # place AND the nonce leaks near the reflection point, fire a
        # script carrying the REAL nonce.  The verifier allowlists the
        # nonce against the response's own CSP header, so a server that
        # rotates nonces per request cannot be falsely confirmed.
        if not confirmed and csp_hdr:
            confirmed = self._try_csp_nonce(
                req, url, method, params, data, param, is_body,
                csp_hdr, resp.text, marker, context) or confirmed
        if marker_escaped:
            effective_max = 3
        elif csp_strict:
            effective_max = 4
        else:
            effective_max = self.max_payloads
        tried = 0
        for base in ([] if confirmed else bases):
            if tried >= effective_max:
                break
            self._check_cancel()
            tried += 1
            # Phase 20-3: record the payload class being dispatched.
            pc_name = base.get("context", context) if isinstance(base, dict) else context
            self.coverage.record_param(url, param, in_body=is_body,
                                       method=method,
                                       payload_class=pc_name,
                                       payloads_sent=1)
            if self._try_payload(req, url, method, params, data, param, is_body,
                                 base["payload"], context, waf_info,
                                 max_transforms_override=2 if marker_escaped else None,
                                 transform_priority=transform_priority):
                # Phase 20-3: mark this param as confirmed.
                self.coverage.record_param(url, param, in_body=is_body,
                                           method=method, confirmed=True)
                self.coverage.record_finding(url, method)
                confirmed = True
                break  # one confirmed finding per param is enough
        # Phase 33: parameter position shifting (Burp-style).  WAFs often
        # guard only the parameter's ORIGINAL location (query or body).
        # When a WAF is present and nothing confirmed, re-fire the top
        # payloads with the parameter cloned into the OTHER location --
        # the flipped is_body makes _set_param place it there.  Small
        # fixed budget (3 payloads x capped transforms) keeps cost low.
        if (not confirmed and not marker_escaped and not csp_strict
                and waf_info and waf_info.get("waf")):
            self._try_position_shift(
                req, url, method, params, data, param, is_body,
                bases, context, waf_info, transform_priority)
        # L5 Blind XSS: inject out-of-band callback payloads when an OOB
        # listener is configured. Confirmation happens later in collect_oob().
        if self.oob:
            self.coverage.touch_layer(url, "L5_blind_oob", method,
                                      detail=f"param='{param}'")
            self._inject_blind(req, url, method, params, data, param, is_body)
        # L7 Advanced detection layers (Phase 1+): run only when the marker
        # was reflected -- if not reflected, there's nothing to mutate /
        # clobber / template-inject against.
        self._run_advanced_layers(req, url, method, params, data, param,
                                  is_body, marker, resp.text)

    # ------------------------------------------------------------------
    # _scan_param phase helpers (extracted 2026-09; behaviour-preserving)
    # ------------------------------------------------------------------

    def _build_candidates(self, context: str, marker_escaped: bool):
        """Build candidate payloads for a reflection context + polyglots.

        Phase 19: sample broadly across related corpora so the 1000+ payload
        corpus is actually exercised within the max_payloads budget.
        Phase 27-1: when the marker is HTML-encoded, drastically reduce the
        payload budget and skip cross-context expansion -- the server is
        output-encoding, so only a couple of probes are needed to confirm
        the encoder is solid.
        """
        def _sample(ctx_name: str, n: int) -> list[dict]:
            """Take up to n payloads from a context, spread across the list."""
            ps = payloads.by_context(ctx_name)
            if len(ps) <= n:
                return ps
            # Even stride sampling so we get diverse shapes, not just the
            # first n entries.
            step = len(ps) / n
            return [ps[int(i * step)] for i in range(n)]

        if marker_escaped:
            primary_budget = 2  # minimal probe set for encoded reflections
        else:
            primary_budget = max(6, self.max_payloads // 2)
        candidates = _sample(context, primary_budget)
        if not marker_escaped:
            # A reflection in an href/src attribute can also be exploited
            # with a javascript: URI, so try those too.
            if context in ("url_href", "meta_refresh"):
                candidates = candidates + _sample("url_javascript", 4)
                # data: URI is a sibling scheme that often works in href/src.
                candidates = candidates + _sample("data_uri", 3)
            # SVG/Math reflections: prefer their dedicated payloads, but also try
            # generic element-body payloads so we never miss a working vector.
            if context in ("svg_context", "math_context"):
                candidates = candidates + _sample("html_element", 4)
            # Template-expression reflection: also try Vue-style template payloads
            # and the dedicated framework template corpora (Angular/Vue/Svelte/
            # Mustache/Ember/etc.) so sandbox-escape shapes get exercised.
            if context in ("template_angular", "template_vue"):
                candidates = (candidates
                              + _sample("template_vue", 2)
                              + _sample("framework_angular", 3)
                              + _sample("framework_vue", 3)
                              + _sample("framework_mustache", 2))
            # CDATA reflection: the breakout lands in a script-block context.
            if context in ("cdata",):
                candidates = candidates + _sample("script_block", 4)
            # html_element reflection: also draw from the new HTML-shaped corpora
            # (DOM clobber, HTML5 tags, dangling markup, error page, script
            # gadgets, header reflection, path XSS, markdown HTML) so the new
            # 700+ payloads are actually exercised by the engine.
            if context == "html_element":
                candidates = (candidates
                              + _sample("dom_clobber", 2)
                              + _sample("html5_new", 2)
                              + _sample("dangling_markup", 1)
                              + _sample("script_gadget", 2)
                              + _sample("markdown", 2)
                              + _sample("framework_react", 1)
                              + _sample("framework_svelte", 1))
            # script_block reflection: also draw from script-shaped corpora
            # (service worker / postMessage / JSONP / prototype gadgets).
            if context == "script_block":
                candidates = (candidates
                              + _sample("service_worker", 2)
                              + _sample("postmessage_source", 2)
                              + _sample("prototype_gadget", 2))
            # CSS context: also try the dedicated CSS exfiltration payloads.
            if context == "css_context":
                candidates = candidates + _sample("css_exfil", 3)
        polies = [p for p in payloads.all_polyglots()
                  if context in p.get("contexts", [])]
        return candidates, polies

    def _prioritize_bases(self, req, url, method, params, data, param,
                          is_body, bases, context, marker_escaped):
        """Phase 31/32: reflection-profile prioritization + generative
        payloads.  Returns (bases, transform_priority, profile) -- the
        profile is None when skipped (escaped marker) or probe failed;
        Phase 95 consumes it for the escape-convergence re-check."""
        transform_priority = None
        if marker_escaped:
            return bases, transform_priority, None
        profile = self._probe_reflection_profile(
            req, url, method, params, data, param, is_body)
        if profile is not None and not profile["full_reflection"]:
            bases = rp_mod.prioritize_payloads(profile, bases)
            transform_priority = rp_mod.prioritize_transforms(profile)
            # Phase 32: generative payloads built from SURVIVING chars
            # only -- they can slip past the filter that blocks the
            # corpus entries, so they lead the queue (dedup'd).
            gen_pls = gen_mod.generate(profile, context)
            if gen_pls:
                known = {b.get("payload") for b in bases}
                bases = ([g for g in gen_pls
                          if g["payload"] not in known] + bases)
        return bases, transform_priority, profile

    def _try_csp_nonce(self, req, url, method, params, data, param,
                       is_body, csp_hdr: str, resp_text: str, marker: str,
                       context: str):
        """Phase 36: exploit a CSP nonce leaked near the reflection point.

        Fires a script carrying the REAL nonce; the verifier allowlists the
        nonce against the response's own CSP header, so a server that
        rotates nonces per request cannot be falsely confirmed.
        Returns True when a finding was added.
        """
        try:
            _nonces = csp_mod.extract_nonces_from_csp(csp_hdr)
        except Exception:
            _nonces = []
        if not _nonces:
            return False
        try:
            _near = csp_mod.detect_nonce_near_marker(
                csp_hdr, resp_text or "", marker)
        except Exception:
            return False
        if not _near.get("nonce_exposed_near_marker"):
            return False
        _n = _near.get("nonce_value") or _nonces[0]
        _token = "xssv_" + secrets.token_hex(4)
        _npay = (f"<script nonce='{_n}'>"
                 f"alert('{_token}')</script>")
        _nprobe = self._set_param(params, data, param, _npay, is_body)
        _nresp = None
        try:
            _nresp = req.request(method, url, params=_nprobe["params"],
                                 data=_nprobe["data"])
            self._bump()
            self.coverage.record_request(url, method)
        except Exception:
            pass
        _ok = False
        if _nresp is not None:
            self.coverage.touch_layer(
                url, "L7_nonce_bypass", method,
                detail="nonce leaked near reflection -> "
                       "same-nonce script injected")
            _nv = verifier.verify_semantic(
                _nresp.text or "", _token,
                response_headers=dict(_nresp.headers))
            _ok = bool(_nv["confirmed"])
        if not _ok:
            return False
        # The proof here is `verify_semantic` on the injected response: the
        # nonce-bearing payload landed in an executable context.  No browser ran
        # it, so "executed" overstated the claim, and the tier says so plainly.
        _cls, _conf, _det = _grade_evidence(None, "high", (
            "CSP nonce leaked near the reflection "
            "point; injected script carrying the "
            "page nonce rendered in an executable context"))
        self._add(Finding(**{
            "url": url, "method": method, "param": param,
            "type": "reflected", "context": context,
            "payload": _npay,
            "transform": ["csp_nonce_leak"],
            "severity": "high",
            "confidence": _conf,
            "detail": _det,
            "evidence_class": _cls,
            "headless": None,
            "proof": _proof(_nresp, method, param, _npay),
        }))
        if self.verbose:
            _log.debug("    [+] CSP nonce leak exploited")
        return True

    def _try_position_shift(self, req, url, method, params, data, param,
                            is_body, bases, context, waf_info,
                            transform_priority):
        """Phase 33: re-fire top payloads in the OTHER parameter location."""
        self.coverage.touch_layer(
            url, "L2_position_shift", method,
            detail=f"param='{param}' re-fired in "
                   f"{'query' if is_body else 'body'}")
        for base in bases[:3]:
            if self._try_payload(req, url, method, params, data, param,
                                 not is_body, base["payload"], context,
                                 waf_info, max_transforms_override=4,
                                 transform_priority=transform_priority):
                self.coverage.record_param(url, param,
                                           in_body=not is_body,
                                           method=method, confirmed=True)
                self.coverage.record_finding(url, method)
                break


    def _try_payload(self, req, url, method, params, data, param, is_body,
                     payload, context, waf_info, max_transforms_override=None,
                     transform_priority=None):
        token = "xssv_" + secrets.token_hex(4)
        marked = verifier.mark(payload, token)

        # Phase 27-1: allow the caller to override max_transforms (used when
        # the marker is HTML-encoded -- no point trying 12 transform chains
        # on a reflection that will be escaped anyway).
        effective_max_transforms = max_transforms_override or self.max_transforms

        # Build the variant list.  We combine three sources, in order:
        #   1. The static _DEFAULT_TRANSFORMS list (backwards-compatible,
        #      covers the classic WAF-evasion combos).
        #   2. Context-aware mutations from ctx_mutation.mutate_for_context
        #      (Phase 13b -- picks mutations that actually help in THIS
        #      reflection context, e.g. script_close_tag only in script
        #      contexts, attr_quote_break only in attribute contexts).
        #   3. Multi-encoding chains from multi_encode.all_chain_variants
        #      (Phase 13c -- double-URL + HTML entity + JS unicode chains
        #      that survive deep decode stacks).
        #
        # Each variant is (transform_chain, variant_payload).  We cap the
        # total at effective_max_transforms to bound request count.
        variants: list[tuple[list[str], str]] = []

        # Source 1: static transforms (always included).
        for tset in _DEFAULT_TRANSFORMS[:effective_max_transforms]:
            variant = marked
            for t in tset:
                variant = transform.apply(t, variant)
            variants.append((tset, variant))

        # Source 2: context-aware mutations (Phase 13b).
        # Only add if we have budget left and the context is recognized.
        if len(variants) < effective_max_transforms:
            try:
                ctx_variants = ctx_mut.mutate_for_context(
                    marked, context,
                    max_variants=max(4, effective_max_transforms - len(variants)))
                for chain, variant in ctx_variants:
                    if len(variants) >= effective_max_transforms:
                        break
                    # Skip duplicates (same payload already in list).
                    if not any(v == variant for _, v in variants):
                        variants.append((chain, variant))
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] ctx_mutation error: {e}")

        # Source 3: multi-encoding chains (Phase 13c).
        # Only add if we have budget left AND a WAF was detected (these
        # chains are most useful when a WAF is decoding specific encodings).
        waf_name = waf_info.get("waf") if waf_info else None
        if len(variants) < effective_max_transforms and (waf_name or self.waf_name):
            try:
                target_waf = waf_name or self.waf_name
                me_variants = me_mod.all_chain_variants(
                    marked, context, target_waf,
                    max_variants=max(2, effective_max_transforms - len(variants)))
                for name, steps, variant in me_variants:
                    if len(variants) >= effective_max_transforms:
                        break
                    if not any(v == variant for _, v in variants):
                        variants.append(([f"me:{name}"], variant))
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] multi_encode error: {e}")

        # Source 4: WAF-specific bypass chains (Phase 29-2).
        # These are tested COMBINATIONS of transforms + base payloads that
        # defeat real-world WAFs (Cloudflare, AWS, ModSecurity, etc.).
        # Only injected when a WAF was detected -- otherwise the generic
        # chains from Source 1 already cover the common cases.
        if len(variants) < effective_max_transforms and (waf_name or self.waf_name):
            try:
                target_waf = waf_name or self.waf_name
                waf_chains = bypass_mod.chains_for_waf(target_waf)
                for _waf, base, chain, _why in waf_chains:
                    if len(variants) >= effective_max_transforms:
                        break
                    # Apply the chain to the MARKED payload (so we can
                    # still verify execution via the token).  This lets
                    # the WAF-specific base payloads benefit from the
                    # verifier's semantic confirmation.
                    try:
                        variant = bypass_mod.apply_chain(
                            verifier.mark(base, token), chain)
                    except Exception:
                        variant = base
                    if not any(v == variant for _, v in variants):
                        variants.append(([f"bp:{target_waf}"], variant))
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] bypass_chain error: {e}")

        # Phase 31: profile-driven transform prioritization.  Stable sort:
        # variants with equal priority keep their original order, so the
        # scan only changes behavior when the reflection profile actually
        # observed character stripping/encoding.
        if transform_priority:
            rank = {name: i for i, name in enumerate(transform_priority)}
            default = len(rank)

            def _prio(tset):
                return min((rank.get(t, default) for t in tset),
                           default=default)

            variants.sort(key=lambda vt: _prio(vt[0]))

        # Try each variant.
        for tset, variant in variants:
            # Phase 157: skip a variant whose token the transform chain
            # destroyed.  ``verify_semantic`` matches the token with a plain
            # ``str.find``, so such a variant can never be confirmed -- it is
            # a request that can only ever return "not confirmed".
            #
            # Measured statically over the whole corpus (12 transform sets x
            # 1074 payloads): 7218 of 12888 variants (56%) are dead this way
            # (dom_clobber is worst: 11% survive).  Same bug family as
            # Phase 156 in scan_stored.  Verdict-neutral by construction: a
            # variant that cannot confirm can neither create an FN nor an FP.
            if token not in variant:
                continue
            probe = self._set_param(params, data, param, variant, is_body)
            try:
                resp = req.request(method, url, params=probe["params"],
                                   data=probe["data"])
                self._bump()
            except Exception:
                continue
            w = wafmod.detect(resp)
            if w["waf"]:
                with self._lock:
                    if not self.waf_name:
                        self.waf_name = w["waf"]
            if w["blocked"] and w["reason"]:
                continue  # blocked; try next transform
            v = verifier.verify_semantic(resp.text, token,
                                         response_headers=dict(resp.headers))
            if v["confirmed"]:
                # Phase 165: the token survived -- but did the PAYLOAD?  A
                # filter that rewrites the dangerous part while leaving the
                # token byte-identical (alert( -> blocked(, or stripping a
                # `data:text/html,` prefix) passes verify_semantic and proves
                # nothing: the shipped PoC then cannot reproduce, and a human
                # replaying it sees the neutered result.  Keep looking for a
                # variant that does survive instead of reporting one that does
                # not.  Measured on benchmark neg-filter-03/05.
                if not verifier.payload_survived(resp.text, variant):
                    continue
                self._record(req, url, method, param, is_body, "reflected",
                             context, variant, tset, v, resp, token)
                return True
        # Phase 166: nothing confirmed with the plain stamp.  A keyword filter
        # rewrites a LITERAL callable while letting the concatenated form
        # through, so the payloads that survive are exactly the ones the old
        # marker could not carry -- the target was structurally unprovable
        # (measured: benchmark filter_keywords rewrites
        # alert|prompt|confirm|eval|function|setTimeout|setInterval|fetch|
        # XMLHttpRequest followed by "(" AND strips <script> and on*= tags).
        # Retry with the concat stamp.  Bounded to two requests and only
        # reached when everything above failed, so a target that confirms
        # normally pays nothing.
        concat_marked = verifier.mark(payload, token, style="concat")
        if concat_marked != marked:
            retry: list[tuple[list[str], str]] = [([], concat_marked)]
            for tset, _v in variants[:1]:
                v2 = concat_marked
                for t in tset:
                    v2 = transform.apply(t, v2)
                retry.append((list(tset) + ["concat_stamp"], v2))
            for tset, variant in retry:
                if token not in variant:
                    continue
                probe = self._set_param(params, data, param, variant, is_body)
                try:
                    resp = req.request(method, url, params=probe["params"],
                                       data=probe["data"])
                    self._bump()
                except Exception:
                    continue
                v = verifier.verify_semantic(
                    resp.text, token, response_headers=dict(resp.headers))
                if v["confirmed"] and verifier.payload_survived(resp.text,
                                                                variant):
                    self._record(req, url, method, param, is_body,
                                 "reflected", context, variant, tset, v, resp,
                                 token)
                    return True
        # Phase 22-3: time-based fallback.  When the marker IS reflected
        # (we got here past the early return) but none of the standard
        # payloads confirmed execution, the target may have a strict CSP
        # that blocks alert().  Try resource-fetch payloads that trigger
        # an OOB callback -- if the browser fetches the callback resource,
        # we know the payload was parsed as HTML despite CSP.
        if self.oob and self._advanced_layers:
            try:
                from . import time_xss as tx_mod
                tx_mod.scan_time_based(
                    self, req, url, method, params, data, param, is_body)
                # Phase 176u: record AFTER the layer has actually run.  The
                # touch_layer used to sit before the call, so a failure on
                # entry -- a bad import, a renamed symbol -- still printed
                # "L7_time_based: ran" in the client's coverage matrix while
                # the CSP fallback had done nothing at all.  Same lie, same
                # fix as L6_dom_dynamic (scanner_layers.py:93-105), which is
                # the pattern copied here including the failed-status row.
                self.coverage.touch_layer(
                    url, "L7_time_based", method,
                    detail=f"fallback for param '{param}' (CSP may block alert)")
            except Exception as e:
                self.coverage.record_layer(url, "L7_time_based", method,
                                           status="failed",
                                           detail=f"{type(e).__name__}: "
                                                  f"{str(e)[:140]}")
                _log.warning("L7_time_based failed for %s (%s: %s); the CSP "
                             "fallback did not run on this parameter", url,
                             type(e).__name__, e)
        return False

    # -- L4 stored XSS -----------------------------------------------------

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
                _cls, _conf, _det = _grade_evidence(
                    None, "high",
                    v["detail"] + f" (pre-encoded {struct} param)")
                self._add(Finding(**{
                    "url": url, "method": method, "param": param,
                    "type": "reflected", "context": context,
                    "payload": enc,
                    "transform": [f"pre_encode:{struct}"],
                    "severity": "high",
                    "confidence": _conf,
                    "detail": _det,
                    "evidence_class": _cls,
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


    def _record(self, req, url, method, param, is_body, ftype, context, payload,
                tset, verify, resp, token):
        headless = None
        if self.use_headless:
            if is_body and self.json_body is not None:
                # Phase 46: headless confirmation replays the probe as a
                # form body -- meaningless for JSON-carrier findings (the
                # semantic confirmation already ran against the real JSON
                # response), so skip rather than confirm against the wrong
                # content type.
                headless = {"available": False, "confirmed": False,
                            "detail": "json carrier; headless replay skipped"}
            else:
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
            # Phase 179 (user decision): severity drops WITH confidence.
            # A reflection in a non-HTML response cannot execute in a
            # browser tab; carrying it at high severity meant every
            # severity-only consumer (benchmark FP gate, SARIF error
            # level, report highlighting) treated it like a live sink.
            # The finding is kept -- severity AND confidence read low.
            confidence = "low"
            severity = "low"
            detail = (detail + " (non-HTML content-type '%s')"
                      % ctype.split(";")[0].strip())
        evidence, confidence, detail = _grade_evidence(headless, confidence,
                                                      detail)
        self._add(Finding(**{
            "url": url, "method": method, "param": param,
            "type": ftype, "context": context, "payload": payload,
            "transform": tset, "severity": severity,
            "confidence": confidence, "detail": detail,
            # The strongest evidence class actually behind this finding, stated
            # instead of being implied by a severity label.  Its OWN key: every
            # other producer in this codebase (~50 sites across layers/*,
            # async_scanner, sandbox) writes an evidence EXCERPT into `evidence`,
            # and report.py / report_ai.py read that as descriptive text.  A tier
            # name in there silently replaced the reflected-markup excerpt.
            "evidence_class": evidence,
            # Phase 164: WHERE the payload actually rode.  The PoC generator
            # used to infer this from the method ("POST -> body"), which is
            # wrong for every position-shift finding: _try_position_shift
            # re-fires the parameter into the OTHER location, so a POST whose
            # payload rode the query shipped a curl with the payload in the
            # body -- the one place the WAF inspects.  Measured on
            # pos-pshift-01: the shipped PoC replayed into "Sorry, you have
            # been blocked", while the query carrier returns 200 and reflects.
            "param_in": "body" if is_body else "query",
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

    def _check_cancel(self):
        """Abort cooperatively when the operator cancelled the scan.

        Raises BudgetExhausted, which the API worker maps to CANCELLED
        (with the findings gathered so far) when the flag is set.
        """
        # getattr, not self.cancel_event: test helpers build Scanner via
        # __new__ and set attributes by hand -- a bare instance must skip
        # cancellation, not crash on the missing attribute.
        ev = getattr(self, "cancel_event", None)
        if ev is not None and ev.is_set():
            raise BudgetExhausted("scan cancelled by operator")

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
                    # Phase 98: replay-worthy session headers too
                    # (Authorization / X-API-Key / custom anti-bot ...).
                    # Cookie is carried by the -b channel, transport
                    # control headers are dropped inside build_poc.
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
            # Phase 135: actually RUN the PoC once.  Everything above only
            # *builds* strings -- nothing checked that the exported curl /
            # URL / HTML reproduces the finding, so "reproducible PoC" was a
            # claim rather than a measurement.  One request per finding
            # (findings are rare); disable with --no-poc-verify.
            if getattr(self, "_poc_verify", False) and self.req is not None:
                try:
                    # Counting proxy: the replayer drives the Requester
                    # directly and never bumps, so without this its requests
                    # would not appear in the scan's total.
                    verdict = verifyfix_mod.verify_poc(
                        CountingRequester(self.req, self._bump), f.data,
                        verbose=self.verbose)
                    if (not getattr(self, "poc_include_auth", False)
                            and verdict.get("verified")):
                        # The replay used the scan session; the exported PoC
                        # does not carry it.  Say so, rather than letting a
                        # reader discover it as a 401.
                        try:
                            _creds = bool(
                                self.req.session.cookies.get_dict()
                                or self.req.session.headers)
                        except Exception:
                            _creds = False
                        if _creds:
                            verdict["note"] = (
                                "replayed with the scan session; the exported "
                                "PoC omits credentials (pass "
                                "--poc-include-auth to include them)")
                    f.data["poc_verified"] = verdict.get("verified")
                    f.data["poc_verify"] = verdict
                except Exception as e:
                    if self.verbose:
                        _log.debug(f"    [!] PoC verify error: {e}")
                    f.data.setdefault("poc_verified", None)

    # -- L7 advanced detection layers (Phase 1+) ---------------------------

