"""Crawler methods (SPA headless crawl, hidden-param mining, BFS crawl)
as a Scanner mixin.  Phase 40 split: moved verbatim from scanner.py.
"""
from __future__ import annotations

import secrets

from . import payloads
from . import layer_guard
from . import param_miner
from . import form_miner
from . import js_miner
from . import verifier
from . import transform
from . import csp as csp_mod
from . import jsonp as jsonp_mod
from . import mutation as mxss_mod
from . import dom_clobber as clobber_mod
from . import template as tpl_mod
from . import polyglot as poly_mod
from . import dom as dommod
from . import dom_engine
from . import spa_crawler as spa_mod
from .findings import (Finding, _DEFAULT_TRANSFORMS, _grade_evidence,
                       _norm, _proof, _safe_snippet)
from .logger import get_logger

_log = get_logger("scanner.mixins")



from .parser_utils import bs_parser as _bs_parser  # noqa: F401  (Phase 40 split omission fix)


class CrawlMixin:
    """Crawler / attack-surface discovery methods."""

    def _crawl_spa(self, start_url):
        """Phase 18: SPA headless crawler entry point.

        Constructs a SpaCrawler configured from the Scanner's options and
        the Requester's session cookies (P3-1: headless session sharing),
        then delegates to it.  SpaCrawler falls back to ``_crawl()``
        internally when Playwright is unavailable.
        """
        # P3-1: export the requester's session cookies so the SPA crawler
        # visits authenticated routes in the same session as the scanner.
        cookies: dict = {}
        try:
            jar = getattr(self.req, "session", None)
            if jar is not None and getattr(jar, "cookies", None) is not None:
                # RequestsCookieJar -> dict (drops domain/path metadata;
                # Playwright will re-scope them to the target origin).
                cookies = {c.name: c.value
                           for c in jar.cookies if c.name}
        except Exception:
            cookies = {}
        # Export extra headers (User-Agent etc.) so the SPA browser matches
        # the scanner's HTTP fingerprint.
        extra_headers: dict = {}
        try:
            hdrs = getattr(self.req.session, "headers", None)
            if hdrs is not None:
                # Skip auto-managed headers (Host, Cookie) that Playwright
                # sets itself; keep only the operator-supplied ones.
                skip = {"host", "cookie", "content-length", "accept-encoding"}
                extra_headers = {k: v for k, v in hdrs.items()
                                 if k.lower() not in skip}
        except Exception:
            extra_headers = {}

        crawler = spa_mod.SpaCrawler(
            max_depth=self.crawl_depth,
            scope=self.scope,
            timeout=20,
            headless=True,
            per_page_budget_s=8.0,
            max_total_pages=50,
            max_clicks_per_page=10,
            verbose=self.verbose,
            cookies=cookies,
            extra_headers=extra_headers,
        )
        # Wire the bump callback so SpaCrawler navigations increment the
        # parent scanner's requests_made counter (keeps reports accurate).
        crawler._bump = self._bump
        return crawler.crawl(start_url, fallback_crawler=self._crawl)

    def _mine_hidden_params(self, url: str, method: str,
                            existing_params: dict, existing_data: dict,
                            bav: bool = False) -> dict:
        """Phase 21-2: probe an endpoint for hidden parameters.

        Uses ``param_miner.mine_params`` to send candidate param names
        (debug, redirect, callback, ...) and detect which ones the server
        responds to differently.  Returns a dict of discovered params
        ready to merge into the endpoint's param dict.

        Bounded by ``max_payloads`` to avoid request explosion on large
        crawl sets.  Returns an empty dict if nothing interesting is found
        or if the request budget is exhausted.
        """
        if not url:
            return {}
        try:
            # Cap candidates to keep request volume bounded.  The miner
            # sends one request per candidate, so max_params=20 means at
            # most 20 extra requests per endpoint.
            budget = max(10, min(self.max_payloads, 20))
            # Phase 43: operator wordlist (--param-wordlist) prepended.
            extra = getattr(self, "param_wordlist", None) or None
            found = param_miner.mine_params(
                self.req, url, method=method,
                existing_params=existing_params or {},
                existing_data=existing_data or {},
                max_params=budget,
                verbose=self.verbose,
                mode="auto",
                extra_candidates=extra,
                bav=bav,
            )
        except Exception as e:
            if layer_guard.is_wiring_error(e):
                _log.warning("[layer:param_miner] %s: %s -- param mining is "
                             "OFF until the defect is fixed",
                             type(e).__name__, e)
            return {}
        out: dict = {}
        for p in found:
            name = p.get("name")
            if not name:
                continue
            # Phase 82: BAV confirmations become real findings (one per
            # kind) -- the adjacent-vulnerability classes DalFox reports
            # alongside XSS triage.
            for b in p.get("bav") or []:
                # Graded OUTSIDE the try below: that handler swallows every
                # exception, so a grading bug would silently delete findings
                # rather than surface as one.
                _cls, _conf, _det = _grade_evidence(
                    None, "medium",
                    f"BAV probe on param '{name}': {b['detail']}")
                try:
                    from .findings import Finding
                    self._add(Finding(
                        url=url, method=method, param=name,
                        type="bav", context=b["kind"],
                        payload="", transform=[],
                        severity="medium", confidence=_conf,
                        detail=_det, evidence_class=_cls,
                        headless=None, proof={"kind": b["kind"]},
                    ))
                except Exception:
                    pass
            # Only add params that either reflect or cause a notable
            # response change (length_delta > 50 or status delta).
            if p.get("reflected") or p.get("length_delta", 0) > 50 \
                    or p.get("status_delta", 0) != 0:
                out[name] = "xss"
        return out

    def _crawl(self, start_url):
        """Deep crawler: breadth-first discover of in-scope endpoints.

        Follows same-origin (and optional ``scope`` prefix) <a href> links up to
        ``crawl_depth`` levels, and extracts <form> endpoints (GET/POST).  Every
        in-scope page is returned as a scannable endpoint (with its query params
        if any) so DOM sinks are covered even on param-less pages.  Returns a
        flat, deduped list of ``(url, method, params, data)`` tuples.
        """
        from bs4 import BeautifulSoup
        from collections import deque
        from urllib.parse import urlparse, urljoin
        base = urlparse(start_url)
        same_origin = base.netloc
        start_nurl = _norm(start_url).split("?", 1)[0]
        queue: deque = deque([(start_url, 0)])
        visited: set = set()
        endpoints: list = []
        seen_ep: set = set()
        max_depth = self.crawl_depth
        while queue:
            url, depth = queue.popleft()
            nurl = _norm(url)
            if nurl in visited:
                continue
            visited.add(nurl)
            if depth > max_depth:
                continue
            try:
                resp = self.req.get(url)
                self._bump()
            except Exception:
                continue
            # Enqueue every in-scope link for further crawling.
            soup = BeautifulSoup(resp.text, _bs_parser())
            for a in soup.find_all("a", href=True):
                href = (a["href"] or "").strip()
                if not href or href.startswith(("#", "javascript:",
                                                "mailto:", "tel:", "data:")):
                    continue
                full = urljoin(url, href)
                fu = urlparse(full)
                if fu.netloc != same_origin:
                    continue
                if self.scope and not full.startswith(self.scope):
                    continue
                nf = _norm(full)
                if nf not in visited:
                    queue.append((full, depth + 1))
            # Register discovered endpoints.
            # IMPORTANT: keep the query string ONLY in the params dict, never
            # embedded in the URL.  scan_endpoint() also passes ``params`` to
            # the requester, so an embedded ?q=hi PLUS params={q:marker} would
            # produce a duplicate/merged ?q=hi&q=marker and the server would
            # read the first value (hi); the marker never reflects and the
            # reflected layer silently misses every crawled query-param endpoint.
            # 1) links carrying query params -> GET endpoint
            for a in soup.find_all("a", href=True):
                href = (a["href"] or "").strip()
                if not href or "?" not in href:
                    continue
                full = urljoin(url, href)
                fu = urlparse(full)
                if fu.netloc != same_origin:
                    continue
                if self.scope and not full.startswith(self.scope):
                    continue
                q = full.split("?", 1)[1]
                params = {k.split("=")[0]: "xss" for k in q.split("&") if k}
                ep_url = _norm(full).split("?", 1)[0]
                key = ("GET", ep_url, tuple(sorted(params)))
                if key not in seen_ep:
                    seen_ep.add(key)
                    endpoints.append((ep_url, "GET", params, {}))
            # 2) every in-scope page itself -> scan it (covers DOM on param-less
            #    pages like /dom). Use normalized URL with query stripped, no
            #    params.  Skip the start URL: scan_target() already scans it as
            #    endpoints[0], so registering it here would duplicate the DOM
            #    analysis pass.
            page_url = _norm(url).split("?", 1)[0]
            if page_url == start_nurl:
                pass  # already endpoints[0]
            else:
                page_key = ("PAGE", page_url, "")
                if page_key not in seen_ep:
                    seen_ep.add(page_key)
                    endpoints.append((page_url, "GET", {}, {}))
            # 3) forms -> GET/POST endpoint with discovered inputs.
            # Phase 21-2: use form_miner for complete field coverage
            # (textarea/select/checkbox/radio/hidden), replacing the
            # old input-only extraction that missed half the field types.
            try:
                forms_found = form_miner.forms_to_endpoints(resp.text, url)
                if forms_found:
                    self.coverage.touch_layer(
                        url, "L9_form_miner", "GET",
                        detail=f"discovered {len(forms_found)} form(s)")
                for ep in forms_found:
                    f_url, f_method, f_params, f_data = ep
                    fu = urlparse(f_url)
                    if fu.netloc != same_origin:
                        continue
                    if self.scope and not f_url.startswith(self.scope):
                        continue
                    act_url = _norm(f_url).split("?", 1)[0]
                    fields = f_params or f_data
                    key = (f_method, act_url, tuple(sorted(fields)))
                    if key not in seen_ep:
                        seen_ep.add(key)
                        endpoints.append((act_url, f_method, f_params, f_data))
            except Exception:
                # Fall back to the old BS4 form extraction if form_miner
                # blows up (keeps the scan resilient).
                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action") or url)
                    fu = urlparse(action)
                    if fu.netloc != same_origin:
                        continue
                    if self.scope and not action.startswith(self.scope):
                        continue
                    method = (form.get("method") or "GET").upper()
                    inputs = {i.get("name"): (i.get("value") or "xss")
                              for i in form.find_all("input")
                              if i.get("name")}
                    if inputs:
                        act_url = _norm(action).split("?", 1)[0]
                        key = (method, act_url, tuple(sorted(inputs)))
                        if key not in seen_ep:
                            seen_ep.add(key)
                            data = inputs if method == "POST" else {}
                            params = {} if method == "POST" else inputs
                            endpoints.append((act_url, method, params, data))
            # Phase 21-2: mine JS for hidden endpoints (fetch/axios/XHR/
            # route definitions).  These are endpoints referenced in JS
            # source but never linked via <a href> -- common in SPAs.
            # Only fetch external JS at depth 0 to avoid blowing up the
            # request count on deep crawls.
            try:
                js_result = js_miner.mine_html(resp.text, url)
                js_endpoints: list[tuple[str, str]] = list(
                    js_result.get("inline_endpoints", []))
                if js_endpoints or js_result.get("external_scripts"):
                    self.coverage.touch_layer(
                        url, "L9_js_miner", "GET",
                        detail=f"inline:{len(js_endpoints)} "
                               f"scripts:{len(js_result.get('external_scripts', []))}")
                # Fetch external scripts (only at shallow depth to limit
                # request volume; deep-crawl pages rarely define new routes).
                if depth == 0:
                    for script_url in js_result.get("external_scripts", [])[:8]:
                        try:
                            sj = self.req.get(script_url)
                            self._bump()
                            ext = js_miner.mine_js_file(sj.text or "")
                            js_endpoints.extend(ext.get("endpoints", []))
                        except Exception as e:
                            if layer_guard.is_wiring_error(e):
                                _log.warning(
                                    "[layer:js_miner] %s: %s -- JS mining "
                                    "is OFF until the defect is fixed",
                                    type(e).__name__, e)
                            continue
                # Resolve + register discovered JS endpoints.
                for ep_url, kind in js_endpoints:
                    resolved = urljoin(url, ep_url)
                    ru = urlparse(resolved)
                    if ru.netloc != same_origin:
                        continue
                    if self.scope and not resolved.startswith(self.scope):
                        continue
                    # If the JS endpoint has a query string, treat it as a
                    # GET endpoint with those params.
                    if "?" in resolved:
                        q = resolved.split("?", 1)[1]
                        params = {k.split("=")[0]: "xss"
                                  for k in q.split("&") if k}
                        ep_u = _norm(resolved).split("?", 1)[0]
                        key = ("GET", ep_u, tuple(sorted(params)))
                        if key not in seen_ep:
                            seen_ep.add(key)
                            endpoints.append((ep_u, "GET", params, {}))
                    else:
                        ep_u = _norm(resolved).split("?", 1)[0]
                        page_key = ("PAGE", ep_u, "")
                        if page_key not in seen_ep:
                            seen_ep.add(page_key)
                            endpoints.append((ep_u, "GET", {}, {}))
            except Exception as e:
                # JS mining is best-effort; never break the crawl.  Wiring
                # defects still escalate -- silent layer loss is worse than
                # a noisy crawl.
                if layer_guard.is_wiring_error(e):
                    _log.warning("[layer:js_endpoints] %s: %s",
                                 type(e).__name__, e)
        return endpoints


def _abs(base, link):
    from urllib.parse import urljoin
    return urljoin(base, link)

