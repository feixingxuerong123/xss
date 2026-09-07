"""Stored (L4) + blind/OOB (L5) scanning methods, as a Scanner mixin.

Phase 40 split: methods moved verbatim from scanner.py.  Requires the
host Scanner to provide: req/_add/_bump/_lock/_oob_pending/_oob_started,
coverage, max_transforms/max_payloads, verbose, findings.
"""
from __future__ import annotations

from __future__ import annotations

import secrets

from . import payloads
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
from .findings import (Finding, _DEFAULT_TRANSFORMS,
                       _norm, _proof, _safe_snippet)
from .logger import get_logger

_log = get_logger("scanner.mixins")



class StoredBlindMixin:
    """L4 stored + L5 blind/OOB detection methods."""

    def scan_stored(self, inject_url: str, view_url: str | None = None,
                    method: str = "POST", param: str = "q",
                    req: Requester | None = None,
                    fresh_session: bool = False):
        """Inject a payload, then re-fetch a 'view' page to detect persisted
        (stored) XSS. The view page must render previously stored entries.

        Phase 46 (pentest-readiness): the previous implementation always
        re-fetched the view page with the SAME authenticated session, and
        when no explicit view URL was given it viewed the inject page
        itself -- so a plain reflected endpoint was reported as
        ``stored``/high-confidence.  Now:

        * ``fresh_session=True`` re-fetches the view page from a cookie-free
          clone (same auth headers, no session cookies) -- if the payload is
          still rendered, persistence is proven from an independent viewer.
        * When the view page is the inject page itself (no explicit
          --stored-view), the finding is downgraded to confidence=medium
          with an explicit "same-session self-view" note, so operators can
          tell unproven persistence from confirmed stored XSS.
        """
        req = req or self.req
        explicit_view = view_url is not None
        view_url = view_url or inject_url
        if view_url == inject_url and inject_url.rstrip("/").endswith("/store"):
            view_url = inject_url.rstrip("/")[:-len("/store")] + "/view"
            explicit_view = True
        # Phase 20-3: record L4 stored XSS layer.
        self.coverage.touch_layer(inject_url, "L4_stored", method,
                                  detail=f"inject->{view_url} param='{param}'")
        view_req = req
        if fresh_session:
            try:
                view_req = self._fresh_session_view_req(req)
            except Exception as e:
                _log.warning("fresh-session viewer unavailable (%s); "
                             "falling back to the scan session", e)
        bases = (payloads.by_context("html_element")
                 + payloads.by_context("script_block")
                 + payloads.by_context("event_handler")
                 + payloads.by_context("svg_context"))[:self.max_payloads]
        bases += [p for p in payloads.all_polyglots()
                  if "html_element" in p.get("contexts", [])]
        for base in bases:
            token = "xssv_" + secrets.token_hex(4)
            marked = verifier.mark(base["payload"], token)
            for tset in _DEFAULT_TRANSFORMS[:self.max_transforms]:
                variant = marked
                for t in tset:
                    variant = transform.apply(t, variant)
                try:
                    if method.upper() == "POST":
                        req.request(method, inject_url, data={param: variant})
                    else:
                        req.request(method, inject_url, params={param: variant})
                    self._bump()
                    # Phase 21-3: invalidate any cached GET for the view URL
                    # so the next fetch actually sees the just-stored payload.
                    if hasattr(req, "invalidate"):
                        req.invalidate(view_url)
                    vresp = view_req.get(view_url)
                    self._bump()
                except Exception:
                    continue
                v = verifier.verify_semantic(vresp.text, token,
                                             response_headers=dict(vresp.headers))
                if v["confirmed"]:
                    if fresh_session and view_req is not req:
                        confidence = "high"
                        note = ("persistence CONFIRMED from a fresh "
                                "cookie-free viewer session")
                    elif not explicit_view and view_url == inject_url:
                        confidence = "medium"
                        note = ("same-session self-view: the payload renders "
                                "on the inject page itself, which does NOT "
                                "prove persistence for other viewers -- "
                                "re-run with --stored-view / "
                                "--stored-fresh-session to confirm")
                    else:
                        confidence = "high"
                        note = "explicit viewer page rendered the payload"
                    self._add(Finding(**{
                        "url": inject_url, "method": method, "param": param,
                        "type": "stored", "context": "stored_view",
                        "payload": variant, "transform": tset,
                        "severity": "high", "confidence": confidence,
                        "detail": f"payload persisted and executed in {view_url} "
                                  f"({v['detail']}; {note})",
                        "headless": None,
                        "proof": {"view_url": view_url, "token": token,
                                  "fresh_session": bool(fresh_session and
                                                        view_req is not req),
                                  "snippet": _safe_snippet(vresp.text, token)}}))
                    return True
        return False

    @staticmethod
    def _fresh_session_view_req(req):
        """A cookie-free Requester clone for independent viewer confirmation.

        Carries the same timeout/proxy/headers/auth-headers (so the view
        page still renders) but NO session cookies -- a different visitor.
        Shares the budget/breaker so guards still apply.  Raises when the
        request module is unavailable (pure-mock test requesters).
        """
        from .requester import Requester
        session = getattr(req, "session", None)
        if session is None:
            raise RuntimeError("requester has no session to derive from")
        proxy = session.proxies.get("http")
        rate = getattr(getattr(req, "rate_limiter", None), "rate", 0)
        clone = Requester(timeout=getattr(req, "timeout", 15), proxy=proxy,
                          headers=dict(session.headers),
                          verify_ssl=getattr(session, "verify", True),
                          rate_limit=rate or 0,
                          budget=getattr(req, "budget", None),
                          breaker=getattr(req, "breaker", None))
        return clone

    # -- L4 second-order XSS (inject A, discover B by crawling) -------------
    def scan_second_order(self, inject_url: str, param: str = "q",
                          method: str = "POST", start_url: str | None = None,
                          viewer_urls: list[str] | None = None,
                          max_pages: int = 25):
        """Detect second-order XSS: inject at endpoint A, then crawl to
        discover endpoint B where the stored payload renders unescaped.

        Unlike ``scan_stored`` (which requires the operator to supply the
        view URL), this method *discovers* the view page by crawling the
        site after injection.  See ``core.second_order`` for details.

        ``viewer_urls`` -- explicit list of candidate viewer pages.  When
        provided, crawling is skipped and only these URLs are checked.
        ``start_url`` -- crawl start point (defaults to ``inject_url``).
        """
        from . import second_order as so_mod
        # Phase 20-3: record L4 second-order layer.
        self.coverage.touch_layer(inject_url, "L4_second_order", method,
                                  detail=f"inject {param} -> crawl "
                                         f"{start_url or inject_url}")
        results = so_mod.scan_second_order(
            self, inject_url, param=param, method=method,
            start_url=start_url, viewer_urls=viewer_urls,
            max_pages=max_pages, verbose=self.verbose)
        for r in results:
            self._add(Finding(**{
                "url": r["inject_url"], "method": r["inject_method"],
                "param": r["inject_param"],
                "type": "second_order", "context": r["context"],
                "payload": r["payload"], "transform": [],
                "severity": "high", "confidence": "high",
                "detail": (f"payload injected at {r['inject_url']} "
                           f"({r['inject_method']} {r['inject_param']}) "
                           f"executed at {r['viewer_url']} "
                           f"({r['detail']})"),
                "headless": None,
                "proof": {"viewer_url": r["viewer_url"],
                          "token": r["token"], "snippet": r["snippet"]},
            }))
            self.coverage.record_finding(r["viewer_url"], "GET")
        if results and self.verbose:
            _log.debug(f"[+] second-order: {len(results)} confirmed finding(s)")
        return len(results) > 0

    # -- L5 blind XSS (out-of-band callback) --------------------------------
    def _inject_blind(self, req, url, method, params, data, param, is_body):
        # Only inject blind payloads where the parameter reflects an UNESCAPED
        # executable tag.  This (a) focuses blind on real reflection points and
        # (b) keeps HTML-escaped endpoints (e.g. /safe) at zero false positives
        # -- an escaped OOB payload can never execute, so it can't beacon.
        raw_tags = ("<script", "<svg", "<img", "<iframe", "<body ")
        blind_bases = payloads.by_context("blind_oob")
        if not blind_bases:
            return
        # One reflection probe with a representative OOB payload (token masked).
        probe_variant = (blind_bases[0]["payload"]
                         .replace("https://__OOB__", self.oob.callback_url("__T__"))
                         .replace("http://__OOB__", self.oob.callback_url("__T__")))
        probe = self._set_param(params, data, param, probe_variant, is_body)
        try:
            resp = req.request(method, url, params=probe["params"],
                               data=probe["data"])
            self._bump()
        except Exception:
            return
        if not any(t in resp.text for t in raw_tags):
            return
        # Reflection is executable -> start listener and fire real OOB payloads
        # each carrying a unique token so callbacks can be attributed.
        if not self._oob_started:
            try:
                self.oob.start()
                self._oob_started = True
            except Exception as e:
                _log.warning("OOB listener failed to start: %s", e,
                             exc_info=self.verbose)
                return
        # Inject ONE blind payload per (url, param).  Multiple payloads on the
        # same parameter all beacon back to the same sink, producing N duplicate
        # findings for a single vulnerability.  One is enough for confirmation.
        base = blind_bases[0]
        token = self.oob.token()
        cb = self.oob.callback_url(token)
        variant = (base["payload"]
                   .replace("https://__OOB__", cb)
                   .replace("http://__OOB__", cb))
        probe = self._set_param(params, data, param, variant, is_body)
        try:
            req.request(method, url, params=probe["params"],
                        data=probe["data"])
            self._bump()
        except Exception:
            return
        with self._lock:
            self._oob_pending.append({
                "token": token, "url": url, "method": method,
                "param": param, "payload": variant, "context": "blind_oob",
            })

    def collect_oob(self, timeout: float | None = None):
        """Poll the OOB listener and turn received beacons into CONFIRMED
        (high-severity) blind-XSS findings.  Call after scanning completes.

        A received callback is strong evidence: a real browser executed the
        injected payload and beaconed out, which blind/reflected scanning alone
        can never prove.  Injections that received NO callback are NOT reported
        as findings (avoiding noise / false confidence).

        Phase 46 (pentest-readiness): real blind payloads often fire only
        when an admin views a page MINUTES or HOURS after injection -- a
        fixed 12-second window silently missed all of them.  Now:

        * ``timeout`` defaults to ``scanner.oob_timeout`` (CLI
          ``--oob-timeout``; raise it for realistic blind windows).
        * Un-confirmed injections are RETAINED in ``_oob_pending`` instead
          of being dropped.
        * With ``oob_keep_listening`` set (CLI ``--oob-keep-listening``)
          the listener is NOT stopped and retained injections stay armed:
          a follow-up ``collect_oob()`` (longer --oob-timeout, or the same
          call from a wrapper script hours later) still attributes late
          beacons.
        """
        if not self.oob:
            return
        timeout = float(timeout if timeout is not None
                        else getattr(self, "oob_timeout", 12))
        expected = {p["token"] for p in self._oob_pending}
        received: set = set()
        try:
            received = self.oob.poll(expected, timeout=timeout) or set()
        except Exception as e:
            _log.warning("OOB poll failed: %s", e, exc_info=self.verbose)
        with self._lock:
            pending = list(self._oob_pending)
            self._oob_pending = []
        confirmed = {t for t in received if t in expected}
        by_token = {p["token"]: p for p in pending}
        for tok in confirmed:
            p = by_token.get(tok)
            if not p:
                continue
            self._add(Finding(**{
                "url": p["url"], "method": p["method"], "param": p["param"],
                "type": "blind", "context": "blind_oob",
                "payload": p["payload"], "transform": [],
                "severity": "high", "confidence": "high",
                "detail": (f"Blind XSS CONFIRMED via out-of-band callback. The "
                           f"injected payload beaconed to the callback host "
                           f"('{self.oob.name}'); a victim's browser executed it, "
                           f"proving the input renders in an executable context "
                           f"(classic blind/stored flow)."),
                "headless": None,
                "proof": {"callback": self.oob.callback_url(tok)},
            }))
        unconfirmed = [p for p in pending if p["token"] not in confirmed]
        if getattr(self, "oob_keep_listening", False):
            # Retain late-arriving candidates: keep the listener alive and
            # re-arm only the injections that have not beaconed yet.
            with self._lock:
                self._oob_pending.extend(unconfirmed)
            if unconfirmed:
                _log.info("[*] blind: %d payload(s) still armed -- the "
                          "listener stays up; run a follow-up collect (or a "
                          "longer --oob-timeout) to attribute late callbacks",
                          len(unconfirmed))
        elif unconfirmed and self.verbose:
            _log.debug(f"[*] blind: {len(unconfirmed)} OOB payload(s) never "
                       f"beaconed within {timeout}s")
        if self.verbose:
            if confirmed:
                _log.debug(f"[+] blind: {len(confirmed)} OOB callback(s) received -> "
                      f"confirmed")
            else:
                _log.debug(f"[*] blind: {len(pending)} OOB payload(s) injected, "
                      f"no callback received within {timeout}s")
        if not getattr(self, "oob_keep_listening", False):
            try:
                self.oob.stop()
            except Exception as e:
                if self.verbose:
                    _log.debug(f"    [!] OOB listener stop error: {e}")
            self._oob_started = False

    # -- DOM layer ---------------------------------------------------------

