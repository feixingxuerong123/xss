"""Stored (L4) + blind/OOB (L5) scanning methods, as a Scanner mixin.

Phase 40 split: methods moved verbatim from scanner.py.  Requires the
host Scanner to provide: req/_add/_bump/_lock/_oob_pending/_oob_started,
coverage, max_transforms/max_payloads, verbose, findings.
"""
from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING

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
from .findings import (EVIDENCE_OOB, Finding, _DEFAULT_TRANSFORMS,
                       _grade_evidence, _norm, _proof, _safe_snippet)
from .logger import get_logger

if TYPE_CHECKING:  # only ever referenced inside annotations
    from .requester import Requester

_log = get_logger("scanner.mixins")

# Phase 156: the per-probe token, used to normalise a variant for dedupe
# (the token itself is unique per payload, so it must not take part in the
# equality test).
_TOKEN_RE = re.compile(r"xssv_[0-9a-f]{8}")



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
        # NOTE (Phase 156, deliberately NOT changed): the four context
        # corpora are capped at max_payloads, but the html_element
        # polyglots are appended on top of that cap -- 14 + 35 = 49 bases
        # at the default knob, i.e. ``--max-payloads 14`` buys 49 payloads
        # here.  Making the knob honest would cut the polyglot tail from 35
        # to a handful, which IS a detection-breadth change (polyglots are
        # the shapes that survive sanitisers), so it is left to an explicit
        # decision instead of being smuggled into a speed pass.  Measured
        # cost of the status quo: 588 (payload x transform) pairs, of which
        # 238 survive -- see the two filters below.
        bases = (payloads.by_context("html_element")
                 + payloads.by_context("script_block")
                 + payloads.by_context("event_handler")
                 + payloads.by_context("svg_context"))[:self.max_payloads]
        bases += [p for p in payloads.all_polyglots()
                  if "html_element" in p.get("contexts", [])]
        # Phase 156: skip pairs that prove nothing new.  Measured on
        # benchmark neg-stored-01 (49 payloads x 12 transform sets):
        #
        #   * 60% of pairs (350/588) mangle the token through a transform,
        #     which makes them UNCONFIRMABLE -- verify_semantic() matches
        #     the token with a plain str.find;
        #   * 14% are the same string once verifier.mark() has normalised
        #     the alert() argument, i.e. the same test twice.
        #
        # Both filters are verdict-neutral: a pair that cannot confirm only
        # ever returns "not confirmed".  Cost went 1176 -> 400 requests.
        seen_variants: set = set()
        for base in bases:
            token = "xssv_" + secrets.token_hex(4)
            marked = verifier.mark(base["payload"], token)
            for tset in _DEFAULT_TRANSFORMS[:self.max_transforms]:
                variant = marked
                for t in tset:
                    variant = transform.apply(t, variant)
                # A transform that rewrites the token (url/hex encoding,
                # case flips, ...) makes this pair UNCONFIRMABLE --
                # verify_semantic() matches the token with a plain substring
                # search, so a mangled token can never be found in the view
                # page.  scan_stored_dom already carried this guard;
                # scan_stored did not.
                if token not in variant:
                    continue
                # Dedupe on what is actually SENT, with the token
                # normalised out: two corpus entries that differ only in
                # their alert() argument are the same probe.
                key = _TOKEN_RE.sub("TOKEN", variant)
                if key in seen_variants:
                    continue
                seen_variants.add(key)
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
                    # Read UNCACHED, and not only via `req.invalidate` above:
                    # with `--stored-fresh-session` the page is fetched through a
                    # DIFFERENT Requester (line ~77), and `Requester.invalidate`
                    # only clears the caller's own cache (requester.py:352-361).
                    # So from the second variant onward the viewer was served its
                    # own cached copy of the page as it looked after variant 1 --
                    # `verify_semantic` then could not find the newer token, and
                    # the whole stored pass could report "not stored" having
                    # really tested one payload out of ~n.
                    vresp = view_req.get(view_url, cache_get=False)
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
                    # `verify_semantic` proves the token landed in an EXECUTABLE
                    # CONTEXT on the viewer page.  Nothing in this path ran a
                    # browser, so the old wording ("persisted and executed")
                    # claimed more than was observed -- and the tier attached
                    # below says plainly that execution is unverified.
                    _d0 = (f"payload persisted and rendered in an executable "
                           f"context in {view_url} ({v['detail']}; {note})")
                    _cls, _conf, _det = _grade_evidence(None, confidence, _d0)
                    self._add(Finding(**{
                        "url": inject_url, "method": method, "param": param,
                        "type": "stored", "context": "stored_view",
                        "payload": variant, "transform": tset,
                        "severity": "high", "confidence": _conf,
                        "detail": _det,
                        "evidence_class": _cls,
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

    # -- L4 stored XSS, DOM-verified (SPA shape) ---------------------------

    def scan_stored_dom(self, inject_url: str, view_url: str | None = None,
                        param: str = "q", json_body: bool = False,
                        extra_fields: dict | None = None):
        """Phase 152: stored XSS verified by the REAL BROWSER (SPA shape).

        ``scan_stored`` verifies persistence by looking for the token in the
        VIEW PAGE'S HTTP TEXT.  On a modern SPA that can never confirm: the
        stored value is fetched client-side (XHR) and inserted by framework
        code, so the server-rendered view HTML does not contain it (measured
        on OWASP Juice Shop: a payload stored via ``POST /api/Feedbacks``
        renders only inside the authenticated ``/#/administration`` route).

        This method submits marker-carrying write payloads -- form-encoded
        AND, unless ``json_body`` narrows it, a JSON body (SPA write
        endpoints are JSON; classic guestbooks are form) -- then renders the
        view page in the instrumented real browser.  The DOM engine's sink
        hooks report any flow of the token into an executable sink
        (innerHTML / outerHTML / document.write / ...), which is the same
        marker discipline as URL probing with the marker carried by the
        STORED payload instead of the URL.  ``extra_fields`` carries the
        companion fields real write APIs demand (register/profile
        endpoints want password, captcha, csrf, ...).  Auth state (cookies,
        headers,
        localStorage) is the scanner's configured browser session, so
        authenticated view routes render exactly as a victim sees them.

        Confidence mirrors ``scan_stored``: an explicit ``view_url`` is
        high; a self-view (view == inject) is medium.
        """
        view_url = view_url or inject_url
        explicit_view = view_url != inject_url or inject_url.rstrip(
            "/").endswith("/view")
        engine = self._resolve_dom_engine()
        if engine is None or not engine.available():
            _log.debug("stored-dom: real browser unavailable -- cannot "
                       "verify %s", inject_url)
            return False
        self.coverage.touch_layer(
            inject_url, "L4_stored_dom", "POST",
            detail=f"inject->{view_url} param='{param}' "
                   f"({'json' if json_body else 'form+json'})")

        bases: list = []
        for ctx_name in ("html_element", "svg_context"):
            for base in payloads.by_context(ctx_name):
                bases.append(base)
                if len(bases) >= 3:
                    break
            if len(bases) >= 3:
                break
        encodings = ("json",) if json_body else ("form", "json")
        for base in bases:
            token = "xssv_" + secrets.token_hex(4)
            variant = verifier.mark(base["payload"], token)
            if token not in variant:
                # mark() rewrites alert(...) args; a payload without one
                # would store a token-free string the hooks can never see.
                continue
            stored = False
            # Companion fields real write APIs demand (register/profile
            # endpoints want password, captcha, csrf, ...).  The payload
            # always rides in ``param``; companions are constant per scan.
            body: dict = dict(extra_fields or {})
            body[param] = variant
            for enc in encodings:
                try:
                    if enc == "json":
                        req2 = self.req.request("POST", inject_url,
                                                json=body)
                    else:
                        req2 = self.req.request("POST", inject_url,
                                                data=body)
                    self._bump()
                    stored = stored or (req2 is not None)
                except Exception:
                    continue
            if not stored:
                continue
            if hasattr(self.req, "invalidate"):
                self.req.invalidate(view_url)
            try:
                hits = engine.analyze(view_url, marker=token)
            except Exception as e:  # noqa: BLE001
                _log.debug("stored-dom: browser analyze failed (%s)", e,
                           exc_info=self.verbose)
                continue
            if hits:
                sinks = ", ".join(sorted({h.get("sink", "") for h in hits
                                          if isinstance(h, dict)})[:3])
                if not explicit_view and view_url == inject_url:
                    confidence = "medium"
                    note = ("same-session self-view: persistence for other "
                            "viewers is NOT proven -- re-run with an "
                            "explicit --stored-view")
                else:
                    confidence = "high"
                    note = "view page rendered the stored payload in a real browser"
                # The DOM engine ran a real browser and the marker reached an
                # executable sink, so this finding DOES have browser-grade
                # proof.  It used to be filed with `headless: None`, which would
                # have graded as "never checked" -- the opposite of the truth.
                _h = {"available": True, "confirmed": True, "outcome": "fired",
                      "detail": f"dom engine: marker reached sink(s) {sinks}"}
                _cls, _conf, _det = _grade_evidence(_h, confidence, (
                    f"stored payload rendered client-side and "
                    f"reached executable sink(s) [{sinks}] on "
                    f"{view_url} ({note})"))
                # Execution and persistence are different claims.  A browser
                # firing the marker proves the first; the self-view case above
                # has NOT proved it renders for other visitors, and that is what
                # this site's confidence number is about -- so the grade may
                # state the tier, but it may not raise this confidence.
                _conf = confidence
                self._add(Finding(**{
                    "url": inject_url, "method": "POST", "param": param,
                    "type": "stored_dom", "context": "stored_dom_view",
                    "payload": variant, "transform": [],
                    "severity": "high", "confidence": _conf,
                    "detail": _det,
                    "evidence_class": _cls,
                    "headless": _h,
                    "proof": {"view_url": view_url, "token": token,
                              "sinks": sinks,
                              "snippets": [str(h.get("snippet", ""))[:200]
                                           for h in hits[:3]]},
                }))
                return True
        return False

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
            # second_order confirms with `verify_semantic` (nonce token landed
            # in an executable context on the viewer page), NOT with a browser
            # that ran it -- so "executed at" here used to claim an observation
            # nobody made.
            _cls, _conf, _det = _grade_evidence(None, "high", (
                f"payload injected at {r['inject_url']} "
                f"({r['inject_method']} {r['inject_param']}) "
                f"rendered in an executable context at {r['viewer_url']} "
                f"({r['detail']})"))
            self._add(Finding(**{
                "url": r["inject_url"], "method": r["inject_method"],
                "param": r["inject_param"],
                "type": "second_order", "context": r["context"],
                "payload": r["payload"], "transform": [],
                "severity": "high", "confidence": _conf,
                "detail": _det,
                "evidence_class": _cls,
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
                # A beacon arriving at the callback host is execution proof,
                # observed out-of-band.  `headless: None` above only means the
                # dialog hook never looked; grading it as "no browser check"
                # would understate the strongest channel this tool has.
                "evidence_class": EVIDENCE_OOB,
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

