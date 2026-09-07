"""HTTP requester with session, proxy, header, and rate-limit support.

Phase 21-3: includes an optional GET response cache to avoid re-fetching
the same URL multiple times during a scan (e.g. the crawl pass and the
DOM-analysis pass both GET the same page).  The cache is:
  * Bounded (LRU, default 64 entries) to cap memory.
  * Thread-safe (guarded by a lock).
  * GET-only (POST/PUT are never cached -- not idempotent).
  * Disabled when params differ (only caches the bare URL fetch).
  * Opt-out via ``cache_get=False`` for cases where freshness matters.
"""
from __future__ import annotations

import time
import threading
from collections import OrderedDict

import requests

from .budget import Budget, BudgetExhausted, CircuitOpen, CircuitBreaker  # noqa: F401 (re-exported)
from .stealth import HeaderRotator, ProxyPool, jitter_interval, load_proxies  # noqa: F401 (re-exported)

# Phase 46: the previous default UA contained an "XSSentinel/1.0" token,
# fingerprinting every scan in SIEM/WAF logs (pentest audit P0).  The
# default is now a plain, current Chrome UA; --user-agent / --random-agent
# override it, and an explicit -H "User-Agent: ..." still wins.
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 "
                  "Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


class RateLimiter:
    """Thread-safe token-bucket rate limiter.

    ``rate`` = max requests per second (0 = unlimited).  When the bucket is
    empty, ``acquire()`` blocks until enough time has passed for the next
    token.  This keeps the scanner polite on sensitive targets.
    """

    def __init__(self, rate: float = 0, jitter: float = 0.0):
        self.rate = max(0.0, float(rate))
        # Phase 51: jitter = +/- fraction of the interval (0 = fixed
        # cadence, the pre-Phase-51 behaviour).  A metronomic request
        # stream is itself a WAF/SIEM fingerprint.
        self.jitter = max(0.0, min(1.0, float(jitter or 0.0)))
        self._min_interval = 1.0 / self.rate if self.rate > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                time.sleep(jitter_interval(wait, self.jitter))
            self._last = time.monotonic()


class JsonBody(dict):
    """Marker wrapper: a dict that must be sent as an ``application/json``
    body (JSON APIs).

    The whole detection pipeline funnels body probes through
    ``req.request(..., data=probe["data"])``; when ``probe["data"]`` is a
    ``JsonBody`` the Requester switches to ``json=`` (and the matching
    Content-Type) automatically -- no detection layer needs to know the
    body carrier.
    """


class Requester:
    def __init__(self, timeout: int = 15, proxy: str | None = None,
                 headers: dict | None = None, cookies: dict | None = None,
                 verify_ssl: bool = True, max_retries: int = 2,
                 rate_limit: float = 0, cache_size: int = 64,
                 budget: "Budget | None" = None,
                 breaker: "CircuitBreaker | None" = None,
                 proxy_pool: list | None = None,
                 rotate_headers: bool = False,
                 jitter: float = 0.0):
        self.timeout = timeout
        self.rate_limiter = RateLimiter(rate_limit, jitter=jitter)
        # Phase 46: optional shared request budget.  Every REAL network call
        # spends one unit; BudgetExhausted propagates to the scan loop which
        # stops gracefully.  Clones share the same Budget instance.
        self.budget = budget
        # Phase 46: optional circuit breaker -- consecutive 5xx/429 responses
        # trip it and every subsequent request raises CircuitOpen, so the
        # scan stops instead of hammering a dead/blocking target.  Clones
        # share the same breaker instance.
        self.breaker = breaker
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        # Phase 51: egress rotation (--proxy-list) and per-request header
        # rotation (--rotate-headers).  Both default OFF: the previous
        # single-proxy / static-header behaviour is unchanged unless the
        # operator opts in.
        # A ProxyPool instance may be passed directly so clones can share
        # one rotation/eviction state across worker threads.
        self.proxy_pool = proxy_pool if isinstance(proxy_pool, ProxyPool) \
            else (ProxyPool(load_proxies(proxy_pool)) if proxy_pool else None)
        # The rotator is bound to the session UA (if any) so a Firefox
        # persona never sends Chrome-only Sec-CH-UA headers.
        self.header_rotator = HeaderRotator(
            self.session.headers.get("User-Agent")) if rotate_headers else None
        self.session.verify = verify_ssl
        adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        # Phase 21-3: GET response cache (LRU, bounded, thread-safe).
        # Only bare-URL GETs (no params) are cached -- param'd GETs carry
        # payloads/markers and must always hit the wire.
        self._cache_size = max(0, int(cache_size))
        self._cache: "OrderedDict[str, requests.Response]" = OrderedDict()
        self._cache_lock = threading.Lock()
        # Counters for observability (hits/misses).
        self.cache_hits = 0
        self.cache_misses = 0
        # Phase 45: optional response hook -- callable(resp, requester)
        # invoked after EVERY response.  SessionManager.attach() uses it to
        # detect a session dying MID-SCAN (401/403 or redirect-to-login) and
        # re-authenticate immediately, closing the gap where keep_alive()
        # only ran between batch URLs.
        self.on_response = None

    def _guard(self, url: str) -> None:
        """Raise CircuitOpen when the breaker has tripped (pre-send)."""
        if self.breaker is not None and self.breaker.tripped:
            raise CircuitOpen(
                f"circuit open: {self.breaker.failure_streak} recent "
                f"5xx/429 responses from the target")

    def _post_record(self, resp) -> None:
        """Feed the response status into the circuit breaker (if any)."""
        if self.breaker is not None and resp is not None:
            try:
                self.breaker.record(resp.status_code)
            except Exception:
                pass

    def _fire_hook(self, resp, method: str, url: str, params, data):
        """Run the on_response hook; return a REPLACEMENT response if the
        hook re-authenticated (it retries the request once with fresh
        credentials), else None (keep the original response)."""
        if self.on_response is None:
            return None
        try:
            return self.on_response(resp, self, method, url, params, data)
        except Exception:
            return None  # auth hooks must never break the scan

    # -- Phase 51: stealth plumbing -----------------------------------------
    def _stealth_headers(self, headers: dict | None) -> dict | None:
        """Per-request headers = rotated browser bundle + caller overrides.

        Rotation never touches Host / Content-Length / Content-Type /
        Accept-Encoding / Cookie / User-Agent, and an explicit caller header
        always wins (detection layers set their own semantics).
        """
        if self.header_rotator is None:
            return headers
        merged = self.header_rotator.next_headers()
        if headers:
            merged.update(headers)
        return merged

    def _stealth_proxies(self) -> dict | None:
        """Next proxy from the pool, or None (keep session.proxies)."""
        if self.proxy_pool is None:
            return None
        return self.proxy_pool.as_kwargs()

    def _send(self, method: str, url: str, **kw) -> requests.Response:
        """session.request() with stealth extras and dead-proxy failover.

        A dead relay inside a rotation pool would otherwise burn 1/N of
        every scan: on a proxy-level failure the entry is evicted and the
        request is retried once on the next live proxy.
        """
        proxies = self._stealth_proxies()
        if proxies is not None:
            kw["proxies"] = proxies
        try:
            return self.session.request(method, url,
                                        timeout=self.timeout, **kw)
        except (requests.exceptions.ProxyError,
                requests.exceptions.ConnectTimeout) as e:
            if self.proxy_pool is None:
                raise
            bad = kw.get("proxies") or {}
            self.proxy_pool.mark_dead(bad.get("http") or bad.get("https"))
            alt = self._stealth_proxies()
            if not alt or alt == bad:
                raise
            kw["proxies"] = alt
            return self.session.request(method, url,
                                        timeout=self.timeout, **kw)

    def get(self, url: str, params: dict | None = None,
            cache_get: bool = True,
            headers: dict | None = None) -> requests.Response:
        """GET a URL.  When ``cache_get`` is True and ``params`` is empty,
        the response is cached so subsequent bare-URL GETs to the same URL
        return the cached response without a network round-trip.

        ``headers`` are merged OVER the session headers for this request
        only (requests semantics -- per-request wins); used by upload/stored
        follow-up GETs that need to override a header without rebuilding the
        session (async-path parity).
        """
        # Cache lookup: only for bare-URL GETs (no params, no per-request
        # header override -- headers change the request semantics).
        if cache_get and self._cache_size > 0 and not params and not headers:
            with self._cache_lock:
                cached = self._cache.get(url)
                if cached is not None:
                    # Move to end (most-recently-used) for LRU.
                    self._cache.move_to_end(url)
                    self.cache_hits += 1
                    return cached
                # Phase 29-3: count misses inside the lock so the counter
                # is accurate under concurrent access.
                self.cache_misses += 1
        self.rate_limiter.acquire()
        self._guard(url)
        if self.budget is not None:
            self.budget.spend(url)
        resp = self._send("GET", url, params=params,
                          headers=self._stealth_headers(headers))
        self._post_record(resp)
        # Cache store: only successful (2xx/3xx) bare-URL GETs.
        if cache_get and self._cache_size > 0 and not params \
                and 200 <= resp.status_code < 400:
            with self._cache_lock:
                self._cache[url] = resp
                if len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)  # evict oldest (LRU)
        retried = self._fire_hook(resp, "GET", url, params, None)
        return retried if retried is not None else resp

    def post(self, url: str, data: dict | None = None,
             params: dict | None = None,
             json: dict | None = None,
             files: dict | None = None,
             headers: dict | None = None) -> requests.Response:
        self.rate_limiter.acquire()
        self._guard(url)
        if self.budget is not None:
            self.budget.spend(url)
        # JSON-carrier support (Phase 46): a JsonBody probe is sent as a
        # JSON document, never as form encoding.
        if json is None and isinstance(data, JsonBody):
            json = dict(data)
            data = None
        hdrs = self._stealth_headers(headers)
        if json is not None:
            if files:
                raise ValueError("json= and multipart files= are mutually "
                                 "exclusive")
            resp = self._send("POST", url, json=json, params=params,
                              headers=hdrs)
        elif files is not None:
            # Phase 48: multipart upload -- `files` carries the file
            # part(s); `data` rides along as the other form fields in the
            # SAME multipart body (requests does this natively).
            resp = self._send("POST", url, data=data, files=files,
                              params=params, headers=hdrs)
        else:
            resp = self._send("POST", url, data=data, params=params,
                              headers=hdrs)
        self._post_record(resp)
        retried = self._fire_hook(resp, "POST", url, params,
                                  json if json is not None else data)
        return retried if retried is not None else resp

    def request(self, method: str, url: str, params: dict | None = None,
                 data: dict | None = None,
                 json: dict | None = None,
                 files: dict | None = None,
                 headers: dict | None = None) -> requests.Response:
        """Send an arbitrary-method request.

        Phase 46: previously every non-POST method silently DROPPED the
        body (``data`` was discarded) -- JSON-API PUT/PATCH probes could
        never be sent.  Now PUT/PATCH/DELETE go through
        ``session.request`` with their body intact.
        Phase 48: ``files`` enables multipart upload bodies on any method;
        ``headers`` are merged over the session headers for this request
        only (async-path parity -- the aiohttp session always accepted
        per-request headers while the sync Requester silently ignored the
        kwarg, so upload_probe's ``headers=`` raised TypeError on every
        probe).
        """
        m = method.upper()
        if m == "POST":
            return self.post(url, data=data, params=params, json=json,
                             files=files, headers=headers)
        if m == "GET":
            return self.get(url, params=params, headers=headers)
        self.rate_limiter.acquire()
        self._guard(url)
        if self.budget is not None:
            self.budget.spend(url)
        if json is None and isinstance(data, JsonBody):
            json = dict(data)
            data = None
        hdrs = self._stealth_headers(headers)
        if json is not None:
            if files:
                raise ValueError("json= and multipart files= are mutually "
                                 "exclusive")
            resp = self._send(m, url, json=json, params=params, headers=hdrs)
        elif files is not None:
            resp = self._send(m, url, data=data, files=files,
                              params=params, headers=hdrs)
        else:
            resp = self._send(m, url, data=data, params=params, headers=hdrs)
        self._post_record(resp)
        return resp

    def invalidate(self, url: str | None = None) -> None:
        """Invalidate cached GET responses.  If ``url`` is given, evict only
        that entry; otherwise clear the entire cache.  Useful when the
        caller knows the server state has changed (e.g. after a stored-XSS
        injection)."""
        with self._cache_lock:
            if url is not None:
                self._cache.pop(url, None)
            else:
                self._cache.clear()

    def clone(self) -> "Requester":
        """Return an independent Requester with the same config. Used so each
        worker thread owns its own session (requests.Session is not guaranteed
        thread-safe for concurrent requests)."""
        # Phase 29-3: use getattr() for robustness -- get_adapter() may
        # return an adapter without a max_retries attribute in edge cases
        # (e.g. custom transport adapters injected by middleware).
        max_retries = 2
        try:
            adapter = self.session.get_adapter("http://")
            max_retries = getattr(getattr(adapter, "max_retries", None),
                                  "total", 2)
        except Exception:
            pass
        clone = Requester(timeout=self.timeout, proxy=self.session.proxies.get("http"),
                         headers=dict(self.session.headers),
                         cookies=dict(self.session.cookies),
                         verify_ssl=self.session.verify,
                         max_retries=max_retries,
                         rate_limit=self.rate_limiter.rate,
                         cache_size=self._cache_size,
                         budget=self.budget,
                         breaker=self.breaker,
                         # Phase 51: clones share the SAME ProxyPool so
                         # rotation stays global across worker threads
                         # (evicting a dead relay helps every worker), but
                         # each gets its own header rotator sequence.
                         proxy_pool=self.proxy_pool,
                         rotate_headers=bool(self.header_rotator),
                         jitter=self.rate_limiter.jitter)
        # Phase 45: worker-thread clones keep the response hook so a session
        # dying mid-scan is re-authenticated regardless of which clone saw it.
        clone.on_response = self.on_response
        return clone
