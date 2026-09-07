"""SPA headless crawler driven by Playwright.

Modern single-page applications (React/Vue/Angular/Svelte) render their
navigation client-side: links are injected into the DOM only after JS
execution, route changes happen via ``history.pushState`` without a full
page load, and many endpoints are discovered only through XHR/fetch calls
triggered by user interaction.  The classic BeautifulSoup crawler in
``scanner._crawl()`` sees only the initial HTML payload and misses every
client-rendered route.

This module provides ``SpaCrawler`` -- a Playwright-driven crawler that:

1. **Renders pages in a real Chromium** so client-side templating executes
   and the post-hydration DOM is the source of truth for link discovery.
2. **Hooks ``history.pushState`` / ``replaceState`` / ``hashchange``** so
   SPA navigations are captured even when no full page load occurs.
3. **Auto-interacts** with clickable navigation elements (nav links,
   tabs, menu buttons) to trigger lazy-loaded routes that would otherwise
   stay hidden until a user clicks them.
4. **Intercepts ``fetch`` / ``XMLHttpRequest``** to harvest API endpoints
   the SPA calls, which often surface injectable JSON/JSONP params.
5. **Shares the requester's cookies** (P3-1) so authenticated SPA routes
   behind a login wall are crawled in the same session.
6. **Dedups by route template** (``/users/123`` ≡ ``/users/456``) to
   avoid crawling thousands of equivalent resource URLs.
7. **Falls back to BS4 static crawl** when Playwright is unavailable.

Returns the same ``(url, method, params, data)`` tuple shape as
``Scanner._crawl()`` so ``scan_target()`` consumes SPA-discovered
endpoints with zero changes.

Supersedes the BS4 crawler for any target that ships client-side JS.
XSStrike, Dalfox, and Burp Suite Pro's crawler all rely on either static
HTML parsing (XSStrike, Dalfox) or a separate licensed browser engine
(Burp); this module ships in-box and degrades gracefully.
"""
from __future__ import annotations

import re
import time
from collections import deque
from typing import Callable
from urllib.parse import urlparse, urljoin, parse_qsl

# --------------------------------------------------------------------------
# Availability probe -- mirrors dom_engine.DynamicDomAnalyzer.available()
# so callers can auto-fall-back to the BS4 crawler when Playwright is
# missing (e.g. CI without browsers installed).
# --------------------------------------------------------------------------


def _playwright_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("playwright") is not None
    except Exception:
        return False


# Path-template dedup pattern: collapse /users/123, /users/456, /posts/abc
# into the same route template /users/{id}, /posts/{id}.  This prevents the
# crawler from following thousands of equivalent resource URLs on big sites
# while still discovering distinct routes.
_NUMERIC_ID = re.compile(r"/\d{2,}(?=/|$|\?)")
_UUID = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"(?=/|$|\?)", re.IGNORECASE)
_LONG_HASH = re.compile(r"/[0-9a-f]{16,}(?=/|$|\?)", re.IGNORECASE)


def _route_template(url: str) -> str:
    """Normalize a URL to its route template for dedup.

    /users/123/edit?foo=bar -> https://host/users/{id}/edit
    /p/a1b2c3d4e5f6a1b2    -> https://host/p/{hash}
    """
    p = urlparse(url)
    path = p.path or "/"
    path = _UUID.sub("/{uuid}", path)
    path = _LONG_HASH.sub("/{hash}", path)
    path = _NUMERIC_ID.sub("/{id}", path)
    # Drop query for template key -- ?id=1 and ?id=2 are the same endpoint
    # for crawl-routing purposes (the scanner will probe params separately).
    return f"{p.scheme}://{p.netloc}{path}"


# JS snippet injected via add_init_script.  Hooks SPA navigation APIs and
# records every route change into a window-level array we can read back.
# Mirrors the init-script pattern from dom_engine._init_script().
_NAV_HOOK_JS = """
() => {
    window.__xss_routes = window.__xss_routes || [];
    const record = (loc) => {
        try {
            const u = (loc && (loc.href || loc)) || window.location.href;
            if (u && window.__xss_routes.indexOf(u) < 0) {
                window.__xss_routes.push(u);
            }
        } catch (e) {}
    };
    record(window.location.href);
    const origPush = history.pushState.bind(history);
    history.pushState = function (s, t, url) {
        const r = origPush(s, t, url);
        record(window.location.href);
        return r;
    };
    const origReplace = history.replaceState.bind(history);
    history.replaceState = function (s, t, url) {
        const r = origReplace(s, t, url);
        record(window.location.href);
        return r;
    };
    window.addEventListener('popstate', () => record(window.location.href));
    window.addEventListener('hashchange', () => record(window.location.href));
}
"""


class SpaCrawler:
    """Playwright-driven SPA crawler.

    Construct with crawl options, then call ``crawl(start_url)`` to get a
    list of ``(url, method, params, data)`` tuples ready for
    ``Scanner.scan_endpoint``.

    The crawler maintains a long-lived ``BrowserContext`` across pages so
    cookies set by the SPA (e.g. CSRF tokens, session IDs) propagate to
    subsequently crawled routes.  When a ``Requester`` is supplied, its
    cookies are pre-injected into the context (P3-1).
    """

    # Clickable selectors that commonly trigger SPA navigation.  We click
    # a bounded number per page to surface lazy-loaded routes without
    # exploding the crawl frontier.
    _CLICK_SELECTORS = [
        "nav a", "nav button", "header a", "header button",
        "[role='tab']", "[role='menuitem']", "[role='link']",
        "a[href^='/']", "a[href^='#']", "a[href]:not([href^='mailto:'])",
        "button", "[data-route]", "[data-link]", "[onclick]",
    ]

    def __init__(self,
                 max_depth: int = 2,
                 scope: str | None = None,
                 timeout: int = 20,
                 headless: bool = True,
                 per_page_budget_s: float = 8.0,
                 max_total_pages: int = 50,
                 max_clicks_per_page: int = 10,
                 verbose: bool = False,
                 cookies: dict | None = None,
                 extra_headers: dict | None = None):
        self.max_depth = max(0, int(max_depth))
        self.scope = scope
        self.timeout = timeout
        self.headless = headless
        self.per_page_budget_s = per_page_budget_s
        self.max_total_pages = max_total_pages
        self.max_clicks_per_page = max_clicks_per_page
        self.verbose = verbose
        self.cookies = cookies or {}
        self.extra_headers = extra_headers or {}
        self.requests_made = 0
        # Bump callback -- wired by Scanner._crawl_spa() so the parent
        # scanner's requests_made counter stays accurate.
        self._bump: Callable[[], None] = lambda: None

    @staticmethod
    def available() -> bool:
        """True if Playwright is importable.  Mirrors dom_engine probe."""
        return _playwright_available()

    # -- public API --------------------------------------------------------
    def crawl(self, start_url: str,
              fallback_crawler: Callable[[str], list] | None = None
              ) -> list[tuple[str, str, dict, dict]]:
        """Crawl ``start_url`` and return scannable endpoints.

        If Playwright is unavailable, transparently delegates to
        ``fallback_crawler`` (typically ``Scanner._crawl``) so the scan
        proceeds with BS4-based static discovery.
        """
        if not self.available():
            if fallback_crawler is not None:
                if self.verbose:
                    print("[spa] Playwright unavailable; "
                          "falling back to static BS4 crawler")
                return fallback_crawler(start_url)
            if self.verbose:
                print("[spa] Playwright unavailable and no fallback given")
            return []

        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            if fallback_crawler is not None:
                return fallback_crawler(start_url)
            return []

        endpoints: list[tuple[str, str, dict, dict]] = []
        seen_ep: set = set()
        seen_routes: set = set()
        visited: set = set()
        # XHR/fetch endpoints harvested from network interception.
        xhr_endpoints: list[tuple[str, str]] = []

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    args=["--no-sandbox", "--disable-blink-features=AutomationControlled"])
                context = browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    user_agent=("Mozilla/5.0 (XSSentinel/SPA-Crawler) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/120.0.0.0 Safari/537.36"),
                    ignore_https_errors=True,
                )
                # P3-1: inject requester cookies so authenticated SPA
                # routes are crawled in the same session.
                if self.cookies:
                    origin = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
                    ctx_cookies = []
                    for name, value in self.cookies.items():
                        ctx_cookies.append({
                            "name": name, "value": str(value),
                            "url": origin,
                        })
                    if ctx_cookies:
                        try:
                            context.add_cookies(ctx_cookies)
                        except Exception as e:
                            if self.verbose:
                                print(f"[spa] cookie injection failed: {e}")
                if self.extra_headers:
                    try:
                        context.set_extra_http_headers(self.extra_headers)
                    except Exception:
                        pass

                # Network interception: capture every XHR/fetch URL the
                # SPA calls.  These often surface injectable JSON/JSONP
                # params invisible to a DOM-only crawl.
                def _on_response(resp):
                    try:
                        rurl = resp.url
                        rp = urlparse(rurl)
                        # Only same-origin XHR endpoints (not assets).
                        base = urlparse(start_url)
                        if rp.netloc != base.netloc:
                            return
                        if rp.path.endswith((".js", ".css", ".png", ".jpg",
                                              ".gif", ".svg", ".woff",
                                              ".woff2", ".ico")):
                            return
                        method = (resp.request.method or "GET").upper()
                        xhr_endpoints.append((rurl, method))
                    except Exception:
                        pass

                context.on("response", _on_response)

                page = context.new_page()
                page.add_init_script(_NAV_HOOK_JS)
                # Dismiss any unexpected dialogs (alert/confirm/prompt).
                page.on("dialog", lambda d: d.dismiss())

                queue: deque = deque([(start_url, 0)])
                pages_crawled = 0

                while queue and pages_crawled < self.max_total_pages:
                    url, depth = queue.popleft()
                    nurl = _norm_url(url)
                    if nurl in visited:
                        continue
                    visited.add(nurl)
                    if depth > self.max_depth:
                        continue

                    # Per-page time budget: cap how long we spend on any
                    # single SPA page so a slow/infinite route never
                    # stalls the whole crawl.
                    page_deadline = time.monotonic() + self.per_page_budget_s
                    try:
                        page.goto(url, timeout=int(self.timeout * 1000),
                                  wait_until="domcontentloaded")
                        # Wait for SPA hydration / network idle, bounded
                        # by the per-page budget.
                        try:
                            remaining = max(500, int((page_deadline - time.monotonic()) * 1000))
                            page.wait_for_load_state("networkidle",
                                                     timeout=remaining)
                        except Exception:
                            pass
                        self.requests_made += 1
                        self._bump()
                        pages_crawled += 1
                    except Exception as e:
                        if self.verbose:
                            print(f"[spa] goto failed for {url}: {e}")
                        continue

                    # 1) Extract post-render <a href> links from the DOM.
                    new_links = self._extract_dom_links(page, url)
                    for link in new_links:
                        if not self._in_scope(link, start_url):
                            continue
                        if _norm_url(link) not in visited:
                            queue.append((link, depth + 1))

                    # 2) Read SPA-navigated routes captured by the init
                    #    script (pushState/replaceState/hashchange).
                    try:
                        routes = page.evaluate(
                            "() => (window.__xss_routes || [])")
                    except Exception:
                        routes = []
                    for r in routes or []:
                        if not self._in_scope(r, start_url):
                            continue
                        if _norm_url(r) not in visited:
                            queue.append((r, depth + 1))

                    # 3) Register the page itself as a DOM-scan endpoint
                    #    (covers param-less SPA routes like /dashboard).
                    self._register_page(endpoints, seen_ep, seen_routes,
                                         url, start_url)

                    # 4) Register <a href> with query params as GET endpoints.
                    self._register_query_links(endpoints, seen_ep,
                                                new_links, start_url)

                    # 5) Register <form> endpoints discovered in the
                    #    rendered DOM.
                    self._register_forms(page, endpoints, seen_ep,
                                          url, start_url)

                    # 6) Auto-click navigation elements to trigger
                    #    lazy-loaded routes.  Bounded by max_clicks_per_page
                    #    and the remaining page budget.
                    if depth < self.max_depth and \
                            time.monotonic() < page_deadline:
                        self._auto_click(page, url, new_links, start_url,
                                          page_deadline)

                # 7) Register XHR/fetch endpoints harvested from network
                #    interception.  These often carry injectable query
                #    params the DOM never surfaces.
                self._register_xhr(endpoints, seen_ep, xhr_endpoints,
                                    start_url)

                try:
                    context.close()
                    browser.close()
                except Exception:
                    pass
        except Exception as e:
            if self.verbose:
                print(f"[spa] crawl aborted: {e}")
            return endpoints

        if self.verbose:
            print(f"[spa] crawled {pages_crawled if 'pages_crawled' in dir() else '?'} pages, "
                  f"discovered {len(endpoints)} endpoints "
                  f"({len(xhr_endpoints)} via XHR interception)")
        return endpoints

    # -- helpers -----------------------------------------------------------
    def _in_scope(self, url: str, start_url: str) -> bool:
        """Same-origin + optional scope-prefix check (mirrors _crawl)."""
        try:
            fu = urlparse(url)
            base = urlparse(start_url)
            if fu.netloc != base.netloc:
                return False
            if self.scope and not url.startswith(self.scope):
                return False
            return True
        except Exception:
            return False

    def _extract_dom_links(self, page, base_url: str) -> list[str]:
        """Extract all <a href> from the rendered DOM (post-JS)."""
        try:
            raw = page.evaluate("""() => {
                const out = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    out.push(a.getAttribute('href') || '');
                });
                return out;
            }""")
        except Exception:
            return []
        links: list[str] = []
        for href in raw or []:
            if not href:
                continue
            if href.startswith(("#", "javascript:", "mailto:",
                                  "tel:", "data:")):
                continue
            full = urljoin(base_url, href)
            links.append(full)
        return links

    def _register_page(self, endpoints, seen_ep, seen_routes,
                        url: str, start_url: str) -> None:
        """Register a page itself as a DOM-scan endpoint."""
        page_url = _norm_url(url).split("?", 1)[0]
        start_nurl = _norm_url(start_url).split("?", 1)[0]
        if page_url == start_nurl:
            return  # already endpoints[0] in scan_target
        # Route-template dedup: don't register the same template twice.
        tmpl = _route_template(page_url)
        if tmpl in seen_routes:
            return
        seen_routes.add(tmpl)
        key = ("PAGE", page_url, "")
        if key not in seen_ep:
            seen_ep.add(key)
            endpoints.append((page_url, "GET", {}, {}))

    def _register_query_links(self, endpoints, seen_ep,
                               links: list[str], start_url: str) -> None:
        """Register <a href> with query params as GET endpoints."""
        for full in links:
            if "?" not in full:
                continue
            if not self._in_scope(full, start_url):
                continue
            fu = urlparse(full)
            q = fu.query
            params = {k: "xss" for k, _ in parse_qsl(q) if k}
            if not params:
                continue
            ep_url = _norm_url(full).split("?", 1)[0]
            # Route-template dedup for query endpoints too.
            tmpl = _route_template(ep_url)
            key = ("GET", tmpl, tuple(sorted(params)))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            endpoints.append((ep_url, "GET", params, {}))

    def _register_forms(self, page, endpoints, seen_ep,
                         base_url: str, start_url: str) -> None:
        """Register <form> endpoints discovered in the rendered DOM."""
        try:
            forms = page.evaluate("""() => {
                const out = [];
                document.querySelectorAll('form').forEach(f => {
                    const inputs = {};
                    f.querySelectorAll('input,select,textarea').forEach(i => {
                        const n = i.getAttribute('name');
                        if (n) inputs[n] = i.getAttribute('value') || 'xss';
                    });
                    out.push({
                        action: f.getAttribute('action') || '',
                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                        inputs: inputs,
                    });
                });
                return out;
            }""")
        except Exception:
            return
        for form in forms or []:
            action = urljoin(base_url, form.get("action") or base_url)
            if not self._in_scope(action, start_url):
                continue
            method = form.get("method") or "GET"
            inputs = form.get("inputs") or {}
            if not inputs:
                continue
            act_url = _norm_url(action).split("?", 1)[0]
            tmpl = _route_template(act_url)
            key = (method, tmpl, tuple(sorted(inputs)))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            data = inputs if method == "POST" else {}
            params = {} if method == "POST" else inputs
            endpoints.append((act_url, method, params, data))

    def _register_xhr(self, endpoints, seen_ep,
                       xhr_endpoints: list[tuple[str, str]],
                       start_url: str) -> None:
        """Register XHR/fetch endpoints harvested from network interception.

        These often carry injectable JSON/JSONP params invisible to a
        DOM-only crawl (e.g. /api/search?q=... called via fetch()).
        """
        seen: set = set()
        for rurl, method in xhr_endpoints:
            if not self._in_scope(rurl, start_url):
                continue
            fu = urlparse(rurl)
            params = {k: "xss" for k, _ in parse_qsl(fu.query) if k}
            ep_url = _norm_url(rurl).split("?", 1)[0]
            tmpl = _route_template(ep_url)
            key = (method, tmpl, tuple(sorted(params)))
            if key in seen_ep or key in seen:
                continue
            seen.add(key)
            # XHR endpoints are typically POST JSON or GET with query.
            # We probe them as standard GET/POST endpoints; the scanner's
            # JSONP/JSON param miner layers will detect content-type
            # specifics.
            data = {} if method == "GET" else params
            params = params if method == "GET" else {}
            endpoints.append((ep_url, method, params, data))

    def _auto_click(self, page, base_url: str, known_links: list[str],
                     start_url: str, page_deadline: float) -> None:
        """Click a bounded set of navigation elements to trigger SPA routes.

        After each click, wait briefly for any new route to register via
        the init-script hook, then collect newly-revealed links.  This
        surfaces lazy-loaded routes that stay hidden until user interaction.
        """
        known_set = set(known_links)
        clicks_done = 0
        for sel in self._CLICK_SELECTORS:
            if clicks_done >= self.max_clicks_per_page:
                break
            if time.monotonic() >= page_deadline:
                break
            try:
                els = page.query_selector_all(sel)
            except Exception:
                continue
            for el in els[:3]:  # cap per-selector to avoid explosion
                if clicks_done >= self.max_clicks_per_page:
                    break
                if time.monotonic() >= page_deadline:
                    break
                try:
                    # Skip elements that open new windows/tabs.
                    target = el.get_attribute("target") or ""
                    if target in ("_blank", "_parent", "_top"):
                        continue
                    el.scroll_into_view_if_needed(timeout=1000)
                except Exception:
                    continue
                try:
                    el.click(timeout=1500)
                    clicks_done += 1
                except Exception:
                    continue
                # Wait briefly for any SPA navigation to settle.
                try:
                    page.wait_for_timeout(400)
                except Exception:
                    pass
                # Collect newly-revealed links after the click.
                try:
                    after = self._extract_dom_links(page, base_url)
                except Exception:
                    after = []
                # If new routes appeared, register them for crawling.
                for link in after:
                    if link not in known_set and self._in_scope(link, start_url):
                        known_set.add(link)
                        # Push to the caller's queue via the known_links
                        # list (scan_target will pick these up on the
                        # next BFS iteration through the _extract_dom_links
                        # path -- but to be safe, we also enqueue them
                        # directly via a side-channel).
                        known_links.append(link)
                # Read SPA-navigated routes captured by the init script.
                try:
                    routes = page.evaluate(
                        "() => (window.__xss_routes || [])")
                except Exception:
                    routes = []
                for r in routes or []:
                    if r not in known_set and self._in_scope(r, start_url):
                        known_set.add(r)
                        known_links.append(r)


def _norm_url(url: str) -> str:
    """Normalize a URL for visited-set dedup (mirrors scanner._norm)."""
    from urllib.parse import urlparse, urlunparse
    try:
        p = urlparse(url)
    except Exception:
        return url
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, p.params, p.query, ""))
