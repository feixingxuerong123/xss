"""Dynamic DOM-XSS engine (real browser, Playwright).

The static analyzer in `dom.py` *guesses* by regex-matching source->sink in the
page source.  That is heuristic: it cannot tell whether the tainted value
actually reaches the sink at runtime, and it misses compiled framework output
or dynamically-built sinks.  This module closes that gap by **executing** the
page in a real headless browser:

  1. Inject a UNIQUE marker into the attacker-controllable *source*
     (location.hash / location.search / document.cookie / postMessage).
  2. Instrument the dangerous sinks (innerHTML, document.write, eval/Function,
     location.*, jQuery .html/.append/..., setAttribute on* ..., window.open)
     with an init script that runs BEFORE the page's own scripts.
  3. When the marker actually flows into a sink, record the hit and fire
     alert(marker) so the dialog event is captured as hard proof.

A confirmed dynamic hit is high-confidence: it means attacker input truly
executed in a sink.  If Playwright is unavailable, `analyze()` returns [] and
the caller falls back to the static heuristic.

This is the "real DOM engine" upgrade over static taint analysis.
"""
from __future__ import annotations

import atexit
import re
import secrets
import threading
from .stealth import marker as _stem_marker


def _init_script(marker: str) -> str:
    """JS instrumented before page scripts: wraps sinks, records marker hits."""
    return r"""
(function(){
  var MARKER = "__MARKER__";
  window.__xss_dom_hits = [];
  function hit(sink, snippet){
    window.__xss_dom_hits.push({sink: sink, snippet: String(snippet||'').slice(0,200)});
    try { alert(MARKER); } catch(e){}
  }
  // Phase 144: do NOT require a primitive string.  Angular (Trusted Types)
  // hands the innerHTML setter a TrustedHTML wrapper -- typeof is 'object',
  // not 'string' -- so the old check answered "no marker" while the marker
  // was sitting in String(v) all along.  On such a page EVERY innerHTML
  // assignment is an object, so this silently disabled the sink for the
  // whole DOM engine.  Found on OWASP Juice Shop: the hash-routed marker
  // demonstrably reached <span id="searchValue">, the hook demonstrably
  // worked on a manual assignment, and the hit log still read zero.
  // Coercing via String() is what the browser itself does before parsing the
  // value, so a toString() match is a genuine match.
  function has(v){
    if (v == null) return false;
    if (typeof v === 'string') return v.indexOf(MARKER) !== -1;
    try { return String(v).indexOf(MARKER) !== -1; } catch(e) { return false; }
  }

  // innerHTML / outerHTML setters
  ['innerHTML','outerHTML'].forEach(function(prop){
    try {
      var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (d && d.set){
        var o = d.set;
        Object.defineProperty(Element.prototype, prop, {
          configurable: true, get: d.get,
          set: function(v){ if (has(v)) hit('Element.'+prop, v); return o.call(this, v); }
        });
      }
    } catch(e){}
  });

  // insertAdjacentHTML
  if (Element.prototype.insertAdjacentHTML){
    var oIAH = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(p, t){
      if (has(t)) hit('insertAdjacentHTML', t);
      return oIAH.call(this, p, t);
    };
  }

  // iframe.srcdoc (property assignment parses the value as a document)
  try {
    var dSD = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (dSD && dSD.set){
      var oSD = dSD.set;
      Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
        configurable: true, get: dSD.get,
        set: function(v){ if (has(v)) hit('iframe.srcdoc', v); return oSD.call(this, v); }
      });
    }
  } catch(e){}

  // document.write / writeln
  ['write','writeln'].forEach(function(m){
    if (document[m]){
      var o = document[m];
      document[m] = function(){
        for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('document.'+m, arguments[i]);
        return o.apply(document, arguments);
      };
    }
  });

  // Function constructor (covers eval-like dynamic code).
  //
  // Phase 141: a plain ``window.Function = function(){...}`` replacement is
  // NOT transparent -- it drops the constructor's own prototype/identity and,
  // critically, breaks frameworks that build their dependency-injection
  // closures with ``new Function(...)``.  Angular does exactly that, and the
  // observable symptom was brutal: the SPA never finished bootstrapping, the
  // marker never reached the page, and every probe silently "found nothing"
  // (confirmed on OWASP Juice Shop: with the override in place the marker was
  // absent from the DOM; with it removed the marker rendered normally).
  // A Proxy forwards apply/construct to the native function, so the marker is
  // still observed while page behaviour stays intact.
  try {
    var OrigFn = window.Function;
    var fnHook = function(args){
      try {
        var code = Array.prototype.map.call(args, String).join(',');
        if (has(code)) hit('Function', code);
      } catch(e){}
    };
    window.Function = new Proxy(OrigFn, {
      apply: function(t, thisArg, args){
        fnHook(args);
        return Reflect.apply(t, thisArg, args);
      },
      construct: function(t, args, newTarget){
        fnHook(args);
        return Reflect.construct(t, args, newTarget);
      }
    });
  } catch(e) { /* leave the native Function alone rather than break the page */ }

  // setTimeout / setInterval with string body
  ['setTimeout','setInterval'].forEach(function(m){
    var o = window[m];
    window[m] = function(fn, t){
      if (typeof fn === 'string' && has(fn)) hit(m, fn);
      return o.apply(this, arguments);
    };
  });

  // location.assign / replace / href / search / hash / pathname
  //
  // Phase 141: ``location`` is [Unforgeable] -- assigning to its members
  // throws a TypeError in Chrome.  Without this ``try`` the whole IIFE died
  // here, so every hook BELOW this point (window.open, setAttribute, the
  // jQuery wrappers, addEventListener/postMessage) was never installed at
  // all.  Verified with an end-of-script sentinel: before the fix the IIFE
  // never reached its last statement.
  ['assign','replace'].forEach(function(m){
    try {
      if (location[m]){
        var o = location[m];
        location[m] = function(u){ if (has(u)) hit('location.'+m, u); return o.call(location, u); };
      }
    } catch(e){}
  });
  ['href','search','hash','pathname'].forEach(function(p){
    try {
      var d = Object.getOwnPropertyDescriptor(Location.prototype, p);
      if (d && d.set){
        var o = d.set;
        Object.defineProperty(Location.prototype, p, {
          configurable: true, get: d.get,
          set: function(v){ if (has(v)) hit('location.'+p, v); return o.call(this, v); }
        });
      }
    } catch(e){}
  });

  // window.open
  var oOpen = window.open;
  window.open = function(){
    for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('window.open', arguments[i]);
    return oOpen.apply(window, arguments);
  };

  // setAttribute with on* handler value
  var oSA = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, val){
    if (typeof name === 'string' && name.toLowerCase().indexOf('on') === 0 && has(val))
      hit('setAttribute('+name+')', val);
    return oSA.call(this, name, val);
  };

  // jQuery sinks (may load after this script)
  function wrapJQ(){
    if (window.jQuery && window.jQuery.fn){
      ['html','append','prepend','after','before','replaceWith','text','attr','prop','val','load']
        .forEach(function(m){
          if (window.jQuery.fn[m]){
            var o = window.jQuery.fn[m];
            window.jQuery.fn[m] = function(){
              for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('jQuery.'+m, arguments[i]);
              return o.apply(this, arguments);
            };
          }
        });
    }
  }
  wrapJQ();
  document.addEventListener('DOMContentLoaded', wrapJQ);

  // postMessage handlers: fire a synthetic message carrying the marker
  var oAE = window.addEventListener;
  window.addEventListener = function(type, handler, opts){
    if (type === 'message' && typeof handler === 'function'){
      setTimeout(function(){
        try { handler({ data: MARKER, origin: location.origin, source: window }); } catch(e){}
      }, 50);
    }
    return oAE.call(window, type, handler, opts);
  };
})();
""".replace("__MARKER__", marker)


_CLIENT_JS_RE = re.compile(
    r"<script\b|on\w+\s*=|javascript:|addEventListener\(\s*['\"]message|"
    r"ng-app|v-html|dangerouslySetInnerHTML", re.I)


# ---------------------------------------------------------------------------
# Shared headless browser (Phase 38 / P1-6): ONE Chromium per THREAD, reused
# across analyze() and verify_headless() calls.  Launching a browser costs
# ~1-2s and the old code paid it for every single confirmation.  Instances
# are thread-local (playwright sync objects are thread-bound) and registered
# for atexit cleanup.  Callers own PAGES, never the browser: create pages
# freely and close them; do NOT close the shared browser.
# ---------------------------------------------------------------------------
_TLS = threading.local()
_ALL_BROWSERS: list[tuple] = []
_BROWSER_LOCK = threading.Lock()


def get_shared_browser():
    """Return a thread-bound, reused headless Chromium instance."""
    b = getattr(_TLS, "browser", None)
    if b is not None:
        try:
            if b.is_connected():
                return b
        except Exception:
            pass
    # Playwright's sync API runs its asyncio loop *in the calling thread*
    # (greenlet-based).  Starting it while a loop is already running here
    # corrupts that loop and breaks every later asyncio.run() in the
    # process -- refuse loudly instead; callers catch and degrade to static
    # analysis.
    if _loop_running():
        raise RuntimeError(
            "cannot start Playwright sync API: this thread already has a "
            "running event loop (would break asyncio.run() afterwards); "
            "use dom_engine='static' or run from a loop-free thread")
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    b = pw.chromium.launch(args=["--no-sandbox"])
    _TLS.pw = pw
    _TLS.browser = b
    with _BROWSER_LOCK:
        _ALL_BROWSERS.append((pw, b))
    return b


def _loop_running() -> bool:
    """True when the calling thread currently has a *running* asyncio loop."""
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def shutdown_thread_browser() -> None:
    """Stop THIS thread's shared Playwright instance, if any.

    The shared browser exists to amortize Chromium startup across scans, but
    its sync API leaves the thread's asyncio loop permanently running -- any
    later ``asyncio.run()`` in the same thread then fails with "cannot be
    called from a running event loop".  Embedders and test harnesses that
    mix sync Playwright with asyncio must call this when done with dynamic
    DOM analysis to unwind the loop.
    """
    pw = getattr(_TLS, "pw", None)
    b = getattr(_TLS, "browser", None)
    if pw is None and b is None:
        return
    with _BROWSER_LOCK:
        _ALL_BROWSERS[:] = [
            (p, br) for (p, br) in _ALL_BROWSERS if p is not pw]
    _TLS.pw = None
    _TLS.browser = None
    if b is not None:
        try:
            b.close()
        except Exception:
            pass
    if pw is not None:
        try:
            pw.stop()  # stops the greenlet-driven loop in this thread
        except Exception:
            pass


@atexit.register
def _shutdown_shared_browsers():
    """Best-effort cleanup of every thread's browser at interpreter exit."""
    with _BROWSER_LOCK:
        instances, _ALL_BROWSERS[:] = _ALL_BROWSERS[:], []
    for pw, b in instances:
        try:
            b.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass


def page_has_client_js(html: str) -> bool:
    """Quick pre-filter: only spend a browser session on pages that actually
    run client-side JS (skip plain HTML to save time)."""
    return bool(_CLIENT_JS_RE.search(html or ""))


# Upper bound on "swap a real query parameter for the marker" probes, so a
# URL with dozens of parameters cannot multiply the browser cost.
_MAX_SEARCH_PARAM_PROBES = 4

# Phase 141: how long to let a page settle after navigation before reading
# the sink log.  ``page.goto()`` returns once the load event fires, but an
# SPA renders its route *after* that -- reading immediately returns an empty
# hit log, so every probe on a client-rendered page looked like a miss.  A
# page that renders synchronously pays this once per goto probe; the default
# probe set has ~8, so the cost is bounded and only paid when the DOM engine
# is actually enabled.
_DOM_SETTLE_MS = 700


def _query_param_names(url: str) -> list:
    """Ordered, de-duplicated query parameter names of ``url``."""
    from urllib.parse import urlparse, parse_qsl
    try:
        pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return []
    names: list = []
    seen: set = set()
    for key, _value in pairs:
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _with_param_value(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``.

    Every other parameter keeps its original value so pages that branch on
    them still reach the same code path.
    """
    from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    out = [(k, value if k == name else v) for k, v in pairs]
    if not any(k == name for k, _v in pairs):
        out.append((name, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(out), ""))


# ---------------------------------------------------------------------------
# SPA hash routing (``http://h/#/search?q=1``) -- Phase 141
#
# The query lives *inside* the fragment, so ``urlparse().query`` is empty
# and every parameter-discovery path used to miss it.  Only the browser can
# see these values (an HTTP request never carries the fragment), so unlike
# ordinary parameters they are a DOM-XSS concern only -- which is also why
# fixing this in the DOM engine is enough.
# ---------------------------------------------------------------------------

def _hash_route_query(url: str) -> str:
    """Query string carried inside the URL fragment, or ``""``.

    ``http://h/#/search?q=1`` -> ``q=1``.  A fragment without a ``?``
    (``#/search``) yields ``""``.
    """
    from urllib.parse import urlparse
    try:
        frag = urlparse(url).fragment
    except Exception:
        return ""
    if not frag:
        return ""
    _, sep, query = frag.partition("?")
    return query if sep else ""


def _hash_param_names(url: str) -> list:
    """Ordered, de-duplicated names of the fragment-carried parameters."""
    from urllib.parse import parse_qsl
    try:
        pairs = parse_qsl(_hash_route_query(url), keep_blank_values=True)
    except Exception:
        return []
    names: list = []
    seen: set = set()
    for key, _value in pairs:
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _with_hash_param_value(url: str, name: str, value: str) -> str:
    """Set a fragment-carried parameter, keeping the route path intact.

    ``http://h/#/search?q=1`` + ``name='q'`` + ``value=MK`` becomes
    ``http://h/#/search?q=MK``.  The ``/search`` route must survive: drop it
    and the SPA renders a different view (usually its 404), so the sink is
    never reached and the probe silently proves nothing.
    """
    from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
    parsed = urlparse(url)
    route, sep, query = parsed.fragment.partition("?")
    pairs = parse_qsl(query, keep_blank_values=True) if sep else []
    out = [(k, value if k == name else v) for k, v in pairs]
    if not any(k == name for k, _v in pairs):
        out.append((name, value))
    new_fragment = route + "?" + urlencode(out)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, parsed.query, new_fragment))


class DynamicDomAnalyzer:
    """Runs a real headless browser to confirm DOM-XSS sinks execute."""

    def __init__(self, timeout: int = 20, headless: bool = True):
        # `timeout` is in SECONDS (caller-facing). Playwright's goto/wait APIs
        # expect MILLISECONDS, so we multiply at the boundary below.
        self.timeout = timeout
        self.headless = headless

    @staticmethod
    def available() -> bool:
        try:
            import importlib.util as u
            return u.find_spec("playwright") is not None
        except Exception:
            return False

    def _probes(self, url: str, marker: str) -> list:
        """Build delivery probes: how to push the marker into each source.

        Covers the full set of DOM taint sources defined by OWASP:
          * location.hash / location.search / location.href / location.pathname
          * document.referrer (via Referer header injection)
          * document.cookie
          * window.name (cross-page persistence)
          * postMessage
        """
        from urllib.parse import urlparse, urlunparse, quote
        probes = []
        parsed = urlparse(url)
        base = url.split("#")[0].split("?")[0]
        # location.hash
        probes.append({"kind": "goto", "url": base + "#" + marker,
                       "source": "location.hash"})
        # location.search
        # NOTE: ``base`` has already been stripped of both the fragment and
        # the query, so the separator must be derived from ``base`` -- not
        # from the original ``url``.  Deriving it from ``url`` produced
        # ``http://h/p&__xss__=MK`` for every input that carried a query
        # string, i.e. a path with no query at all, which silently disabled
        # this probe on every URL a real scan visits.
        sep = "&" if "?" in base else "?"
        probes.append({"kind": "goto", "url": base + sep + "__xss__=" + marker,
                       "source": "location.search"})
        # A page reads a *specific* parameter (``?q=``), so the generic
        # ``__xss__`` probe above only helps pages that read any parameter.
        # Replay the original query with each real parameter's value swapped
        # for the marker; capped so the browser cost stays bounded.
        for name in _query_param_names(url)[:_MAX_SEARCH_PARAM_PROBES]:
            if name == "__xss__":
                continue
            probes.append({"kind": "goto",
                           "url": _with_param_value(url, name, marker),
                           "source": "location.search"})
        # SPA hash routing: the parameters live inside the fragment
        # (``#/search?q=``).  Nothing above reaches them -- ``base`` has the
        # fragment stripped, ``urlparse().query`` is empty, and an HTTP
        # request never carries the fragment at all.  The page's own router
        # is the only thing that ever sees these values, which is precisely
        # the DOM-XSS case.  Verified against OWASP Juice Shop, where both
        # hash-routed XSS went undetected without this probe.
        for name in _hash_param_names(url)[:_MAX_SEARCH_PARAM_PROBES]:
            probes.append({"kind": "goto",
                           "url": _with_hash_param_value(url, name, marker),
                           "source": "location.hash"})
        # location.href (full URL reflected as-is)
        href_url = base + sep + "__xss__=" + quote(marker) + "#" + marker
        probes.append({"kind": "goto", "url": href_url,
                       "source": "location.href"})
        # location.pathname (path segment injected)
        path_marker = base.rstrip("/") + "/" + quote(marker, safe="")
        probes.append({"kind": "goto", "url": path_marker,
                       "source": "location.pathname"})
        # document.referrer (set via Referer header on navigation)
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        probes.append({"kind": "referer", "url": url, "origin": origin,
                       "referer_value": href_url,
                       "source": "document.referrer"})
        # document.cookie
        probes.append({"kind": "cookie", "url": url, "origin": origin,
                       "source": "document.cookie"})
        # window.name (persists across navigations within the same tab)
        probes.append({"kind": "window_name", "url": url,
                       "source": "window.name"})
        # postMessage
        probes.append({"kind": "postmsg", "url": url, "source": "postMessage"})
        return probes

    def analyze(self, url: str, marker: str | None = None) -> list:
        if not self.available():
            return []
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return []
        marker = marker or (_stem_marker("xssentinel_dom_") + secrets.token_hex(4))
        findings: list = []
        seen: set = set()
        try:
            browser = get_shared_browser()
            page = browser.new_page()
            try:
                page.add_init_script(_init_script(marker))
                page.on("dialog", lambda d: d.dismiss())
                for probe in self._probes(url, marker):
                    try:
                        if probe["kind"] == "goto":
                            # Phase 141: wait_until="load" (the old default)
                            # waits for every subresource.  A real page pulls
                            # CDN fonts and trackers, so on a slow or filtered
                            # network the navigation times out and the outer
                            # ``except: continue`` discards the probe WITHOUT
                            # ever reading the sink log -- the DOM engine looks
                            # like it found nothing while it never actually
                            # looked.  domcontentloaded is enough to run the
                            # page's own scripts, and a navigation error must
                            # not skip the hit log either: the sink can fire
                            # before a late subresource trips the timeout.
                            try:
                                page.goto(probe["url"],
                                          wait_until="domcontentloaded",
                                          timeout=self.timeout * 1000)
                            except Exception:
                                pass
                            # Let the route render (see _DOM_SETTLE_MS).
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                        elif probe["kind"] == "cookie":
                            page.context.add_cookies(
                                [{"name": "__xss__", "value": marker,
                                  "url": probe["origin"]}])
                            page.goto(probe["url"], timeout=self.timeout * 1000)
                        elif probe["kind"] == "postmsg":
                            page.goto(probe["url"], timeout=self.timeout * 1000)
                            page.wait_for_timeout(400)
                        elif probe["kind"] == "referer":
                            # Inject a forged Referer header on the navigation
                            # so ``document.referrer`` picks up the marker.
                            try:
                                page.context.set_extra_http_headers(
                                    {"Referer": probe["referer_value"]})
                            except Exception:
                                pass
                            try:
                                page.goto(probe["url"], timeout=self.timeout * 1000)
                            finally:
                                try:
                                    page.context.set_extra_http_headers({})
                                except Exception:
                                    pass
                        elif probe["kind"] == "window_name":
                            # window.name persists across navigations within
                            # the same tab.  Set it via an intermediate page
                            # on the target origin, then navigate to the URL.
                            try:
                                page.goto(probe["origin"] or probe["url"],
                                          timeout=self.timeout * 1000)
                                page.evaluate(
                                    f"window.name = {repr(marker)};")
                                page.goto(probe["url"],
                                          timeout=self.timeout * 1000)
                            except Exception:
                                continue
                    except Exception:
                        continue
                    try:
                        hits = page.evaluate("window.__xss_dom_hits || []")
                    except Exception:
                        hits = []
                    for h in hits:
                        sink = h.get("sink")
                        key = (sink, probe["source"])
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "type": "dom_dynamic",
                            "sink": sink,
                            "source": probe["source"],
                            "snippet": h.get("snippet", ""),
                            "confidence": "high",
                            "detail": (f"DOM XSS CONFIRMED in real browser: "
                                       f"attacker-controlled source "
                                       f"'{probe['source']}' reached executable "
                                       f"sink '{sink}' (marker executed)."),
                        })
            finally:
                # Pages are disposable; the shared browser is NOT closed.
                try:
                    page.close()
                except Exception:
                    pass
        except Exception:
            return []
        return findings
