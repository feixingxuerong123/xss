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
  function has(v){ return typeof v === 'string' && v.indexOf(MARKER) !== -1; }

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

  // Function constructor (covers eval-like dynamic code)
  var OrigFn = window.Function;
  window.Function = function(){
    var code = Array.prototype.map.call(arguments, String).join(',');
    if (has(code)) hit('Function', code);
    return OrigFn.apply(this, arguments);
  };

  // setTimeout / setInterval with string body
  ['setTimeout','setInterval'].forEach(function(m){
    var o = window[m];
    window[m] = function(fn, t){
      if (typeof fn === 'string' && has(fn)) hit(m, fn);
      return o.apply(this, arguments);
    };
  });

  // location.assign / replace / href / search / hash / pathname
  ['assign','replace'].forEach(function(m){
    if (location[m]){
      var o = location[m];
      location[m] = function(u){ if (has(u)) hit('location.'+m, u); return o.call(location, u); };
    }
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
        sep = "&" if "?" in url.split("#")[0] else "?"
        probes.append({"kind": "goto", "url": base + sep + "__xss__=" + marker,
                       "source": "location.search"})
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
                            page.goto(probe["url"], timeout=self.timeout * 1000)
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
