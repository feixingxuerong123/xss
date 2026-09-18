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
import json
import logging
import re
import secrets
import threading
import time

from .stealth import marker as _stem_marker

_log = logging.getLogger(__name__)


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

  // Phase 163: URL property sinks.  setAttribute() was hooked, but
  // ``el.src = ...`` is a different code path and one of these executes
  // WITHOUT any activation.  Measured in Chromium (Playwright, headless):
  //
  //   iframe.src = 'javascript:...'  -> executes immediately
  //   a.href     = 'javascript:...'  -> does NOT execute, not even on a
  //                                     trusted click in this harness; it is
  //                                     activation-dependent, so it is NOT
  //                                     claimed as confirmed here
  //   el.onerror = 'code' (string)   -> does NOT execute at all: the
  //                                     event-handler PROPERTY path is not a
  //                                     sink (the content attribute is, and
  //                                     setAttribute is already hooked)
  //
  // Guarded by URL scheme, not by the marker alone: a plain http src that
  // happens to carry the marker is not a vulnerability.
  var URL_SINKS = [
    [window.HTMLIFrameElement, 'src', 'iframe.src'],
    [window.HTMLEmbedElement, 'src', 'embed.src'],
    [window.HTMLObjectElement, 'data', 'object.data']
  ];
  URL_SINKS.forEach(function(pair){
    var Ctor = pair[0], prop = pair[1], label = pair[2];
    try {
      if (!Ctor || !Ctor.prototype) return;
      var d = Object.getOwnPropertyDescriptor(Ctor.prototype, prop);
      if (!d || !d.set) return;
      var o = d.set;
      Object.defineProperty(Ctor.prototype, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function(v){
          try {
            var s = String(v);
            var m = /^\s*(javascript|data:text\/html)/i.exec(s);
            if (m && has(s)) hit(label + '(' + m[1].toLowerCase() + ')', s);
          } catch(e){}
          return o.call(this, v);
        }
      });
    } catch(e) { /* leave the native accessor alone rather than break the page */ }
  });

  // Phase 162: Range.createContextualFragment.  The static analyzer lists it
  // as a HIGH sink, but the engine never hooked it -- measured with
  // benchmark/sink_matrix.py: a page that parses attacker HTML through a
  // Range was MISS before this hook and HIT after.  Wrapped on the prototype
  // so every Range instance is covered.
  try {
    if (window.Range && Range.prototype.createContextualFragment){
      var oCCF = Range.prototype.createContextualFragment;
      Range.prototype.createContextualFragment = function(html){
        try { if (has(html)) hit('Range.createContextualFragment', html); }
        catch(e){}
        return oCCF.call(this, html);
      };
    }
  } catch(e) { /* leave the native method alone rather than break the page */ }

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

  // Phase 161: a direct ``eval(code)`` is NOT covered by the Function hook
  // above -- eval is its own global, it never routes through the Function
  // constructor.  The comment there said "covers eval-like dynamic code",
  // which was an assumption, not a measurement: it is false for eval.
  // Measured cost: the benchmark vector dom_search_eval
  // (``eval(new URLSearchParams(location.search).get('x'))``) never produced
  // a dom_dynamic finding, while its setTimeout twin dom_hash_settimeout
  // did -- same page shape, same marker, same probe.  So a page whose only
  // sink is eval() was unverifiable by the browser engine.
  //
  // The marker check runs BEFORE the call so the hit is recorded even when
  // the evaluated marker is not valid JavaScript (it usually is not: the
  // marker is a bare identifier, so eval throws a ReferenceError -- which is
  // precisely why the payload's *value* must be observed, not its result).
  // Phase 162: the engine's OWN probe code is compiled through this global
  // eval -- page.evaluate() sends a source string -- so a probe that carries
  // the marker (the window_name probe's ``window.name = 'xssentinel_dom_..'``)
  // was indistinguishable from the page evaling attacker data.  Measured
  // cost: two SAFE cases scored as "DOM XSS CONFIRMED" (their payload field
  // was the probe's own source, which is how it was diagnosed).  The harness
  // raises __xss_dom_harness around its own evaluations, synchronously, so
  // page code can never be inside that window.
  try {
    var origEval = window.eval;
    window.eval = function(code){
      try {
        if (!window.__xss_dom_harness && has(code)) {
          hit('eval', String(code));
        }
      } catch(e){}
      return origEval.call(window, code);
    };
  } catch(e) { /* leave the native eval alone rather than break the page */ }

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


# Phase 154 (as written) / Phase 159 (inverted).  A browser pass costs ~5.6s
# (9 probes x ~700ms settle); 41 of the 57 slow benchmark cases paid it
# without needing it (~25% of the run, see benchmark/speed_profile.py).
#
# Phase 154 implemented the filter as a SINK WHITELIST: "run the browser only
# if we can see a sink pattern in the inline script".  That is backwards --
# every sink the regex does not name becomes unverifiable.  Measured cost
# (this session, full regression 20260918-011159):
#   * tests/test_async_dom_live.py went red -- its page is
#     ``document.getElementById('f').srcdoc = decodeURIComponent(...)``.
#     ``srcdoc`` is a real sink (an attacker-controlled srcdoc executes
#     script) and it matches nothing in the Phase 154 pattern list.
#   * tests/test_async_deep.py went red the same way.
# The Phase 154 commit also claimed "conservative by construction: anything
# the regexes cannot parse is let through by the caller keeping the old
# page_has_client_js check".  That is false: the caller ANDs the two checks,
# so combining them can only ever be NARROWER than either alone.
#
# Phase 159 inverts the question.  Instead of "is there evidence of a sink?"
# it asks "can we PROVE this page cannot execute anything?"  Only provably
# inert pages (literal/JSON declarations, no call, no member write, no DOM
# global) are skipped.  Unknown constructs now get the browser, which is the
# direction a recall-first scanner must err on.
_CAN_EXEC_RE = re.compile(
    # any call or grouping -- a sink is almost always a call
    r"\(|\)"
    # function bodies / dynamic code
    r"|=>|\bfunction\b|\bclass\b|\bnew\b|\beval\b|\bFunction\b|\batob\b|"
    r"\bimport\b|\brequire\b|\bsetTimeout\b|\bsetInterval\b"
    # a DOM/BOM global -- the page can reach the document, so it can sink
    r"|\b(?:document|window|location|navigator|history|screen|self|top|"
    r"parent|frames|globalThis|localStorage|sessionStorage|alert|fetch|"
    r"XMLHttpRequest|URLSearchParams|URL|postMessage|open|cookie|referrer|"
    r"innerHTML|outerHTML|srcdoc|javascript)\b"
    # member assignment:  a.b = c
    r"|\.[A-Za-z_$][\w$]*\s*=[^=]", re.I)
_EXT_SCRIPT_RE = re.compile(r"<script[^>]*\ssrc\s*=", re.I)
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\ssrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)
# Execution that lives in markup, not in a <script> block: inline event
# handlers, javascript: URLs, an attacker-settable srcdoc/data attribute.
_HTML_EXEC_RE = re.compile(
    r"\son[a-z]+\s*=|:javascript|javascript:|\ssrcdoc\s*=|data:text/html",
    re.I)


def page_can_run_sink(html: str) -> bool:
    """Pre-filter: can this page execute code that could reach a sink?

    Used together with :func:`page_has_client_js` -- passing both means the
    page is worth a real-browser pass.  Phase 159: this answers "is the page
    provably inert?", NOT "did we recognise a sink?".  True for anything we
    cannot see inside (external scripts, unparseable script bodies, DOM
    globals), so the filter can only ever SKIP a browser session that cannot
    possibly produce a DOM finding.
    """
    if not html:
        return False
    if _EXT_SCRIPT_RE.search(html):
        return True
    if _HTML_EXEC_RE.search(html):
        return True
    for body in _INLINE_SCRIPT_RE.findall(html):
        if _CAN_EXEC_RE.search(body or ""):
            return True
    return False


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

# Phase 147: total wall-clock budget for probing ONE url.
#
# Each goto probe waits up to ``timeout`` seconds for its own navigation, so
# a page that pulls a slow or unreachable third-party resource makes every
# probe pay that timeout in turn -- eight probes times twenty seconds is far
# past any scan-level cap, and the whole scan dies with it.  Measured on
# benchmark pos-sri-01 and pos-importmap-01 (pages referencing
# cdn.example): both hit the 90s scan timeout with zero requests recorded,
# and both do so identically on the pre-Phase-144 code, so this is not a
# regression from that work -- it is the DOM engine waiting without bound.
#
# Same reasoning as _DOM_SETTLE_MS: the engine's job is to observe the
# page's own behaviour, and it must do so within a fixed cost.  Once the
# budget is gone we stop probing and return whatever was already found --
# findings are collected per-probe, so a slow tail never costs the head.
# 30s (not more): the benchmark's per-case cap is 45s, and the scan also
# spends time on the baseline and its own layers -- a DOM budget that eats
# most of a case's wall clock turns "slow page" into "case timeout", which
# reads as an error rather than a result.
_DOM_PROBE_BUDGET_S = 30.0


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

    def __init__(self, timeout: int = 20, headless: bool = True,
                 auth_headers: dict | None = None,
                 auth_cookies: list | None = None,
                 auth_local_storage: dict | None = None):
        # `timeout` is in SECONDS (caller-facing). Playwright's goto/wait APIs
        # expect MILLISECONDS, so we multiply at the boundary below.
        self.timeout = timeout
        self.headless = headless
        # Phase 150: replicate the authenticated session in the browser.
        # requests.Session headers/cookies never reach Playwright on their
        # own; without them the confirmation layer visits authenticated
        # routes anonymously (401 / login wall) and every sink behind the
        # login is invisible to it.
        self.auth_headers: dict = dict(auth_headers or {})
        self.auth_cookies: list = list(auth_cookies or [])
        # SPA route guards commonly read the token from localStorage even
        # when API calls authenticate via cookie/header (observed: Juice
        # Shop renders its 403 route shell with a valid session cookie).
        # Seeded via init script, SCOPED to the scan origin -- an init
        # script runs in every frame, and localStorage is per-origin, so
        # an unscoped seed would copy the session token into the storage
        # of any third-party origin the page embeds.
        self.auth_local_storage: dict = dict(auth_local_storage or {})

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

    def _bounded_goto(self, page, url: str, deadline: float) -> None:
        """Navigate with ``commit`` and a budget-capped timeout.

        Phase 148 fixed two unbounded-cost holes (see below).  Phase 155
        replaces the *wait shape* itself, on measurement:

          pos-sri-01 / pos-importmap-01 (pages loading cdn.example) cost
          32s each -- 27.2s of the 32.3s was inside ``page.goto``, only
          2.1s was the settle floor.  A classic ``<script src>`` blocks
          the parser, so DOMContentLoaded does not fire until that
          third-party resource resolves or fails; with a nav timeout of
          20s the 30s probe budget was spent after 2-3 probes, i.e. the
          page shape silently decided how many probes could run at all.

        ``commit`` returns as soon as the navigation commits.  The page's
        own scripts still execute (they run while parsing, which the
        existing per-probe settle covers -- this engine reads sink hits
        after that settle, not at navigation completion).  Measured on 25
        benchmark cases, domcontentloaded vs commit, same settle:

          * findings identical on all 25 (pos-dom-01..08 keep their
            dom_dynamic hits);
          * CDN-blocked families 31.6s -> 11.3s AND 2-3 probes -> all 8;
          * every other case unchanged (+-0.1s).

        Not waiting for DOMContentLoaded has one real consequence: an
        inline sink placed *after* a slow external script needs that
        script to resolve first, and we no longer wait for it.  That is
        the same trade the probe budget already makes (previously such a
        page consumed the whole budget and skipped its remaining
        probes); we take the bounded, uniform cost instead.

        IGNORED-PREMISE NOTE: "wait for readyState instead" was measured
        too (variant C: commit + readyState poll capped at 5s) and buys
        nothing -- readyState stays 'loading' for exactly as long as
        DOMContentLoaded was blocked: 27s, 6 probes.
        """
        remaining = deadline - time.monotonic()
        timeout_ms = int(max(1.0, min(self.timeout, remaining)) * 1000)
        try:
            page.goto(url, wait_until="commit", timeout=timeout_ms)
        except Exception:
            pass

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
            # Phase 150: create the page carrying the authenticated
            # session.  extra_http_headers applies to every request the
            # page makes (document + XHR), which is how SPAs authenticate
            # API calls.  Domain-less auth cookies are pinned to the scan
            # URL's origin (Playwright requires url or domain+path).
            page = browser.new_page(
                extra_http_headers=self.auth_headers or None)
            if self.auth_local_storage:
                try:
                    import json as _json
                    from urllib.parse import urlparse as _up
                    origin = "{0.scheme}://{0.netloc}".format(_up(url))
                    pairs = "; ".join(
                        "try { window.localStorage.setItem(%s, %s); "
                        "} catch (e) {}"
                        % (_json.dumps(k), _json.dumps(v))
                        for k, v in self.auth_local_storage.items())
                    page.add_init_script(
                        "if (location.origin === %s) { %s }"
                        % (_json.dumps(origin), pairs))
                except Exception:
                    _log.debug("dom: auth localStorage seed failed (url=%s)",
                               url, exc_info=True)
            if self.auth_cookies:
                try:
                    from urllib.parse import urlparse
                    origin = "{0.scheme}://{0.netloc}".format(
                        urlparse(url))
                    cookie_dicts = []
                    for c in self.auth_cookies:
                        cd = {"name": c.get("name"),
                              "value": c.get("value", ""),
                              "path": c.get("path") or "/"}
                        if c.get("domain"):
                            cd["domain"] = c["domain"]
                        else:
                            cd["url"] = origin
                        cookie_dicts.append(cd)
                    page.context.add_cookies(cookie_dicts)
                except Exception:
                    _log.debug("dom: auth cookie apply failed (url=%s)",
                               url, exc_info=True)
            try:
                page.add_init_script(_init_script(marker))
                page.on("dialog", lambda d: d.dismiss())
                # Phase 147: bound the total cost of probing this url (see
                # _DOM_PROBE_BUDGET_S).  Findings are collected per probe, so
                # stopping early keeps everything already confirmed.
                deadline = time.monotonic() + _DOM_PROBE_BUDGET_S
                for probe in self._probes(url, marker):
                    if time.monotonic() > deadline:
                        _log.debug(
                            "dom: probe budget %.0fs spent for %s -- stopping "
                            "with %d finding(s)",
                            _DOM_PROBE_BUDGET_S, url, len(findings))
                        break
                    try:
                        if probe["kind"] == "goto":
                            # Phase 141: wait_until="load" (the old default)
                            # waits for every subresource.  A real page pulls
                            # CDN fonts and trackers, so on a slow or filtered
                            # network the navigation times out and the outer
                            # ``except: continue`` discards the probe WITHOUT
                            # ever reading the sink log -- the DOM engine looks
                            # like it found nothing while it never actually
                            # looked.  A navigation error must not skip the hit
                            # log either: the sink can fire before a late
                            # subresource trips the timeout.
                            # Phase 155: the wait is now "commit" (see
                            # _bounded_goto) -- even domcontentloaded can be
                            # blocked indefinitely by one third-party script.
                            self._bounded_goto(page, probe["url"], deadline)
                            # Let the route render (see _DOM_SETTLE_MS).
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                        elif probe["kind"] == "cookie":
                            page.context.add_cookies(
                                [{"name": "__xss__", "value": marker,
                                  "url": probe["origin"]}])
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                        elif probe["kind"] == "postmsg":
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(400)
                        elif probe["kind"] == "referer":
                            # Inject a forged Referer header on the navigation
                            # so ``document.referrer`` picks up the marker.
                            # Phase 150: set_extra_http_headers REPLACES the
                            # whole dict -- resetting to {} would silently
                            # strip the authenticated session's headers from
                            # every later probe, so always merge with them.
                            try:
                                hdrs = dict(self.auth_headers)
                                hdrs["Referer"] = probe["referer_value"]
                                page.context.set_extra_http_headers(hdrs)
                            except Exception:
                                pass
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                            try:
                                page.context.set_extra_http_headers(
                                    dict(self.auth_headers))
                            except Exception:
                                pass
                        elif probe["kind"] == "window_name":
                            # window.name persists across navigations within
                            # the same tab.  Set it via an intermediate page
                            # on the target origin, then navigate to the URL.
                            #
                            # Phase 162: this read ``probe["origin"]``
                            # unconditionally, but _probes() builds the
                            # window_name probe WITHOUT that key, so it raised
                            # KeyError, the surrounding ``except Exception:
                            # continue`` swallowed it, and the probe never
                            # navigated once.  Measured on a page whose only
                            # sink is ``innerHTML = window.name``: zero
                            # navigations, no finding -- a whole advertised
                            # probe kind that had never run.  ``.get`` keeps a
                            # future probe shape from costing a silent skip.
                            self._bounded_goto(page, probe.get("origin")
                                               or probe["url"], deadline)
                            try:
                                # Phase 162: the eval hook must not treat the
                                # marker WE inject here as a page-initiated
                                # eval -- it did, and two SAFE cases scored as
                                # "DOM XSS CONFIRMED" (diagnosed from the
                                # finding's payload field, which was this very
                                # source string).
                                #
                                # The flag has to be raised in its OWN
                                # evaluation: the hook runs when eval is
                                # CALLED, i.e. before the evaluated body
                                # executes, so setting it inside the same
                                # expression is too late.  Cleared right after,
                                # before the reload, so the page's own eval of
                                # window.name is still detected.
                                page.evaluate("window.__xss_dom_harness = 1;")
                                try:
                                    page.evaluate("window.name = %s;"
                                                  % json.dumps(marker))
                                finally:
                                    page.evaluate(
                                        "window.__xss_dom_harness = 0;")
                                self._bounded_goto(page, probe["url"],
                                                   deadline)
                                page.wait_for_timeout(_DOM_SETTLE_MS)
                            except Exception:
                                continue
                    except Exception:
                        # Phase 162: a probe that raises is skipped, which is
                        # right (one bad probe must not kill the scan) but was
                        # INVISIBLE -- that is exactly how the window_name
                        # KeyError above went unnoticed for so long.  Log it.
                        _log.debug("dom: probe %r skipped for %s",
                                   probe.get("kind"), url, exc_info=True)
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
