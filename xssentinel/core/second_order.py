"""Second-order XSS detection (Phase 21-4).

A second-order (a.k.a. "stored") XSS occurs when user input is persisted at
endpoint A but *executes* at endpoint B -- a different page that renders the
stored value.  Unlike ``Scanner.scan_stored`` (where the operator supplies
the view URL), second-order detection *discovers* the view page by crawling
the application after injection.

Workflow:
  1. Inject a unique marked payload at endpoint A (param P).  The payload
     is a real XSS shape (``<img src=x onerror=alert('TOKEN')>``) -- not a
     bare marker -- so that ``verifier.verify_semantic`` can later
     distinguish "token echoed as escaped text" (not a vuln) from "token
     echoed inside an event handler / script block" (second-order XSS).
  2. Invalidate the GET response cache (the site state changed).
  3. Crawl the site from a start URL (or scan a list of candidate viewer
     URLs supplied by the operator) to discover pages.
  4. For each discovered page, fetch it and search for the token.
  5. If the token is found, run semantic verification to check whether it
     landed in an executable context (script block, event handler,
     javascript: URI, CSS expression, ...).
  6. If confirmed, report a second-order XSS finding pointing at the
     viewer page (B) and the inject endpoint (A).

The crawl is bounded by ``max_pages`` (default 25) to keep request volume
sane.  The inject endpoint itself is excluded from the viewer set so an
immediate reflected XSS is not misreported as second-order.
"""
from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .requester import Requester


# A compact, high-yield payload set for second-order probing.  We try each
# shape in turn until one survives the application's input pipeline and
# surfaces unescaped on a viewer page.  Each carries the token inside an
# alert() call so verify_semantic can confirm execution.
_SECOND_ORDER_SHAPES = [
    "<img src=x onerror=alert('{t}')>",
    "<svg/onload=alert('{t}')>",
    "<script>alert('{t}')</script>",
    "<iframe srcdoc=\"<script>alert('{t}')</script>\">",
    "<body onload=alert('{t}')>",
    "\"><img src=x onerror=alert('{t}')>",
    "'-alert('{t}')-'",
    "javascript:alert('{t}')",
]


def _snippet(text: str, token: str, radius: int = 100) -> str:
    """Return a short snippet of ``text`` around the first ``token`` match."""
    idx = text.find(token)
    if idx == -1:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(token) + radius)
    raw = text[start:end]
    # Collapse whitespace for a compact proof string.
    return " ".join(raw.split())


def inject_payload(req: "Requester", inject_url: str, method: str,
                   param: str, payload: str, verbose: bool = False) -> bool:
    """Inject ``payload`` at endpoint A.

    Returns True if the request succeeded (HTTP response received), False
    on a network/HTTP error.  A 2xx is not required -- some inject
    endpoints return 30x or even 404 and still persist the payload.
    """
    try:
        if method.upper() == "POST":
            req.request(method, inject_url, data={param: payload})
        else:
            req.request(method, inject_url, params={param: payload})
        return True
    except Exception as e:
        if verbose:
            print(f"    [!] second-order inject failed: {e}")
        return False


def discover_viewers(scanner, start_url: str, inject_url: str,
                     scope: str | None = None, max_pages: int = 25
                     ) -> list[tuple[str, str]]:
    """Discover candidate viewer pages by crawling from ``start_url``.

    Returns a de-duplicated list of ``(url, method)`` tuples for GET pages
    that are not the inject endpoint.  ``scanner._crawl`` is reused so the
    second-order pass benefits from the same JS/form/param miners as the
    main scan.
    """
    viewers: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        crawled = scanner._crawl(start_url)
    except Exception:
        crawled = []
    # Always include the start URL itself as a candidate viewer.
    candidates = [(start_url, "GET")]
    for ep_url, ep_method, ep_params, ep_data in crawled:
        if ep_method.upper() != "GET":
            continue
        candidates.append((ep_url, "GET"))
    # Normalize the inject URL for comparison (strip query string).
    inject_base = inject_url.split("?", 1)[0].rstrip("/")
    for url, method in candidates:
        base = url.split("?", 1)[0].rstrip("/")
        if base == inject_base:
            continue  # never check the inject endpoint as a viewer
        if scope and not url.startswith(scope):
            continue
        if url in seen:
            continue
        seen.add(url)
        viewers.append((url, method))
        if len(viewers) >= max_pages:
            break
    return viewers


def check_viewers(req: "Requester", viewers: list[tuple[str, str]],
                  token: str, verbose: bool = False) -> list[dict]:
    """Fetch each viewer page and check for the token.

    Returns a list of confirmed findings, each a dict with:
      ``viewer_url``, ``context``, ``detail``, ``snippet``.
    Pages where the token appears but only in escaped/text form (not
    executable) are NOT reported -- they are noted in verbose mode only.
    """
    from . import verifier

    findings: list[dict] = []
    for viewer_url, method in viewers:
        try:
            # Invalidate any cached GET for this viewer so we see the
            # just-injected payload rather than a stale pre-inject copy.
            if hasattr(req, "invalidate"):
                req.invalidate(viewer_url)
            resp = req.get(viewer_url)
        except Exception:
            continue
        text = resp.text or ""
        if token not in text:
            continue
        v = verifier.verify_semantic(text, token,
                                     response_headers=dict(resp.headers))
        if v["confirmed"]:
            findings.append({
                "viewer_url": viewer_url,
                "context": v["context"],
                "detail": v["detail"],
                "snippet": _snippet(text, token),
            })
            if verbose:
                print(f"    [+] second-order XSS confirmed at "
                      f"{viewer_url} ({v['context']})")
        elif verbose:
            print(f"    [*] token reflected (escaped, not exec) at "
                  f"{viewer_url}: {v['detail']}")
    return findings


def scan_second_order(scanner, inject_url: str, param: str = "q",
                      method: str = "POST",
                      start_url: str | None = None,
                      viewer_urls: list[str] | None = None,
                      max_pages: int = 25,
                      verbose: bool = False) -> list[dict]:
    """Run a full second-order XSS scan.

    Injects marked payloads at ``inject_url`` (param ``param``), then
    discovers viewer pages by crawling from ``start_url`` (or uses the
    explicit ``viewer_urls`` list) and checks each for unescaped
    reflection of the token in an executable context.

    Returns a list of finding dicts.  Each finding is also recorded on
    ``scanner.findings`` and ``scanner.coverage`` by the caller (the
    Scanner.scan_second_order method).
    """
    req = scanner.req
    start_url = start_url or inject_url
    verbose = verbose or scanner.verbose

    # Build the viewer candidate set.
    if viewer_urls:
        inject_base = inject_url.split("?", 1)[0].rstrip("/")
        viewers: list[tuple[str, str]] = []
        seen: set[str] = set()
        for u in viewer_urls:
            base = u.split("?", 1)[0].rstrip("/")
            if base == inject_base:
                continue
            if u in seen:
                continue
            seen.add(u)
            viewers.append((u, "GET"))
    else:
        viewers = discover_viewers(scanner, start_url, inject_url,
                                   scope=scanner.scope, max_pages=max_pages)

    if not viewers:
        if verbose:
            print(f"[*] second-order: no viewer pages discovered from "
                  f"{start_url}")
        return []

    if verbose:
        print(f"[*] second-order: injecting at {inject_url} "
              f"({method} {param}), checking {len(viewers)} viewer page(s)")

    results: list[dict] = []
    # Try each payload shape until one surfaces unescaped on a viewer.
    for shape in _SECOND_ORDER_SHAPES:
        token = "xsso_" + secrets.token_hex(4)
        payload = shape.format(t=token)
        ok = inject_payload(req, inject_url, method, param, payload,
                            verbose=verbose)
        if not ok:
            continue
        scanner._bump()  # count the inject request
        found = check_viewers(req, viewers, token, verbose=verbose)
        # Each viewer fetch also counts as a request.
        scanner.requests_made += len(viewers)
        for f in found:
            results.append({
                "inject_url": inject_url,
                "inject_method": method,
                "inject_param": param,
                "viewer_url": f["viewer_url"],
                "context": f["context"],
                "detail": f["detail"],
                "snippet": f["snippet"],
                "payload": payload,
                "token": token,
            })
        if results:
            # One confirmed shape is enough -- no need to try the rest.
            break
    return results
