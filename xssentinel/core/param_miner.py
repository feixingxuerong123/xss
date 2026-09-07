"""Hidden parameter miner.

Many applications accept parameters that aren't linked from any UI element
(debug, admin, internal, legacy).  This module probes a URL with a list of
common parameter names and reports which ones the server responds to
differently -- those are candidates for further XSS testing.

Detection heuristic:
  1. Send a baseline request with no extra params.
  2. For each candidate param, send a request with value = unique marker.
  3. If the response differs from baseline (length delta, status delta,
     or marker reflected), the param is "interesting".
  4. Return the list of interesting params for the scanner to test.

The wordlist is curated for high-yield XSS-vulnerable params (search,
redirect, callback, etc.).

Supported probe modes (Phase 16):
  * query/form-encoded params (original behavior).
  * JSON body params (``Content-Type: application/json``) -- probes each
    candidate as a top-level field of a JSON object.
  * GraphQL variable probing -- injects each candidate into the
    ``variables`` object of a parameterized GraphQL query.
"""
from __future__ import annotations
import json as _json
import secrets
from typing import Iterable

# Curated wordlist of parameter names that commonly lead to XSS.
# Ordered by real-world yield (most likely first).
CANDIDATE_PARAMS: list[str] = [
    # Reflection-prone
    "q", "query", "search", "keyword", "keywords", "term", "find",
    "name", "title", "subject", "topic", "description", "comment",
    "msg", "message", "text", "content", "body", "note", "notes",
    # Redirects (open redirect -> XSS via javascript:)
    "url", "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "return_url", "next", "next_url", "go", "to", "target", "dest",
    "destination", "continue", "callback_url", "back",
    # JSONP / callback
    "callback", "jsonp", "cb", "cbfunc", "func", "fn", "handler",
    # Common framework params
    "id", "page", "p", "page_id", "pid", "uid", "user", "username",
    "user_id", "userid", "email", "mail", "phone", "tel",
    # Templates / rendering
    "template", "tpl", "view", "render", "format", "output", "type",
    # Admin / debug
    "debug", "test", "dev", "admin", "internal", "_", "cache",
    # XSS classics
    "html", "data", "value", "val", "input", "field", "param", "params",
    # Sort / filter
    "sort", "order", "dir", "asc", "desc", "filter", "f",
    # Layout / theming (often reflected)
    "theme", "skin", "style", "lang", "language", "locale",
    # Misc
    "ref", "source", "src", "origin", "from", "action", "cmd", "command",
    "do", "op", "operation", "step", "stage", "phase", "act", "task",
    # ------------------------------------------------------------------
    # Phase 43 expansion (aligned with SecLists/burp-parameter-names
    # high-yield subsets): the fuzzer triage (Phase 17/22-4) scores the
    # extra candidates cheaply, so a larger list costs little and
    # surfaces hidden params the short list missed.
    # ------------------------------------------------------------------
    # Pagination / cursors
    "offset", "limit", "per_page", "pageSize", "page_size", "size",
    "count", "start", "cursor", "before", "after", "since", "until",
    "index", "pos", "range", "skip", "top",
    # File / path (LFI-adjacent, often reflected in errors)
    "file", "path", "filename", "filepath", "folder", "directory",
    "doc", "document", "attachment", "upload", "download", "cat",
    "read", "load", "include", "require",
    # Auth / session / token (often echoed in error pages)
    "token", "key", "api_key", "apikey", "access_token", "refresh_token",
    "auth", "session", "sid", "sessionid", "session_id", "jwt",
    "client_id", "client_secret", "state", "nonce", "scope",
    "grant_type", "response_type", "code_challenge",
    # User / account
    "account", "acct", "profile", "member", "owner", "author",
    "creator", "editor", "role", "group", "org", "tenant", "uid",
    "gid", "uuid", "guid", "user_email", "first_name", "last_name",
    # Business objects
    "product", "item", "sku", "order", "order_id", "cart", "invoice",
    "payment", "price", "amount", "currency", "qty", "quantity",
    "category", "cat", "brand", "tags", "label",
    # Media (URLs often reflected into attributes)
    "img", "image", "image_url", "photo", "pic", "video", "media",
    "thumb", "thumbnail", "avatar", "icon", "logo", "banner",
    "file_url", "link", "href",
    # Referral / bounce-back (open-redirect twins)
    "referer", "referrer", "r", "rurl", "ru", "returnTo", "redirectTo",
    "returnurl", "ReturnUrl", "u", "goto", "window", "parent",
    # Template / view / layout (LFI + template injection surface)
    "layout", "partial", "tpl_name", "pageName", "screen", "section",
    "module", "component", "widget", "block", "panel", "tab", "modal",
    "dialog", "preview", "draft",
    # API / technical
    "api", "api_url", "endpoint", "base_url", "url_base", "host",
    "domain", "site", "server", "port", "protocol", "proxy",
    "gateway", "webhook", "notify", "ping", "health", "healthcheck",
    "version", "v",
    # Sort / filter extensions
    "orderBy", "sortBy", "sort_by", "sortField", "sort_dir",
    "filter_by", "facet", "group_by", "fields", "columns", "expand",
    # Time
    "date", "time", "timestamp", "ts", "datetime", "day", "month",
    "year", "period", "timezone", "tz",
    # Geo / locale
    "region", "country", "city", "lat", "lon", "latlng", "units",
    # Debug / verbose
    "trace", "log", "level", "verbose", "dump", "show", "print",
    "error", "errors",
    # IDs and codes
    "code", "slug", "alias", "hash", "md5", "sha1", "sha256", "sig",
    "signature", "checksum", "ref_id", "track", "tracking",
]

# De-duplicate while preserving order.  The list grew across several phases
# and quietly picked up repeats (uid / order / cat), which cost redundant
# probes against every crawled endpoint.  Keeps the count at the 313 the
# README advertises.
CANDIDATE_PARAMS = list(dict.fromkeys(CANDIDATE_PARAMS))


def candidate_list() -> list[str]:
    """Return a copy of the candidate parameter list."""
    return list(CANDIDATE_PARAMS)


def load_wordlist(path: str) -> list[str]:
    """Load extra candidate names from a wordlist file (one per line;
    ``#`` starts a comment; blank lines ignored).  Raises FileNotFoundError
    for a missing file -- callers surface the error to the operator."""
    names: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith("#"):
                names.append(name)
    return names


def merged_candidates(extra: Iterable[str] | None = None) -> list[str]:
    """CANDIDATE_PARAMS with operator-supplied names PREPENDED (deduped,
    order-stable) — operator hints deserve the first probe slots."""
    if not extra:
        return list(CANDIDATE_PARAMS)
    seen: set[str] = set()
    out: list[str] = []
    for name in list(extra) + CANDIDATE_PARAMS:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def mine_params(requester, url: str, method: str = "GET",
                existing_params: dict | None = None,
                existing_data: dict | None = None,
                marker_prefix: str = "xsstest_",
                max_params: int = 100,
                verbose: bool = False,
                mode: str = "auto",
                extra_candidates: list[str] | None = None,
                bav: bool = False) -> list[dict]:
    """Probe a URL for hidden parameters.

    Args:
        mode: probing mode -- one of:
            * ``"auto"`` (default): form-encoded by default; switches to
              JSON if the baseline ``Content-Type`` is ``application/json``
              or the response body parses as JSON; switches to GraphQL if
              the response looks like a GraphQL endpoint.
            * ``"form"``: form-encoded params (query string or POST body).
            * ``"json"``: JSON body params (``Content-Type: application/json``).
            * ``"graphql"``: inject candidates into GraphQL ``variables``.

    Returns a list of dicts: [{"name": str, "reflected": bool, "length_delta": int,
    "mode": str, ...}] for params whose response differs from the baseline.
    """
    existing_params = existing_params or {}
    existing_data = existing_data or {}

    # 1) Baseline request.
    json_headers = {"Content-Type": "application/json"}
    try:
        if method.upper() == "POST":
            base_resp = requester.request(method, url,
                                          params=existing_params,
                                          data=existing_data)
        else:
            base_resp = requester.request(method, url,
                                          params=existing_params,
                                          data=existing_data)
        baseline_len = len(base_resp.text or "")
        baseline_status = getattr(base_resp, "status_code", 0)
        baseline_ct = (base_resp.headers.get("Content-Type", "")
                       if hasattr(base_resp, "headers") else "")
        baseline_text = base_resp.text or ""
    except Exception as e:
        if verbose:
            print(f"    [param_miner] baseline request failed: {e}")
        return []

    # 2) Determine probing mode.
    if mode == "auto":
        if _looks_like_graphql(url, baseline_text, existing_data):
            mode = "graphql"
        elif "json" in baseline_ct.lower() or _looks_like_json(baseline_text):
            mode = "json"
        else:
            mode = "form"
    if verbose:
        print(f"    [param_miner] mode={mode} baseline_len={baseline_len} "
              f"status={baseline_status}")

    # 3) Probe each candidate.
    found = []
    candidates = [p for p in (merged_candidates(extra_candidates)
                              if extra_candidates else CANDIDATE_PARAMS)
                  if p not in existing_params
                  and p not in existing_data][:max_params]

    # Phase 78: mirror-page protection (DalFox-style sentinel probe).
    # A page that reflects EVERYTHING makes every candidate score
    # "interesting" and floods the triage with noise.  Three random
    # sentinel names that cannot collide with real params must NOT all
    # reflect; if they do, this is a mirror -- skip mining entirely.
    if len(candidates) > 15:
        sentinel_reflected = 0
        for si in range(3):
            sname = f"_xss_sentinel_{secrets.token_hex(3)}_{si}"
            smarker = f"{marker_prefix}s{si}"
            try:
                sresp = _probe(requester, url, method, mode, sname,
                               smarker, existing_params, existing_data,
                               json_headers)
            except Exception:
                continue
            if sresp is None:
                continue
            if smarker in (sresp.text or ""):
                sentinel_reflected += 1
        if sentinel_reflected == 3:
            if verbose:
                print("    [param_miner] mirror page detected (all 3 "
                      "sentinels reflected) -- mining skipped")
            return []

    # Phase 78: rolling reflection ratio (EWMA-style collapse).  A page
    # that reflects >=85% of the last 15 probes is a mirror too; stop
    # instead of flooding, keeping only discriminative findings.
    reflected_recent: list[int] = []
    for i, name in enumerate(candidates):
        marker = f"{marker_prefix}{i}"
        try:
            resp = _probe(requester, url, method, mode, name, marker,
                          existing_params, existing_data, json_headers)
        except Exception:
            continue
        if resp is None:
            continue
        text = resp.text or ""
        status = getattr(resp, "status_code", 0)
        length_delta = abs(len(text) - baseline_len)
        reflected = marker in text
        # Phase 78: rolling reflection ratio -- collapse on mirrors.
        reflected_recent.append(1 if reflected else 0)
        if len(reflected_recent) >= 15 and \
                sum(reflected_recent) >= 13:
            if verbose:
                print("    [param_miner] reflection ratio >= 85% over the "
                      "last 15 probes -- mirror collapse, stopping")
            # On a mirror, any param reflects -- keep ONE reflected finding
            # as the "any parameter" representative, drop the rest of the
            # reflected-only noise, keep the discriminative delta signals.
            reps = [f for f in found if f["reflected"]][:1]
            found = reps + [f for f in found if not f["reflected"]]
            break
        # "Interesting" if: marker reflected OR status changed OR
        # length delta > 50 bytes (heuristic for server-side processing).
        interesting = reflected or status != baseline_status or length_delta > 50
        if interesting:
            found.append({
                "name": name,
                "reflected": reflected,
                "length_delta": length_delta,
                "status_delta": status - baseline_status,
                "mode": mode,
            })
            if verbose:
                print(f"    [param_miner] {name} ({mode}): "
                      f"reflected={reflected} delta={length_delta}")

    # Phase 81: optional BAV follow-up on the interesting params.
    if bav:
        for f in found:
            f["bav"] = bav_probe(requester, url, method, f["name"],
                                 mode, existing_params, existing_data)
    return found


def _looks_like_json(text: str) -> bool:
    """Heuristic: does the response body look like a JSON object/array?"""
    t = text.lstrip()
    return t.startswith("{") or t.startswith("[")


def _looks_like_graphql(url: str, text: str, data: dict | None) -> bool:
    """Heuristic: does this look like a GraphQL endpoint?

    GraphQL endpoints typically:
      * Live at ``/graphql`` or ``/api/graphql``.
      * Return JSON with ``data``/``errors`` keys.
      * Accept POST with a ``query`` field in the body.
    """
    if "/graphql" in url.lower():
        return True
    t = (text or "").lstrip()
    if t.startswith("{"):
        try:
            obj = _json.loads(t)
            if isinstance(obj, dict) and ("data" in obj or "errors" in obj):
                return True
        except Exception:
            pass
    if data and "query" in data:
        return True
    return False


def _probe(requester, url: str, method: str, mode: str,
           name: str, marker: str,
           existing_params: dict, existing_data: dict,
           json_headers: dict):
    """Send one probe for a single candidate param in the given mode.

    Returns the response object, or None on failure.
    """
    params = dict(existing_params)
    if mode == "form":
        data = dict(existing_data)
        if method.upper() == "POST":
            data[name] = marker
        else:
            params[name] = marker
        return requester.request(method, url, params=params, data=data)
    elif mode == "json":
        # Inject as a top-level JSON field.
        body = dict(existing_data) if existing_data else {}
        body[name] = marker
        return requester.request(method, url, params=params,
                                 data=_json.dumps(body), headers=json_headers)
    elif mode == "graphql":
        # Inject into the ``variables`` object of a parameterized query.
        query = existing_data.get("query") if existing_data else None
        if not query:
            # Default introspection-friendly query with a $name variable.
            query = "query XSSentinelProbe($name: String) { field(name: $name) }"
        variables = dict(existing_data.get("variables", {})) if existing_data else {}
        variables[name] = marker
        body = {"query": query, "variables": variables}
        return requester.request(method, url, params=params,
                                 data=_json.dumps(body), headers=json_headers)
    else:
        # Unknown mode -- fall back to form-encoded.
        data = dict(existing_data)
        data[name] = marker
        return requester.request(method, url, params=params, data=data)


# ---------------------------------------------------------------------------
# Phase 81: BAV (Basic Another Vulnerability) follow-up probes.
# Once a parameter is "interesting" (DalFox's BAV idea), the SAME
# parameter is cheaply probed for three adjacent vulnerability classes.
# Each probe is a single request with a uniquely-recognisable value; the
# response check is unambiguous (a computed number, an injected response
# header, or a redirect Location) -- no fuzzy heuristics.

_BAV_SSTI_EXPR = "{{777*'7'}}"          # evaluates to 5439 (unique)
_BAV_SSTI_RESULT = "5439"
_BAV_CRLF_HEADER = "X-BAV-Probe"
_BAV_REDIRECT_HOST = "bav-redirect.example"


def bav_probe(requester, url: str, method: str, param: str,
              mode: str, existing_params: dict, existing_data: dict,
              ) -> list[dict]:
    """Run the three BAV probes against one parameter.

    Returns a list of dicts: ``{"kind": "ssti"|"open_redirect"|"crlf",
    "detail": str}`` -- only the CONFIRMED kinds are returned; a clean
    parameter yields an empty list.
    """
    out: list[dict] = []
    probes = [
        ("ssti", _BAV_SSTI_EXPR),
        ("open_redirect", f"https://{_BAV_REDIRECT_HOST}/r"),
        ("crlf", f"zz{_BAV_CRLF_HEADER.replace('-', '_')}"),
    ]
    for kind, value in probes:
        send_value = value
        if kind == "crlf":
            # Real CRLF injection rides as %0d%0a; the fake/request layer
            # receives the RAW value -- the origin under test decides.
            send_value = value.replace("_", "-").replace(
                "zz", "a%0d%0a")
        try:
            resp = _probe(requester, url, method, mode, param,
                          send_value, existing_params, existing_data,
                          {"Content-Type": "application/json"}
                          if mode == "json" else None)
        except Exception:
            continue
        if resp is None:
            continue
        text = resp.text or ""
        headers = {k.lower(): v for k, v in
                   getattr(resp, "headers", {}).items()}
        status = getattr(resp, "status_code", 0)
        if kind == "ssti" and _BAV_SSTI_RESULT in text:
            out.append({"kind": "ssti",
                        "detail": f"{{{{777*'7'}}}} evaluated to "
                                  f"{_BAV_SSTI_RESULT} in the response"})
        elif kind == "crlf" and _BAV_CRLF_HEADER.lower() in headers:
            out.append({"kind": "crlf",
                        "detail": f"response carries injected header "
                                  f"{_BAV_CRLF_HEADER}: "
                                  f"{headers[_BAV_CRLF_HEADER.lower()]}"})
        elif kind == "open_redirect" and 300 <= status < 400:
            loc = headers.get("location", "")
            if _BAV_REDIRECT_HOST in loc:
                out.append({"kind": "open_redirect",
                            "detail": f"redirect Location points to "
                                      f"{_BAV_REDIRECT_HOST}: {loc}"})
    return out


def best_targets(found: list[dict], top_n: int = 10) -> list[str]:
    """Return the top-N most promising parameter names from the found list.

    Rank by: reflected first (highest yield), then by length_delta.
    """
    ranked = sorted(found, key=lambda f: (
        not f["reflected"],          # reflected = True first
        -f["length_delta"],          # larger delta first
    ))
    return [f["name"] for f in ranked[:top_n]]
