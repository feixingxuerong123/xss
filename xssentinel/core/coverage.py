"""Scan coverage tracker (Phase 20-3).

Records exactly which detection layers, parameters, and payload classes
were exercised for every endpoint so the operator can prove the scan was
*comprehensive* (not just "ran without crashing").  This closes the gap
between "0 findings" and "0 findings because we actually tested it" --
a distinction auditors and CI gates increasingly demand.

Three dimensions of coverage are tracked per endpoint:

  1. **Layers** -- which of the 23 detection layers (L1 reflected,
     L2 WAF-evade, L3 DOM-static, L4 stored, L5 blind/OOB, L6 DOM-
     dynamic, L7 mutation/clobber/template/polyglot/jsonp/csp, L8
     postmessage/proto/sw/worker/redirect/framework/header/path/
     cookie/error/markdown) actually ran on this endpoint.

  2. **Parameters** -- each parameter that was probed, whether the
     marker reflected, the context it landed in, and how many payload
     variants were sent against it.

  3. **Payload classes** -- which payload corpora (html_element,
     script_block, svg_context, blind_oob, ...) were dispatched, so
     the operator can see which attack classes were exercised.

The tracker is thread-safe (Scanner may call from multiple worker
threads).  ``summary()`` returns a machine-readable dict; ``to_html()``
returns a human-readable section that drops into the HTML report.
"""
from __future__ import annotations

import html as _html
import threading
from datetime import datetime


# ---------------------------------------------------------------------------
# Detection layer registry
# ---------------------------------------------------------------------------
# Each entry: (layer_id, human_name, phase).  ``phase`` is a short tag for
# grouping in the report ("L1".."L8").  Keep this list in sync with the
# layers actually invoked in scanner.py / advanced_layers.py.
LAYERS: list[tuple[str, str, str]] = [
    ("L1_reflected",       "Reflected XSS probing",            "L1"),
    ("L2_waf_evade",       "WAF evasion transforms",           "L2"),
    ("L3_dom_static",      "DOM static taint analysis",        "L3"),
    ("L4_stored",          "Stored XSS (inject -> view)",      "L4"),
    ("L4_second_order",    "Second-order XSS (inject -> crawl)", "L4"),
    ("L5_blind_oob",       "Blind XSS OOB injection",          "L5"),
    ("L6_dom_dynamic",     "DOM dynamic (real browser)",       "L6"),
    ("L7_mutation",        "mXSS mutation",                    "L7"),
    ("L7_dom_clobber",     "DOM clobbering",                   "L7"),
    ("L7_template",        "Template SSTI",                    "L7"),
    ("L7_polyglot",        "Polyglot payloads",                "L7"),
    ("L7_jsonp",           "JSONP callback",                   "L7"),
    ("L7_csp",             "CSP analysis",                     "L7"),
    ("L7_time_based",      "Time-based XSS (side-channel)",    "L7"),
    ("L8_postmessage",     "postMessage XSS",                  "L8"),
    ("L8_prototype",       "Prototype pollution",              "L8"),
    ("L8_service_worker",  "Service Worker XSS",               "L8"),
    ("L8_web_worker",      "Web Worker XSS",                   "L8"),
    ("L8_open_redirect",   "Open redirect -> XSS",             "L8"),
    ("L8_framework",       "Framework DOM XSS",                "L8"),
    ("L8_header",          "Header XSS",                       "L8"),
    ("L8_path",            "Path XSS",                         "L8"),
    ("L8_cookie",          "Cookie XSS",                       "L8"),
    ("L8_error_page",      "Error page XSS",                   "L8"),
    ("L8_markdown",        "Markdown XSS",                     "L8"),
    ("L9_param_miner",     "Hidden parameter discovery",       "L9"),
    ("L9_js_miner",        "JS endpoint mining",               "L9"),
    ("L9_form_miner",      "Form field discovery",             "L9"),
    # Phase 115: these ten were live, dispatched layers whose layer_id was
    # never registered here -- record_layer() stored them via its
    # unknown-layer fallback, so they were invisible to the stats/summary
    # and to the Phase 111 coverage matrix (which reads this table).
    ("L7_csp_nonce",       "CSP nonce leak exploitation",      "L7"),
    ("L7_css_injection",   "CSS injection",                    "L7"),
    ("L7_dangling_markup", "Dangling markup injection",        "L7"),
    ("L7_import_map",      "Import map hijacking",             "L7"),
    ("L7_sanitizer_bypass", "Sanitizer bypass (DOMPurify etc.)", "L7"),
    ("L7_sri_bypass",      "SRI bypass",                       "L7"),
    ("L7_svg_xss",         "SVG-specific XSS",                 "L7"),
    ("L8_cookie_tossing",  "Cookie tossing",                   "L8"),
    ("L8_graphql",         "GraphQL introspection -> XSS",     "L8"),
    ("L8_trusted_types",   "Trusted Types bypass",             "L8"),
    ("L8_websocket",       "WebSocket message -> sink",        "L8"),
    # Phase 115 follow-up: the reconciliation test found ten MORE ids in
    # scanner.py / async_scanner.py / advanced_layers.py that this table
    # never listed (the first pass only grepped the two layers files).
    ("L1_csp_gate",            "CSP gate probe",                   "L1"),
    ("L1_pre_encoded",         "Pre-encoded payload pass",         "L1"),
    ("L1_reflection_profile", "Reflection profiling",             "L1"),
    ("L2_position_shift",     "Position-shift evasion",           "L2"),
    ("L7_cors",               "CORS misconfiguration",            "L7"),
    ("L7_nonce_bypass",       "Nonce bypass",                     "L7"),
    ("L7_xsleak",             "XS-Leak surface audit",            "L7"),
    ("L8_request",            "Request-level checks (async shim)", "L8"),
    ("L9_scenario",           "Scenario replay",                  "L9"),
    ("L9_upload_filename",    "Upload filename probing",          "L9"),
]

LAYER_IDS = {lid for lid, _, _ in LAYERS}
LAYER_NAMES = {lid: name for lid, name, _ in LAYERS}
LAYER_PHASES = {lid: phase for lid, _, phase in LAYERS}


class ParamCoverage:
    """Per-parameter coverage record for a single endpoint."""

    __slots__ = ("name", "in_body", "reflected", "context",
                 "payloads_sent", "payload_classes", "confirmed")

    def __init__(self, name: str, in_body: bool):
        self.name = name
        self.in_body = in_body
        self.reflected = False
        self.context: str | None = None
        self.payloads_sent = 0
        # Set of payload-class tags (html_element, script_block, ...) that
        # were dispatched against this parameter.
        self.payload_classes: set[str] = set()
        # True once any finding was confirmed for this (endpoint, param).
        self.confirmed = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "in_body": self.in_body,
            "reflected": self.reflected,
            "context": self.context,
            "payloads_sent": self.payloads_sent,
            "payload_classes": sorted(self.payload_classes),
            "confirmed": self.confirmed,
        }


class EndpointCoverage:
    """Coverage record for a single (url, method) endpoint."""

    __slots__ = ("url", "method", "layers", "params", "requests",
                 "findings", "crawled", "scan_started", "scan_ended")

    def __init__(self, url: str, method: str, crawled: bool = False):
        self.url = url
        self.method = method
        # layer_id -> {"status": str, "detail": str, "ts": str}
        self.layers: dict[str, dict] = {}
        # param key ("name|in_body") -> ParamCoverage
        self.params: dict[str, ParamCoverage] = {}
        self.requests = 0
        self.findings = 0
        self.crawled = crawled
        self.scan_started: str | None = None
        self.scan_ended: str | None = None

    def record_layer(self, layer_id: str, status: str = "ran",
                     detail: str = "") -> None:
        if layer_id not in LAYER_IDS:
            # Unknown layer -- record it anyway so new layers are visible.
            self.layers[layer_id] = {
                "status": status, "detail": detail,
                "ts": datetime.now().isoformat(timespec="seconds"),
            }
            return
        self.layers[layer_id] = {
            "status": status, "detail": detail,
            "ts": datetime.now().isoformat(timespec="seconds"),
        }

    def touch_layer(self, layer_id: str, detail: str = "") -> None:
        """Mark a layer as ran if not already recorded (idempotent)."""
        if layer_id not in self.layers:
            self.record_layer(layer_id, "ran", detail)

    def record_param(self, name: str, in_body: bool) -> ParamCoverage:
        key = f"{name}|{'body' if in_body else 'query'}"
        if key not in self.params:
            self.params[key] = ParamCoverage(name, in_body)
        return self.params[key]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "crawled": self.crawled,
            "requests": self.requests,
            "findings": self.findings,
            "scan_started": self.scan_started,
            "scan_ended": self.scan_ended,
            "layers": dict(self.layers),
            "params": {k: v.to_dict() for k, v in self.params.items()},
        }


# ---------------------------------------------------------------------------
# Phase 108: per-layer request accounting ("where does the scan spend its
# requests?").  Layer boundaries are already marked 58 times via
# CoverageTracker.touch_layer(), so the accounting hangs off that hook plus
# the Requester's single choke point (_send) -- no call-site changes.
#
# The current layer is per-THREAD (scans run concurrently); the counters
# are shared and lock-protected.
# ---------------------------------------------------------------------------
_LAYER_TLS = threading.local()
_LAYER_REQUESTS: dict = {}
_LAYER_REQUEST_LOCK = threading.Lock()

UNATTRIBUTED_LAYER = "(unattributed)"


def set_current_layer(layer_id: str) -> None:
    """Mark the layer subsequent requests belong to (this thread)."""
    _LAYER_TLS.layer = layer_id


def current_layer() -> str:
    return getattr(_LAYER_TLS, "layer", UNATTRIBUTED_LAYER)


def count_layer_request() -> None:
    """Account one outbound request to the current thread's layer."""
    lid = current_layer()
    with _LAYER_REQUEST_LOCK:
        _LAYER_REQUESTS[lid] = _LAYER_REQUESTS.get(lid, 0) + 1


def layer_request_counts() -> dict:
    with _LAYER_REQUEST_LOCK:
        return dict(_LAYER_REQUESTS)


def reset_layer_request_counts() -> None:
    with _LAYER_REQUEST_LOCK:
        _LAYER_REQUESTS.clear()


class CoverageTracker:
    """Thread-safe scan coverage tracker.

    Plug into Scanner via ``scanner.coverage`` -- the scanner records
    events as it dispatches each detection layer / parameter / payload.
    After scanning, call ``summary()`` for a machine-readable dict or
    ``to_html()`` for a human-readable report section.
    """

    def __init__(self):
        self._endpoints: dict[str, EndpointCoverage] = {}
        self._lock = threading.Lock()
        self._enabled = True

    # -- endpoint lifecycle ------------------------------------------------
    def start_endpoint(self, url: str, method: str = "GET",
                       crawled: bool = False) -> EndpointCoverage:
        key = self._key(url, method)
        with self._lock:
            ep = self._endpoints.get(key)
            if ep is None:
                ep = EndpointCoverage(url, method, crawled=crawled)
                self._endpoints[key] = ep
            ep.scan_started = datetime.now().isoformat(timespec="seconds")
            ep.crawled = ep.crawled or crawled
            return ep

    def end_endpoint(self, url: str, method: str = "GET") -> None:
        key = self._key(url, method)
        with self._lock:
            ep = self._endpoints.get(key)
            if ep:
                ep.scan_ended = datetime.now().isoformat(timespec="seconds")

    # -- layer / param / request recording --------------------------------
    def record_layer(self, url: str, layer_id: str,
                     method: str = "GET", status: str = "ran",
                     detail: str = "") -> None:
        if not self._enabled:
            return
        with self._lock:
            ep = self._start_if_absent(url, method)
            ep.record_layer(layer_id, status, detail)

    def touch_layer(self, url: str, layer_id: str,
                    method: str = "GET", detail: str = "") -> None:
        # Phase 108: every layer boundary marks the current layer so the
        # Requester can attribute its requests (see module-level helpers).
        set_current_layer(layer_id)
        if not self._enabled:
            return
        with self._lock:
            ep = self._start_if_absent(url, method)
            ep.touch_layer(layer_id, detail)

    def record_param(self, url: str, param: str, in_body: bool = False,
                     method: str = "GET", reflected: bool | None = None,
                     context: str | None = None,
                     payload_class: str | None = None,
                     payloads_sent: int = 0,
                     confirmed: bool | None = None) -> None:
        if not self._enabled:
            return
        with self._lock:
            ep = self._start_if_absent(url, method)
            pc = ep.record_param(param, in_body)
            if reflected is not None:
                pc.reflected = pc.reflected or reflected
            if context and not pc.context:
                pc.context = context
            elif context:
                # Keep the first non-trivial context; if it was html_element
                # and we now have something more specific, upgrade.
                if pc.context == "html_element" and context != "html_element":
                    pc.context = context
            if payload_class:
                pc.payload_classes.add(payload_class)
            if payloads_sent:
                pc.payloads_sent += payloads_sent
            if confirmed:
                pc.confirmed = True

    def record_request(self, url: str, method: str = "GET") -> None:
        if not self._enabled:
            return
        with self._lock:
            ep = self._start_if_absent(url, method)
            ep.requests += 1

    def record_finding(self, url: str, method: str = "GET") -> None:
        if not self._enabled:
            return
        with self._lock:
            ep = self._start_if_absent(url, method)
            ep.findings += 1

    # -- query -------------------------------------------------------------
    @staticmethod
    def _key(url: str, method: str) -> str:
        return f"{method.upper()} {url}"

    def _start_if_absent(self, url: str, method: str) -> EndpointCoverage:
        key = self._key(url, method)
        ep = self._endpoints.get(key)
        if ep is None:
            ep = EndpointCoverage(url, method)
            self._endpoints[key] = ep
        return ep

    def endpoints(self) -> list[EndpointCoverage]:
        with self._lock:
            return list(self._endpoints.values())

    # -- summary -----------------------------------------------------------
    def summary(self) -> dict:
        """Machine-readable coverage summary.

        Top-level keys:
          - endpoints: list of per-endpoint dicts
          - totals: aggregate counts
          - layer_coverage: layer_id -> # endpoints where it ran
          - missing_layers: layer_id -> # endpoints where it did NOT run
        """
        with self._lock:
            eps = [ep.to_dict() for ep in self._endpoints.values()]

        total_endpoints = len(eps)
        total_params = sum(len(ep["params"]) for ep in eps)
        total_reflected = sum(
            1 for ep in eps for p in ep["params"].values()
            if p["reflected"]
        )
        total_confirmed = sum(
            1 for ep in eps for p in ep["params"].values()
            if p["confirmed"]
        )
        total_requests = sum(ep["requests"] for ep in eps)
        total_findings = sum(ep["findings"] for ep in eps)
        total_payloads = sum(
            p["payloads_sent"] for ep in eps for p in ep["params"].values()
        )

        # Per-layer coverage across endpoints.
        layer_ran: dict[str, int] = {lid: 0 for lid, _, _ in LAYERS}
        layer_missing: dict[str, int] = {lid: 0 for lid, _, _ in LAYERS}
        for ep in eps:
            for lid, _, _ in LAYERS:
                if lid in ep["layers"]:
                    layer_ran[lid] += 1
                else:
                    layer_missing[lid] += 1

        # All distinct payload classes observed.
        all_classes: set[str] = set()
        for ep in eps:
            for p in ep["params"].values():
                all_classes.update(p["payload_classes"])

        return {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "totals": {
                "endpoints": total_endpoints,
                "parameters": total_params,
                "reflected": total_reflected,
                "confirmed": total_confirmed,
                "requests": total_requests,
                "findings": total_findings,
                "payloads_dispatched": total_payloads,
                "payload_classes": sorted(all_classes),
            },
            "layer_coverage": layer_ran,
            "layer_missing": layer_missing,
            "endpoints": eps,
        }

    # -- HTML rendering ----------------------------------------------------
    def to_html(self) -> str:
        """Render a coverage section for the HTML report.

        Shows three tables:
          1. Layer coverage matrix (which layers ran on how many endpoints).
          2. Per-endpoint summary (params, reflection, payloads, findings).
          3. Per-parameter detail (only for endpoints with params).
        """
        s = self.summary()
        t = s["totals"]
        lc = s["layer_coverage"]
        lm = s["layer_missing"]
        eps = s["endpoints"]

        # -- Layer coverage matrix ----------------------------------------
        # Group by phase for readability.
        phase_groups: dict[str, list[tuple[str, str]]] = {}
        for lid, name, phase in LAYERS:
            phase_groups.setdefault(phase, []).append((lid, name))

        layer_rows = []
        for phase in sorted(phase_groups.keys()):
            entries = phase_groups[phase]
            ran_in_phase = sum(lc[lid] for lid, _ in entries)
            total_in_phase = len(entries) * max(t["endpoints"], 1)
            pct = (ran_in_phase / total_in_phase * 100) if total_in_phase else 0
            layer_rows.append(
                f'<tr class="phase-row"><td colspan="4">'
                f'<strong>{_html.escape(phase)}</strong> '
                f'&mdash; {ran_in_phase}/{total_in_phase} '
                f'({pct:.0f}%)</td></tr>'
            )
            for lid, name in entries:
                ran = lc[lid]
                miss = lm[lid]
                total = ran + miss
                pct = (ran / total * 100) if total else 0
                # Color-code: green >=80%, yellow >=40%, red <40%.
                cls = ("cov-high" if pct >= 80
                       else "cov-med" if pct >= 40
                       else "cov-low")
                bar = (f'<div class="cov-bar"><div class="cov-fill {cls}"'
                       f' style="width:{pct:.0f}%"></div></div>')
                layer_rows.append(
                    f'<tr><td><code>{_html.escape(lid)}</code></td>'
                    f'<td>{_html.escape(name)}</td>'
                    f'<td>{ran}/{total}</td>'
                    f'<td>{bar}<span class="cov-pct">{pct:.0f}%</span></td></tr>'
                )
        layer_rows_html = "\n".join(layer_rows)

        # -- Endpoint summary ---------------------------------------------
        ep_rows = []
        for ep in eps:
            params = list(ep["params"].values())
            n_params = len(params)
            n_refl = sum(1 for p in params if p["reflected"])
            n_conf = sum(1 for p in params if p["confirmed"])
            n_payloads = sum(p["payloads_sent"] for p in params)
            n_layers = len(ep["layers"])
            # Layer coverage % for this endpoint.
            layer_pct = (n_layers / len(LAYERS) * 100) if LAYERS else 0
            crawled_badge = (' <span class="badge-crawled">crawled</span>'
                             if ep["crawled"] else "")
            ep_rows.append(
                f'<tr><td><code>{_html.escape(ep["url"])}</code>'
                f'{crawled_badge}'
                f'</td>'
                f'<td>{_html.escape(ep["method"])}</td>'
                f'<td>{n_layers}/{len(LAYERS)} '
                f'<span class="cov-pct">({layer_pct:.0f}%)</span></td>'
                f'<td>{n_params}</td>'
                f'<td>{n_refl}</td>'
                f'<td>{n_conf}</td>'
                f'<td>{n_payloads}</td>'
                f'<td>{ep["requests"]}</td>'
                f'<td>{ep["findings"]}</td></tr>'
            )
        ep_rows_html = "\n".join(ep_rows) if ep_rows else \
            '<tr><td colspan="9">No endpoints scanned.</td></tr>'

        # -- Per-parameter detail (only for endpoints with params) --------
        param_blocks = []
        for ep in eps:
            params = list(ep["params"].values())
            if not params:
                continue
            rows = []
            for p in params:
                classes = ", ".join(p["payload_classes"]) or "&mdash;"
                refl = '<span class="refl-yes">yes</span>' if p["reflected"] \
                    else '<span class="refl-no">no</span>'
                conf = '<span class="conf-yes">CONFIRMED</span>' if p["confirmed"] \
                    else "&mdash;"
                rows.append(
                    f'<tr><td><code>{_html.escape(p["name"])}</code>'
                    f'<span class="param-loc">{"body" if p["in_body"] else "query"}</span></td>'
                    f'<td>{refl}</td>'
                    f'<td>{_html.escape(p["context"] or "&mdash;")}</td>'
                    f'<td>{p["payloads_sent"]}</td>'
                    f'<td><code>{classes}</code></td>'
                    f'<td>{conf}</td></tr>'
                )
            param_blocks.append(
                f'<details class="param-detail"><summary>'
                f'Parameters for <code>{_html.escape(ep["url"])}</code>'
                f' ({len(params)})</summary>'
                f'<table class="param-table">'
                f'<tr><th>Param</th><th>Reflected</th><th>Context</th>'
                f'<th>Payloads</th><th>Classes</th><th>Status</th></tr>'
                + "\n".join(rows) +
                f'</table></details>'
            )
        param_html = "\n".join(param_blocks)

        # Overall coverage score: average of layer coverage percentages.
        overall = (sum(lc.values()) /
                   (len(LAYERS) * max(t["endpoints"], 1)) * 100
                   ) if t["endpoints"] else 0
        overall_cls = ("cov-high" if overall >= 80
                       else "cov-med" if overall >= 40
                       else "cov-low")

        return f"""
<section class="coverage">
<h2>Scan Coverage Report</h2>
<div class="cov-overview">
  <div class="cov-overall">
    <div class="cov-overall-label">Overall Layer Coverage</div>
    <div class="cov-overall-score {overall_cls}">{overall:.0f}%</div>
  </div>
  <div class="cov-stats">
    <span><strong>{t["endpoints"]}</strong> endpoints</span>
    <span><strong>{t["parameters"]}</strong> params</span>
    <span><strong>{t["reflected"]}</strong> reflected</span>
    <span><strong>{t["confirmed"]}</strong> confirmed</span>
    <span><strong>{t["payloads_dispatched"]}</strong> payloads sent</span>
    <span><strong>{t["requests"]}</strong> requests</span>
    <span><strong>{t["findings"]}</strong> findings</span>
    <span><strong>{len(t["payload_classes"])}</strong> payload classes</span>
  </div>
</div>

<h3>Detection Layer Coverage</h3>
<table class="cov-layer-table">
<tr><th>Layer ID</th><th>Name</th><th>Endpoints</th><th>Coverage</th></tr>
{layer_rows_html}
</table>

<h3>Per-Endpoint Summary</h3>
<table class="cov-ep-table">
<tr><th>URL</th><th>Method</th><th>Layers</th><th>Params</th><th>Reflected</th><th>Confirmed</th><th>Payloads</th><th>Requests</th><th>Findings</th></tr>
{ep_rows_html}
</table>

<h3>Per-Parameter Detail</h3>
{param_html or '<p class="muted">No parameters probed.</p>'}

<p class="cov-help">
  <strong>How to read this:</strong> "Layer Coverage" shows which detection
  layers actually ran on each endpoint -- a low percentage means the scan
  may have skipped checks (e.g. OOB blind injection disabled, or no DOM
  engine available).  "Reflected" tracks whether the probe marker appeared
  in the response; "Confirmed" means a payload actually executed.  Zero
  findings with high layer coverage = the endpoint was tested thoroughly
  and is genuinely clean.
</p>
</section>
"""

    def to_json_dict(self) -> dict:
        """JSON-serializable coverage dict for the JSON/SARIF report."""
        return self.summary()
