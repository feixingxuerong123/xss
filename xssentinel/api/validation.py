"""Request validation for the XSSentinel REST API (Phase 29-1).

Centralises input validation so every route handler can assert that
inbound JSON conforms to the expected schema before touching the
scanner or job manager.  This protects the service from malformed
client payloads (accidental or malicious) that could otherwise trigger
exceptions deep in the report renderer or exhaust server memory.

Three layers of defence are provided:

  1. **Body size cap** -- :func:`assert_body_size` rejects oversized
     request bodies before parsing JSON (DoS mitigation).
  2. **Finding schema** -- :func:`validate_findings` checks each finding
     dict for required fields and types so the report writer never sees
     a malformed record.
  3. **CORS allowlist** -- :func:`cors_origin_for` returns the
     ``Access-Control-Allow-Origin`` value only when the request Origin
     matches the configured allowlist, blocking arbitrary cross-site
     callers.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Body size limits
# ---------------------------------------------------------------------------
# Default cap on inbound request body size (16 MiB).  Generous enough for
# verify-fix requests carrying a few hundred findings, but blocks
# multi-gigabyte payloads that would exhaust memory.
DEFAULT_MAX_BODY_BYTES: int = 16 * 1024 * 1024

# Cap on the number of findings a single request may carry.  A scan of a
# large site rarely exceeds a few thousand findings; 10k is a sane ceiling.
DEFAULT_MAX_FINDINGS: int = 10_000


def assert_body_size(raw: bytes | str | None,
                     max_bytes: int = DEFAULT_MAX_BODY_BYTES) -> tuple[bool, str]:
    """Return ``(ok, error_message)`` for a raw request body.

    ``ok`` is True when the body is absent (length 0) or within the cap.
    A non-empty body exceeding ``max_bytes`` yields ``ok=False`` with a
    descriptive error string suitable for the API response.
    """
    if raw is None:
        return True, ""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if len(raw) > max_bytes:
        return False, (
            f"request body too large: {len(raw)} bytes exceeds "
            f"maximum of {max_bytes} bytes"
        )
    return True, ""


# ---------------------------------------------------------------------------
# Finding schema validation
# ---------------------------------------------------------------------------
# Required fields for a finding dict.  The report writer and SARIF/CSV/HTML
# builders all read these keys, so their presence and type matter.
_REQUIRED_FIELDS: dict[str, type] = {
    "type": str,
    "severity": str,
    "url": str,
}

# Optional but validated fields (validated only when present).
_OPTIONAL_FIELDS: dict[str, type] = {
    "param": str,
    "method": str,
    "context": str,
    "confidence": str,
    "detail": str,
    "evidence": str,
    "payload": str,
    "poc": (dict, str),
}

_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"high", "medium", "low", "info"})

_VALID_TYPES: frozenset[str] = frozenset({
    "reflected", "stored", "dom", "dom_dynamic", "blind", "mutation_xss",
    "dom_clobber", "template_ssti_angularjs", "template_ssti_vue",
    "template_ssti_svelte", "template_ssti_ember", "template_ssti",
    "jsonp_xss", "csp_bypass", "polyglot_reflection", "postmessage_xss",
    "prototype_pollution", "service_worker_xss", "web_worker_xss",
    "open_redirect_xss", "header_xss", "path_xss", "cookie_xss",
    "error_page_xss", "markdown_xss", "second_order", "time_based_xss",
    "fuzzer_triage", "framework_xss", "framework_react_xss",
    "framework_vue_xss", "framework_angular_xss", "framework_svelte_xss",
    "framework_lit_xss",
    "graphql_xss", "graphql_introspection", "websocket_xss",
    "websocket_insecure", "trusted_types_taint_flow",
    "trusted_types_policy_bypass", "trusted_types_no_policy",
    "trusted_types_policy_unused", "trusted_types_violation",
    "csp_nonce_too_short", "csp_nonce_predictable", "csp_nonce_misconfigured",
    "csp_nonce_multi", "cookie_tossing_set_cookie", "cookie_tossing_client",
    "cookie_sink_flow", "sri_missing_script", "sri_missing_script_summary",
    "sri_missing_style", "sri_broken_no_crossorigin", "sri_malformed",
    "sri_insecure_origin", "import_map_user_controlled",
    "import_map_cross_origin", "import_map_insecure_origin",
    "import_map_after_module", "import_map_multiple", "import_map_invalid_json",
    "sanitizer_vulnerable_version", "sanitizer_config_add_script",
    "sanitizer_config_allow_script", "sanitizer_config_add_iframe",
    "sanitizer_config_return_dom", "sanitizer_config_return_dom_fragment",
    "sanitizer_config_allow_unknown_protocols", "sanitizer_config_allow_data_attr",
    "sanitizer_config_keep_content", "sanitizer_output_to_innerhtml",
    "unsanitized_innerhtml_user_source",
    # Phase 30-1: CSS Injection (CSSI) -- exfiltration gadgets + CSSOM sinks.
    "css_font_face_exfil", "css_selector_exfil", "css_import_injection",
    "css_javascript_uri", "css_expression", "css_moz_binding", "css_behavior",
    "css_template_reflection", "cssom_cssText", "cssom_background",
    "cssom_liststyle", "cssom_content", "cssom_cursor",
    "cssom_insertrule", "cssom_insertrule_import", "cssom_adoptedsheets",
    "css_dynamic_exfil_gadget",
    # Phase 30-2: Dangling Markup Injection.
    "dangling_markup_risk", "dangling_markup_potential",
    # Phase 30-4: SVG XSS -- foreignObject / use / set / animate / SMIL.
    "svg_xss_svg_script", "svg_xss_svg_script_external",
    "svg_xss_svg_script_jsuri", "svg_xss_svg_foreignobject_script",
    "svg_xss_svg_foreignobject_iframe", "svg_xss_svg_foreignobject_event",
    "svg_xss_svg_foreignobject_jsuri", "svg_xss_svg_foreignobject",
    "svg_xss_svg_use_jsuri", "svg_xss_svg_use_data",
    "svg_xss_svg_use_external", "svg_xss_svg_set_event",
    "svg_xss_svg_set_href_jsuri", "svg_xss_svg_animate_event",
    "svg_xss_svg_animate_href_jsuri", "svg_xss_svg_animatetransform_event",
    "svg_xss_svg_animatemotion_event", "svg_xss_svg_smil_onbegin",
    "svg_xss_svg_smil_onend", "svg_xss_svg_smil_onrepeat",
    "svg_xss_svg_a_jsuri", "svg_xss_svg_a_data",
    "svg_xss_svg_image_jsuri", "svg_xss_svg_image_data",
    "svg_xss_svg_handler", "svg_xss_svg_listener",
    "svg_xss_svg_discard_jsuri", "svg_xss_svg_discard",
    "svg_xss_svg_onload", "svg_xss_svg_onclick", "svg_xss_svg_event_handler",
    "svg_xss_svg_style_expression", "svg_xss_svg_style_mozbinding",
    "svg_xss_svg_style_behavior", "svg_xss_svg_text_jsuri",
    "svg_xss_svg_tref_jsuri", "svg_xss_svg_altglyph_jsuri",
})


def _check_type(value: Any, expected: type | tuple) -> bool:
    if isinstance(expected, tuple):
        return isinstance(value, expected)
    return isinstance(value, expected)


def validate_findings(findings: Any,
                      max_count: int = DEFAULT_MAX_FINDINGS
                      ) -> tuple[list[dict], list[str]]:
    """Validate a list of finding dicts.

    Returns ``(valid_findings, errors)`` where ``valid_findings`` is the
    list of findings that passed validation (possibly empty) and
    ``errors`` is a list of human-readable error strings (empty on
    success).  When ``findings`` is not a list or exceeds ``max_count``,
    ``valid_findings`` is empty and ``errors`` describes the problem.

    Findings with unknown ``type`` values are still accepted (returned in
    ``valid_findings``) but a warning is appended to ``errors`` -- this
    keeps the API forward-compatible with future finding types without
    silently dropping records.  Only structural problems (missing fields,
    wrong types, invalid severity) cause a finding to be rejected.
    """
    if not isinstance(findings, list):
        return [], ["'findings' must be a list"]
    if len(findings) > max_count:
        return [], [
            f"too many findings: {len(findings)} exceeds maximum of {max_count}"
        ]

    valid: list[dict] = []
    errors: list[str] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errors.append(f"finding[{i}] is not a JSON object")
            continue
        # Required fields.
        missing = [k for k in _REQUIRED_FIELDS if k not in f]
        if missing:
            errors.append(f"finding[{i}] missing required field(s): {missing}")
            continue
        # Type checks on required fields.
        bad_types = []
        for field, expected in _REQUIRED_FIELDS.items():
            if not _check_type(f.get(field), expected):
                bad_types.append(f"{field} (expected {expected.__name__})")
        if bad_types:
            errors.append(f"finding[{i}] has wrong type for: {bad_types}")
            continue
        # Severity must be a known value.
        sev = str(f.get("severity", "")).lower()
        if sev not in _VALID_SEVERITIES:
            errors.append(
                f"finding[{i}] has invalid severity '{sev}'; "
                f"must be one of {sorted(_VALID_SEVERITIES)}"
            )
            continue
        # Optional field type checks.
        opt_bad = []
        for field, expected in _OPTIONAL_FIELDS.items():
            if field in f and not _check_type(f.get(field), expected):
                opt_bad.append(f"{field} (expected {expected})")
        if opt_bad:
            errors.append(f"finding[{i}] has wrong type for: {opt_bad}")
            continue
        # Type warning (non-blocking).
        ftype = f.get("type", "")
        if ftype and ftype not in _VALID_TYPES:
            errors.append(
                f"finding[{i}] warning: unknown type '{ftype}' "
                f"(accepted but may not render correctly in all reports)"
            )
        valid.append(f)
    return valid, errors


# ---------------------------------------------------------------------------
# CORS allowlist
# ---------------------------------------------------------------------------
def parse_cors_origins(raw: str | list[str] | None) -> list[str]:
    """Parse a CORS allowlist from a comma-separated string or list.

    Returns a list of normalised origin strings (no trailing slash).
    ``None`` or empty input yields an empty list (CORS disabled / deny-all).
    """
    if not raw:
        return []
    if isinstance(raw, str):
        items = [o.strip() for o in raw.split(",")]
    else:
        items = [str(o).strip() for o in raw]
    result: list[str] = []
    for o in items:
        if not o:
            continue
        # Strip trailing slash for consistent matching.
        if o.endswith("/") and len(o) > 1:
            o = o[:-1]
        result.append(o)
    return result


def cors_origin_for(request_origin: str | None,
                    allowed: list[str]) -> str | None:
    """Return the CORS ``Access-Control-Allow-Origin`` value or None.

    When ``allowed`` is empty, CORS is disabled and ``None`` is returned
    (the browser will block cross-origin requests).  When ``allowed``
    contains ``"*"``, ``"*"`` is returned for any request origin (but
    ``Allow-Credentials`` must not be combined with ``*`` per the CORS
    spec, so callers should set credentials=False in that case).

    Otherwise the request origin is returned only if it matches one of
    the allowed origins (exact match after trailing-slash normalisation).
    """
    if not request_origin:
        return None
    if not allowed:
        return None
    if "*" in allowed:
        return "*"
    # Normalise the request origin (strip trailing slash).
    norm = request_origin.rstrip("/") if request_origin.endswith("/") else request_origin
    for a in allowed:
        if a == norm:
            return request_origin
    return None
