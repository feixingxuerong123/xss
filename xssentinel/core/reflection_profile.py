"""Reflection profile: sandwich-marker probing + filter feedback (Phase 31).

Borrowed from DalFox's sandwich-marker classification and OWASP ZAP's
strip-feedback retry loop: after the plain alphanumeric marker reflects,
ONE extra probe carrying the special characters ``"'<>()=/;`` reveals
WHICH characters survive the server's filter/encoder.  The resulting
profile drives the engine instead of blind enumeration:

  * ``prioritize_payloads``   -- payloads whose critical characters were
    stripped/encoded move to the back (e.g. double quote gone -> push
    single-quote breakouts to the front).
  * ``prioritize_transforms`` -- transform families that can restore the
    missing characters are surfaced first (e.g. ``<`` HTML-encoded ->
    ``mixed_case`` cannot help, ``html5_entities``/``fullwidth`` can).

The probe costs one extra request per reflected parameter and is skipped
entirely when the simple marker was already HTML-escaped (the Phase 27-1
early-stop covers that case).  This is a PRIORITIZATION signal only --
it never confirms or denies a vulnerability by itself, so a mis-classified
window can only reorder the probe queue, never change the verdict.
"""
from __future__ import annotations

import re

# Special characters probed by the sandwich marker.  The backtick is
# included because the generator (Phase 32) needs to know whether the
# tagged-template call alert`1` -- the paren-free execution form -- can fire.
PROBE_CHARS = "\"'><>()=/;`"

# HTML entities (lowercase) each probed char may come back as.
_ENTITY_MAP: dict[str, tuple[str, ...]] = {
    '"': ("&quot;", "&#34;", "&#x22;"),
    "'": ("&#39;", "&#x27;", "&apos;"),
    "<": ("&lt;", "&amp;lt;"),
    ">": ("&gt;", "&amp;gt;"),
    "&": ("&amp;",),
    "(": ("&lpar;", "&#40;", "&amp;lpar;"),
    ")": ("&rpar;", "&#41;", "&amp;rpar;"),
    "=": ("&eq;", "&#61;", "&amp;eq;"),
    "/": ("&#47;", "&sol;", "&amp;sol;"),
    ";": ("&semi;", "&amp;semi;"),
}

# Percent-encoding escapes (lowercase) -- servers that urlencode on output.
_PCT_MAP: dict[str, str] = {
    '"': "%22", "'": "%27", "<": "%3c", ">": "%3e",
    "(": "%28", ")": "%29", "=": "%3d", "/": "%2f", ";": "%3b",
}

# Transform families that can restore a character the filter removed.
# Ordered by realistic payoff (entity variants first, deep encodings last).
_RESTORE_LT_ENCODED = [
    "html5_entities", "html_entity_named", "fullwidth", "utf7",
    "interleave_nulls", "js_unicode", "css_unicode", "url_encode_selective",
]
_RESTORE_LT_STRIPPED = [
    "fullwidth", "interleave_nulls", "url_encode_selective",
    "js_unicode", "css_unicode", "html5_entities", "utf7",
]
_RESTORE_QUOTE = [
    "url_encode_selective", "js_unicode", "html_entity_named",
    "html5_entities",
]
_RESTORE_PAREN = ["url_encode_selective", "js_unicode"]


def build_probe(token: str) -> str:
    """Sandwich probe value: unique token followed by every probed char."""
    return token + PROBE_CHARS


def profile_reflection(response_text: str, token: str) -> dict | None:
    """Classify how the sandwich probe came back.

    Returns a profile dict with ``reflected``/``full_reflection`` flags and
    the per-character disposition lists, or None when the input is empty.
    The window right after the token is analyzed as a SET (order-insensitive)
    because null-byte stripping and whitespace normalization can reorder
    characters; this keeps the classification stable on odd servers.
    """
    if not response_text or not token:
        return None
    idx = response_text.find(token)
    if idx == -1:
        return {
            "reflected": False,
            "full_reflection": False,
            "chars_kept": [],
            "chars_stripped": list(PROBE_CHARS),
            "chars_encoded": [],
            "rcdata_tag": None,
            "probe": build_probe(token),
            "detail": "sandwich probe token not reflected",
        }
    # Window right after the token: enough room for entity expansions
    # (&quot; is 6 chars) without reaching into unrelated page content.
    # Phase 95: the raw window must NOT swallow the page's own markup --
    # the "</div></body>" that usually follows the reflection put literal
    # "<"/">" inside the window, so those characters were classified as
    # KEPT even when the encoder had encoded the probe's own copies,
    # which kept is_marker_escaped-style convergence from ever firing.
    # Cut the window at the first STRUCTURAL tag start: "<" followed by
    # a letter, "/" or "!" (the probe's own unencoded "<" is followed by
    # ">" and is preserved).  Contamination after the cut can only make
    # a character look KEPT (conservative: no convergence), never the
    # other way round.
    raw = response_text[idx + len(token):
                        idx + len(token) + len(PROBE_CHARS) * 8 + 8]
    _cut = re.search(r"<(?=[a-zA-Z/!])", raw)
    if _cut:
        raw = raw[:_cut.start()]
    window = raw.lower()

    kept: list[str] = []
    stripped: list[str] = []
    encoded: list[str] = []
    for ch in PROBE_CHARS:
        entities = _ENTITY_MAP.get(ch, ())
        pct = _PCT_MAP.get(ch, "")
        # Phase 95: ENTITY EVIDENCE WINS over a bare character.  When a
        # reflection sits inside a quoted attribute, the page's own closing
        # quote and tag end (">) trail the probe value INSIDE the window,
        # so a bare ch in window no longer proves the probe's ch survived:
        # the probe's copy may be encoded right next to it.  Classify as
        # encoded whenever an entity/pct form of ch is present; a bare ch
        # only means KEPT when the encoder left NO trace of it.
        if any(e in window for e in entities) or (pct and pct in window):
            encoded.append(ch)
        elif ch in window:
            kept.append(ch)
        else:
            stripped.append(ch)

    full = len(kept) == len(PROBE_CHARS)
    parts = []
    if kept:
        parts.append("kept=" + "".join(kept))
    if stripped:
        parts.append("stripped=" + "".join(stripped))
    if encoded:
        parts.append("encoded=" + "".join(encoded))
    # Phase 96: is the reflection point inside an RCDATA element?  Kept as
    # part of the profile so scanner layers can surface breakout payloads
    # without a second probe request.
    return {
        "reflected": True,
        "full_reflection": full,
        "chars_kept": kept,
        "chars_stripped": stripped,
        "chars_encoded": encoded,
        "rcdata_tag": detect_rcdata_tag(response_text, idx),
        "probe": build_probe(token),
        "detail": "reflection profile: " + (", ".join(parts) if parts
                                            else "nothing survived"),
    }


def prioritize_payloads(profile: dict, candidates: list) -> list:
    """Stable reorder: payloads using missing characters go to the back.

    A payload whose critical special characters were stripped/encoded is
    unlikely to fire, so it should not consume the front of the budget.
    Stable sort keeps the original (curated) order among equal scores.
    """
    if profile.get("full_reflection"):
        return candidates
    kept = set(profile.get("chars_kept", []))

    def _score(c) -> int:
        pl = c.get("payload", "") if isinstance(c, dict) else str(c)
        return sum(1 for ch in set(pl) if ch in PROBE_CHARS and ch not in kept)

    return sorted(candidates, key=_score)


def prioritize_transforms(profile: dict) -> list[str] | None:
    """Transform families to try FIRST given the observed filtering.

    Returns None when the reflection is complete (nothing to restore) or
    no observed loss maps to a known restore family -- the caller then
    keeps its default chain order untouched.
    """
    if profile.get("full_reflection"):
        return None
    kept = set(profile.get("chars_kept", []))
    encoded = set(profile.get("chars_encoded", []))

    pri: list[str] = []

    def _add(names: list[str]) -> None:
        for n in names:
            if n not in pri:
                pri.append(n)

    if "<" not in kept:
        if "<" in encoded:
            _add(_RESTORE_LT_ENCODED)
        else:
            _add(_RESTORE_LT_STRIPPED)
    if '"' not in kept or "'" not in kept:
        _add(_RESTORE_QUOTE)
    if "(" not in kept or ")" not in kept:
        _add(_RESTORE_PAREN)
    return pri or None


# ---------------------------------------------------------------------------
# Phase 95: profile-backed escape convergence
# ---------------------------------------------------------------------------
#
# ``is_marker_escaped`` (Phase 27-1) inspects the characters ADJACENT to the
# marker.  For a plain alphanumeric marker echoed inside an element body the
# neighbours are the page's own structural characters (">" of the opening
# tag, "<" of the closing tag) -- a server never encodes those -- so the
# check returns False on exactly the endpoints it was written for
# (html.escape-style output encoding) and the convergence budget never
# kicked in: escaped benchmark cases paid ~203 requests instead of ~10.
#
# The sandwich probe is the authoritative signal instead: it carries
# PROBE_CHARS itself, so a working encoder MUST reflect them as entities.
# The table below lists, per reflection context, the characters that are
# REQUIRED to break out.  Only ENCODED dispositions count -- a STRIPPED
# character can sometimes be restored by a transform family (fullwidth,
# utf7, ...), so stripping alone must not converge (keep probing; FN risk).

PROFILE_CONVERGE_CRITICAL: dict[str, str] = {
    # element bodies: "<" opens a tag; nothing else can escape the text node
    "html_element": "<",
    "svg_context": "<",
    "math_context": "<",
    # quoted attributes: only the enclosing quote can close the value
    # ("<" and ">" inside a quoted value are inert to the HTML tokenizer)
    "html_attribute_dq": '"',
    "html_attribute_sq": "'",
    # unquoted attribute value: ">" terminates the tag (and the value)
    "html_attribute_noquote": ">",
    # deliberately ABSENT: url_href/url_javascript/meta_refresh
    # (javascript: needs no special char), script_block/script_string/cdata
    # (string breakout + </script> interplay), html_comment ("-" is not
    # probed), css_context, template_* ("{}" not probed).
}


def profile_says_encoded(profile: dict | None, context: str | None) -> bool:
    """True when the sandwich profile proves the context cannot be escaped.

    Every critical character for this context must come back ENCODED.  A
    full reflection (nothing lost), a missing profile, or a context with
    no critical set returns False -- the caller keeps the full budget.
    """
    if not profile or profile.get("full_reflection"):
        return False
    crit = PROFILE_CONVERGE_CRITICAL.get(context or "")
    if not crit:
        return False
    encoded = set(profile.get("chars_encoded", []))
    return all(ch in encoded for ch in crit)


# ---------------------------------------------------------------------------
# Phase 96: RCDATA detection -> breakout payload surfacing
# ---------------------------------------------------------------------------
#
# Inside <textarea>/<title>/<xmp> (RCDATA elements) browsers treat the
# content as plain text, so a DIRECT injection (<svg onload=...>) is inert
# and the verifier correctly rejects it.  But the classic RCDATA BREAKOUT
# -- "</textarea><svg onload=...>" -- is fully executable whenever the
# server echoes raw markup, and it is a textbook OWASP vector.  The payload
# corpus had NO breakout entry, so RCDATA endpoints never saw one: the
# verifier's RCDATA gate (which by design still confirms a breakout AFTER
# the closing tag) was never given the chance.  Net effect: 4 benchmark
# cases were silent FNs and any real RCDATA endpoint would have been
# missed too.
#
# The fix mirrors Phase 95's shape: detect the situation from the marker
# reflection (zero extra requests), then let the scanner SURFACE a
# breakout variant of the already-chosen payloads.  Detection reuses the
# verifier's backwards-scan semantics so the two layers agree.

RCDATA_TAGS: tuple[str, ...] = ("textarea", "title", "xmp")


def detect_rcdata_tag(response_text: str, token_idx: int) -> str | None:
    """Return the RCDATA element name when token_idx sits inside one.

    Backwards scan (same semantics as verifier._in_rcdata_raw): find the
    last unclosed <textarea>/<title>/<xmp> opening tag before the token.
    Returns None when the token is NOT inside an RCDATA element.
    """
    if not response_text or token_idx < 0 or token_idx >= len(response_text):
        return None
    before = response_text[:token_idx].lower()
    for tag_name in RCDATA_TAGS:
        last_open = before.rfind("<" + tag_name)
        if last_open == -1:
            continue
        if before.find("</" + tag_name + ">", last_open) == -1:
            return tag_name
    return None


def breakout_prefix(tag_name: str | None) -> str:
    """Closing-tag prefix that escapes the RCDATA element (empty if none)."""
    if tag_name in RCDATA_TAGS:
        return "</" + tag_name + ">"
    return ""


def profile_says_rcdata(profile: dict | None) -> str | None:
    """The RCDATA tag name when the marker reflected inside one, else None."""
    if not profile:
        return None
    return profile.get("rcdata_tag") or None


def surface_rcdata_breakouts(profile: dict | None, bases: list,
                             limit: int = 4) -> tuple[list, str | None]:
    """Phase 96: prepend ``</tag>`` breakout variants for RCDATA reflections.

    Direct injections inside <textarea>/<title>/<xmp> are inert text, but
    the closing-tag breakout is fully executable when the server echoes
    raw markup.  The corpus has no breakout entries, so without this the
    scanner never attempts the one vector that works there (observed as
    FNs on RCDATA benchmark endpoints).

    Takes the first ``limit`` bases, prefixes each with the RCDATA closing
    tag, dedups, and puts the variants at the FRONT of the queue: on a
    raw-echoing endpoint the first variant typically confirms, shrinking
    the request cost from the full budget to a handful.  On an escaping
    server the variants are inert and the Phase 95 encoded-convergence
    still caps the budget independently.

    Returns (new_bases, breakout_tag); new_bases is the original list
    object when there is nothing to do.
    """
    tag = profile_says_rcdata(profile)
    if not tag or not bases:
        return bases, None
    prefix = breakout_prefix(tag)
    seen: set[str] = set()
    variants: list = []
    for b in bases[:limit]:
        if not isinstance(b, dict):
            continue
        pl = b.get("payload") or ""
        if not pl:
            continue
        variant_payload = prefix + pl
        if variant_payload in seen:
            continue
        seen.add(variant_payload)
        v = dict(b)
        v["payload"] = variant_payload
        # Observable payload class; the scan context itself (event
        # handling, verifier routing) is carried by the outer variable.
        v["context"] = "rcdata_breakout"
        v["rcdata_tag"] = tag
        variants.append(v)
    if not variants:
        return bases, None
    return variants + list(bases), tag


def surface_rcdata_breakout_strs(profile: dict | None, cands: list,
                                 limit: int = 4) -> tuple[list, str | None]:
    """String-list variant of :func:`surface_rcdata_breakouts`.

    The async scanner keeps its candidate queue as plain payload strings
    (sync uses payload dicts), so the breakout prefixing is duplicated in
    the minimal string form.  Same contract: variants lead, dedup, and
    the original list object is returned untouched when there is nothing
    to do.
    """
    tag = profile_says_rcdata(profile)
    if not tag or not cands:
        return cands, None
    prefix = breakout_prefix(tag)
    seen: set = set(cands)
    variants: list = []
    for pl in cands[:limit]:
        if not pl:
            continue
        vp = prefix + pl
        if vp in seen:
            continue
        seen.add(vp)
        variants.append(vp)
    if not variants:
        return cands, None
    return variants + list(cands), tag
