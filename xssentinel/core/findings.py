"""Shared finding dataclass + the default transform ladder.

Extracted from scanner.py (Phase 40) so scanner mixins can import them
without a circular import (scanner imports the mixins; mixins import
this module).
"""
from __future__ import annotations

# Evidence tiers a finding may state in its `evidence_class` key.  The four
# browser-* ones come from `scanner._grade_evidence()` reading the headless
# replay outcome; this one cannot, because its proof is a real victim browser
# fetching an out-of-band URL -- a channel the dialog hook never sees (CSP that
# blocks alert() does not block a resource load).  Lives here so the mixins can
# name it without importing scanner (circular).
EVIDENCE_OOB = "oob-confirmed"

# The strongest claim a `verify_semantic` / pure-Python-model finding can make:
# the HTML model says the payload landed in an executable context, and NO
# browser was ever pointed at it.  This is not `browser-unavailable` ("nothing
# looked"), and it is not `browser-executed` -- calling a model verdict either of
# those misstates the evidence in one of two directions, and both directions
# have already happened once in this codebase.
EVIDENCE_MODEL = "model-only"

# Nothing looked at all: no browser, no replay, no model verdict.  Header audits
# (CSP / CORS / XS-Leaks) and pure reflection checks land here.  Sites use this
# CONSTANT rather than the helper because the helper also appends
# "execution unverified" to the detail -- prose that means nothing for a finding
# that never claimed execution, and that a client would read as hedging.
EVIDENCE_NO_BROWSER = "browser-unavailable"

# What a captured secret is replaced with in a finding, a PoC and a stored job.
REDACTED = "<redacted-credential>"

_CRED_EXACT = {"pass", "passwd", "pwd", "pin", "otp", "ssn", "cvv",
               "password", "secret", "auth", "authorization", "cookie"}
_CRED_SUBSTR = ("password", "passwd", "secret", "private_key", "client_secret",
                "authorization", "card_number", "cc_number", "security_code",
                "cvv2", "bearer")


def _grade_evidence(headless, confidence: str, detail: str,
                    model_judged: bool = False):
    """Turn "what the browser did" into a stated tier plus a confidence.

    Two questions were collapsed into one label here: how bad the issue is if it
    is real (severity) and how sure we are that it is real (confidence).  Both
    were hard-coded to high/high at the finding site, so a finding that the real
    Chromium REFUTED -- it loaded the page, no dialog carried the probe token --
    reached the client with the same confidence as one whose dialog did.

    Severity is deliberately NOT touched by this function, and that is not
    caution: `benchmark/runner.py` reads severity as "was this detected", so
    expressing doubt through severity would convert true positives into silent
    false negatives -- trading one honesty problem for a worse one.  Doubt
    belongs in `confidence` and in the named `evidence_class`, both of which the
    report prints.

    `outcome` is what makes the difference expressible at all: `confirmed: False`
    alone conflates "replayed and did not fire" with "never replayed", and only
    the first of those is evidence against the finding.

    Lives in this module (not scanner.py) because the scanner mixins emit
    findings too and cannot import scanner -- this module is the cycle-free
    layer they all share.

    `model_judged=True` is for callers whose whole proof is `verify_semantic` /
    the pure-Python HTML model.  They must not land on the plain
    "execution unverified" clause, which would erase the one judgement that WAS
    made; say "no browser replayed it" instead.  An explicit parameter, never
    inferred from the shape of `headless` -- guessing there would re-create the
    exact mislabeling this function exists to prevent.
    """
    h = headless or {}
    outcome = h.get("outcome")
    if not outcome:                      # an older/other verifier dict
        if h.get("confirmed"):
            outcome = "fired"
        elif not h.get("available"):
            outcome = "unavailable"
        elif "error" in (h.get("detail") or "").lower():
            outcome = "errored"
        else:
            outcome = "not-fired"
    if outcome == "fired":
        return "browser-executed", "high", detail
    if outcome == "not-fired":
        return ("browser-refuted", "low",
                detail + " | browser replay did NOT reproduce execution: report"
                         " as unconfirmed, and note this is not proof of absence")
    if outcome == "errored":
        return ("browser-error", confidence,
                detail + " | browser replay errored, so the strongest evidence"
                         " class is MISSING from this finding")
    if model_judged:
        return (EVIDENCE_MODEL, confidence,
                detail + " | no real-browser replay: the pure-Python HTML model"
                         " judged this an executable context, which is weaker"
                         " than observed execution")
    return (EVIDENCE_NO_BROWSER, confidence,
            detail + " | no browser replay available; execution unverified")


_DEFAULT_TRANSFORMS = [
    [],  # base
    ["mixed_case"],
    ["html_entity_named"],
    ["url_encode_selective"],
    ["comment_break"],
    ["null_byte"],
    ["mixed_case", "comment_break"],
    ["fullwidth"],
    ["constructor_escape"],
    ["interleave_nulls"],
    ["utf7"],
    ["js_unicode"],
    ["css_unicode"],
    ["html5_entities"],
    ["duplicate_attribute"],
]



class Finding:
    def __init__(self, **kw):
        self.data = kw

    def to_dict(self):
        return self.data


def _norm(url: str) -> str:
    """Normalize a URL for comparison/dedup: drop fragment, default port, and
    lowercase scheme+host.  Query string is kept (so /p?a=1 vs /p?b=2 differ)
    but NOT sorted (param order rarely matters for dedup grouping)."""
    from urllib.parse import urlparse, urlunparse
    p = urlparse(url)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    # strip default ports so http://h:80/p == http://h/p
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, p.params, p.query, ""))


def _proof(resp, method, param, payload):
    return {
        "status": resp.status_code,
        "method": method,
        "param": param,
        "payload": payload,
        "snippet": _safe_snippet(resp.text, payload),
    }


def _safe_snippet(text, payload, width=120):
    i = text.find(payload[:30] if payload else "")
    if i == -1:
        return ""
    return text[max(0, i - 40): i + width].replace("\n", " ")


def _is_credential_field(name: str) -> bool:
    """True when a form-field or header NAME says its value is a secret.

    Short/ambiguous names match exactly -- a substring rule would redact
    `compass`, `typing` and `mapping` and quietly break the replays those fields
    are needed for.  Long names are distinctive enough to match anywhere.

    CSRF/nonce fields are deliberately NOT here: they are what makes a replay
    pass, and a one-time token is not the kind of secret that must never appear
    in a report.
    """
    n = (name or "").strip().lower()
    return n in _CRED_EXACT or any(h in n for h in _CRED_SUBSTR)


def attach_replay_ctx(finding, tl) -> None:
    """Phase 48: attach the OTHER (non-target) form fields of the request
    that produced ``finding`` -- typically CSRF/hidden tokens -- so PoC
    generators can emit a replay that passes CSRF checks.

    ``tl`` is the scanner's per-thread context holder (threading.local)
    whose ``reqctx`` was set by _scan_param for the endpoint currently
    being probed.  Guards: only POST-ish findings whose url+method match
    the live context, and only when the endpoint actually had extra body
    fields besides the injected parameter.

    Fields whose name says it holds a credential are masked, not dropped: this
    dict is copied verbatim into the curl and HTML PoC, so scanning a login form
    used to write the captured password into a client deliverable that is
    forwarded, archived and re-read for months.  The NAME stays so the operator
    can see the field exists and supply a value.
    """
    d = finding.data if hasattr(finding, "data") else finding
    if d.get("method") in (None, "GET") or "csrf_fields" in d:
        return
    rc = getattr(tl, "reqctx", None) if tl is not None else None
    if not (rc and rc.get("url") == d.get("url")
            and rc.get("method") == d.get("method")):
        return
    param = d.get("param")
    extra = {k: (REDACTED if _is_credential_field(k) else v)
             for k, v in (rc.get("data") or {}).items()
             if v is not None and k != param}
    if extra:
        d["csrf_fields"] = extra

