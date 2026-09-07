"""Automatic pre-encoding pipeline (Phase 34, DalFox-inspired).

Many real-world params carry STRUCTURED values: base64 tokens, JWTs,
JSON-in-base64 blobs.  Injecting a raw payload into such a param usually
fails not because of a WAF but because the app decodes the container and
gets garbage (or never decodes it at all).

This module:
  1. ``detect_structure`` -- classify the ORIGINAL param value into
     ``jwt`` / ``double_b64`` / ``json_b64`` / ``b64`` / ``none``.
  2. ``encode_payload`` -- re-wrap a (marked) payload with the SAME
     container so the app decodes it back to the executable payload.

The scanner fires these pre-encoded probes BEFORE the plain-text payload
loop; a hit there skips the (on structured params almost hopeless) plain
loop entirely.  Ambiguity guard: a plain b64 verdict additionally requires
the decoded text to contain a non-alphanumeric character, so ordinary
words like ``helloworld`` are not mistaken for containers (their decode
is either non-printable or pure alnum).
"""
from __future__ import annotations

import base64
import json
import re

_B64_CHARS = re.compile(r"^[A-Za-z0-9+/\-_]{8,}={0,2}$")
_JWT_RE = re.compile(
    r"^eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-.+/=]*$")

# Field name used when injecting into JSON/JWT containers.
INJECT_FIELD = "xssentinel"

# Base payloads re-wrapped into the container (token-marked by the caller).
PRE_ENCODE_BASES = [
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
]


def _b64decode(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s2 + "=" * (-len(s2) % 4))


def _b64encode(b: bytes, urlsafe: bool) -> str:
    raw = (base64.urlsafe_b64encode(b) if urlsafe
           else base64.b64encode(b)).decode()
    return raw.rstrip("=")


def _printable(b: bytes) -> bool:
    try:
        t = b.decode("utf-8")
    except Exception:
        return False
    if not t:
        return False
    good = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return good / len(t) >= 0.9


def _has_structure_char(t: str) -> bool:
    """Container payloads decode to text with structural (non-alnum) chars."""
    return any(not c.isalnum() for c in t)


def detect_structure(value: str) -> str:
    """Classify the param value's container.  Returns one of:
    ``jwt`` / ``double_b64`` / ``json_b64`` / ``b64`` / ``none``."""
    if not value or len(value) < 8:
        return "none"
    if _JWT_RE.match(value):
        return "jwt"
    if not _B64_CHARS.match(value):
        return "none"
    try:
        d1 = _b64decode(value)
    except Exception:
        return "none"
    if not _printable(d1):
        return "none"
    t1 = d1.decode("utf-8", "replace")
    # Double base64: the decoded text is itself a base64 blob that decodes
    # to printable text.
    if _B64_CHARS.match(t1):
        try:
            if _printable(_b64decode(t1)):
                return "double_b64"
        except Exception:
            pass
    # JSON container (dict only -- the injected field needs an object).
    try:
        if isinstance(json.loads(t1), dict):
            return "json_b64"
    except Exception:
        pass
    # Plain base64 only when the decoded text looks structured.
    if _has_structure_char(t1):
        return "b64"
    return "none"


def encode_payload(value: str, struct: str, payload: str) -> str | None:
    """Re-wrap ``payload`` with the same container as the original value.

    Returns None when the container cannot be reproduced (non-dict JSON,
    malformed JWT, decode failure) -- the caller then just skips the probe.
    """
    try:
        urlsafe = ("-" in value) or ("_" in value)
        if struct == "b64":
            return _b64encode(payload.encode(), urlsafe)
        if struct == "double_b64":
            once = _b64encode(payload.encode(), urlsafe)
            return _b64encode(once.encode(), urlsafe)
        if struct == "json_b64":
            obj = json.loads(_b64decode(value))
            if not isinstance(obj, dict):
                return None
            obj[INJECT_FIELD] = payload
            return _b64encode(json.dumps(obj).encode(), urlsafe)
        if struct == "jwt":
            h, p, s = value.split(".", 2)
            try:
                obj = json.loads(_b64decode(p))
            except Exception:
                obj = {}
            if not isinstance(obj, dict):
                obj = {}
            obj[INJECT_FIELD] = payload
            p2 = _b64encode(json.dumps(obj).encode(), urlsafe=True)
            return f"{h}.{p2}.{s}"  # keep the original signature segment
    except Exception:
        return None
    return None
