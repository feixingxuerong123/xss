"""Target CORS misconfiguration audit (Phase 51).

A permissive Cross-Origin Resource Sharing policy -- echoing back whatever
``Origin`` a request sends AND allowing credentials -- lets any attacker
site read the victim's data from the target with the victim's cookies.  In
an XSS engagement this is the amplifier consultants check next to every
JSON/API endpoint: a weak CORS policy turns a same-origin-only API into a
cross-site data-exfiltration primitive even without a single injection
point, and it chains with any XSS that IS found.

Detected at the HTTP layer with two header-only probes (the attacker Origin
is an UNRESOLVABLE name, so nothing is ever contacted -- only echoed):

  * GET with ``Origin: https://xssentinel-cors.invalid``
  * if the GET shows no reflection, an OPTIONS preflight with the same
    Origin plus ``Access-Control-Request-Method: GET`` (some frameworks
    only emit CORS headers on preflight responses).

Classification (returned by :func:`classify`):

  * ACAO == the sent origin and ``Allow-Credentials: true`` -> **high**
    (any site can read credentialed responses).
  * ACAO == the sent origin, no credentials                 -> **medium**
    (cookie-less but token / header / IP-allowlist auth still readable).
  * ACAO == ``*`` and ``Allow-Credentials: true``           -> **info**
    (spec-invalid -- browsers reject credentialed ``*`` responses -- but a
    configuration bug worth an audit note).
  * ACAO == ``*`` alone, or ACAO absent                     -> no finding
    (public data only / no cross-origin grant).

The scanner layer (``scanner_layers._scan_cors``) runs this once per
origin and records findings of type ``cors_misconfig``.
"""
from __future__ import annotations

# The attacker origin sent in the probe.  .invalid is reserved (RFC 2606)
# and never resolves, so no external party is ever contacted -- the value
# only exists to test whether the server echoes it back.
EVIL_ORIGIN = "https://xssentinel-cors.invalid"

# Probe pair: (method, extra headers).  OPTIONS is the preflight fallback
# for frameworks that only answer CORS on preflight.
PROBES: tuple[tuple[str, dict], ...] = (
    ("GET", {"Origin": EVIL_ORIGIN}),
    ("OPTIONS", {"Origin": EVIL_ORIGIN,
                 "Access-Control-Request-Method": "GET"}),
)


def classify(acao: str, allow_credentials: str, evil_origin: str = EVIL_ORIGIN):
    """Classify one CORS response header set.

    Args:
        acao:   the raw ``Access-Control-Allow-Origin`` header value ("" if
                absent).
        allow_credentials: the raw ``Access-Control-Allow-Credentials``
                header value ("" if absent).
        evil_origin: the origin that was sent in the probe request.

    Returns:
        ``(severity, reason)`` when the policy is a finding, else ``None``.
        severity is one of "high" / "medium" / "info".
    """
    acao = (acao or "").strip()
    acac = (allow_credentials or "").strip().lower() == "true"
    if not acao:
        return None
    if acao == "*":
        # Browsers refuse credentialed '*' responses, so public '*' alone is
        # benign; '*'+credentials is a spec violation worth a note.
        return ("info", "ACAO '*' combined with Allow-Credentials: true "
                        "(browsers reject credentialed wildcards; broken "
                        "configuration)") if acac else None
    if acao == evil_origin:
        # The server echoes the attacker's origin verbatim: full reflection.
        if acac:
            return ("high",
                    "reflects the request Origin verbatim AND allows "
                    "credentials -- any attacker page can read "
                    "credentialed responses cross-origin")
        return ("medium",
                "reflects the request Origin verbatim (no credentials) -- "
                "cross-site reads still work for token/header/allowlist "
                "authenticated endpoints")
    # ACAO present but unrelated to the probe (a fixed allowlist or a
    # different wildcard) -- not a finding.
    return None
