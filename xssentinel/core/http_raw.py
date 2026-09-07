"""Raw HTTP request file parsing (DalFox ``--rawdata`` / Burp / ZAP
"copy as raw" interoperability).

Parses a raw HTTP request (the wire format exported by Burp, ZAP, and
many recon tools) into the components the scan pipeline needs: method,
absolute URL (Host header supplies the authority; https is chosen when
the file uses TLS-ported conventions or an ``https://`` absolute-form
target), headers, and body.

Phase 83: feeds ``--raw-request``; the parsed values are written back
onto the CLI args namespace so the request flows through the FULL
existing scan pipeline (auth headers, cookies, OOB, crawling, reporting)
instead of a parallel, weaker code path.
"""
from __future__ import annotations

from urllib.parse import urlunparse


class RawRequestError(ValueError):
    """Raised when the raw request file cannot be parsed."""


def parse_raw_request(raw: str, default_scheme: str = "http"
                      ) -> dict:
    """Parse a raw HTTP/1.x request text.

    Returns ``{"method", "url", "headers": {name: value}, "body": str,
    "cookies": "cookie-string", "content_type": str}``.

    Raises :class:`RawRequestError` on a missing request line, a missing
    Host header (HTTP/1.1 requires it and the absolute URL cannot be
    built without it), or a malformed header section.
    """
    if not raw or not raw.strip():
        raise RawRequestError("raw request is empty")
    # Normalise line endings (Burp exports CRLF; hand-edited files may
    # use bare LF).
    text = raw.replace("\r\n", "\n")
    if "\n\n" in text:
        head, _, body = text.partition("\n\n")
    else:
        head, body = text, ""
    lines = head.split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise RawRequestError(
            f"malformed request line: {request_line!r}")
    method = parts[0].upper()
    target = parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise RawRequestError(f"malformed header line: {line!r}")
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    host = headers.get("Host") or headers.get("host")
    if not host:
        raise RawRequestError("missing Host header -- cannot build the "
                              "target URL")

    scheme = default_scheme
    if target.startswith(("http://", "https://")):
        # Absolute-form target (proxies): it carries its own authority.
        url = target
    else:
        if host.lower().endswith(":443") or "https" in headers.get(
                "X-Forwarded-Proto", "").lower():
            scheme = "https"
        path = target if target.startswith("/") else "/" + target
        url = urlunparse((scheme, host, path, "", "", ""))

    cookies = headers.get("Cookie") or headers.get("cookie") or ""
    content_type = (headers.get("Content-Type")
                    or headers.get("content-type") or "")
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "cookies": cookies,
        "content_type": content_type,
    }
