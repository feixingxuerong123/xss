"""PoC replay command generator.

For each finding, generates a ready-to-run command (curl, browser URL,
or HTML file content) that reproduces the XSS.  This is critical for
auditor workflows: the report must include a PoC the reader can run.
"""
from __future__ import annotations
import shlex
from urllib.parse import urlencode


def curl_command(url: str, method: str, params: dict | None,
                 data: dict | None, headers: dict | None,
                 cookies: dict | None, payload: str) -> str:
    """Build a curl command that reproduces the XSS."""
    parts = ["curl", "-s", "-k"]
    # Method.
    if method.upper() == "POST":
        parts.append("-X POST")
    # Headers.
    if headers:
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
    # Cookies.
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.extend(["-b", shlex.quote(cookie_str)])
    # Full URL with params (for GET).
    full_url = url
    if method.upper() == "GET" and params:
        sep = "&" if "?" in url else "?"
        full_url = url + sep + urlencode(params)
    parts.append(shlex.quote(full_url))
    # POST body.
    if method.upper() == "POST" and data:
        parts.extend(["-d", shlex.quote(urlencode(data))])
    return " ".join(parts)


def browser_url(url: str, method: str, params: dict | None,
                payload: str) -> str:
    """Build a URL that can be pasted into a browser (GET only)."""
    if method.upper() != "GET":
        return f"# POST XSS - use curl_command() instead"
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(params)


def html_poc(url: str, method: str, params: dict | None,
             data: dict | None, payload: str) -> str:
    """Build a self-contained HTML PoC file.

    For GET: an <a> link or auto-submitting form.
    For POST: an auto-submitting <form>.
    """
    if method.upper() == "GET":
        full_url = browser_url(url, method, params, payload)
        return (
            "<!DOCTYPE html>\n<html>\n<head><title>XSS PoC</title></head>\n"
            f"<body>\n<p>Click the link to trigger the XSS:</p>\n"
            f'<a href="{full_url}">Trigger XSS</a>\n'
            "<script>setTimeout(function(){window.location='"
            f"{full_url}';}}, 500);</script>\n"
            "</body>\n</html>"
        )
    else:
        # POST: auto-submitting form.
        fields = ""
        for k, v in (data or {}).items():
            fields += f'  <input type="hidden" name="{k}" value="{v}">\n'
        return (
            "<!DOCTYPE html>\n<html>\n<head><title>XSS PoC</title></head>\n"
            f'<body onload="document.forms[0].submit()">\n'
            f'<form action="{url}" method="POST">\n'
            f"{fields}"
            "</form>\n"
            "</body>\n</html>"
        )


def replay_for_finding(finding: dict, headers: dict | None = None,
                       cookies: dict | None = None) -> dict:
    """Generate all replay formats for a finding.

    Returns: {
        "curl": str,
        "browser_url": str,
        "html_poc": str,
    }
    """
    url = finding.get("url", "")
    method = finding.get("method", "GET")
    payload = finding.get("payload", "")
    # Phase 48: POST replays carry the original CSRF/hidden fields beside
    # the injected parameter (see scanner_layers._add / poc.build_poc) so
    # CSRF-protected endpoints accept the replay instead of 403ing.
    csrf_fields = dict(finding.get("csrf_fields") or {})
    if method.upper() == "POST":
        data = dict(csrf_fields)
        data[finding["param"]] = payload
        params = None
    else:
        data = None
        params = {finding["param"]: payload} if finding.get("param") else None
    return {
        "curl": curl_command(url, method, params, data, headers, cookies, payload),
        "browser_url": browser_url(url, method, params, payload),
        "html_poc": html_poc(url, method, params, data, payload),
    }


def write_poc_file(finding: dict, path: str,
                   headers: dict | None = None,
                   cookies: dict | None = None) -> str:
    """Write an HTML PoC file for the finding.  Returns the file path."""
    replay = replay_for_finding(finding, headers, cookies)
    with open(path, "w", encoding="utf-8") as f:
        f.write(replay["html_poc"])
    return path
