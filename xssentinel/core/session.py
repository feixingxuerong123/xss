"""Session / authentication support.

Provides:
  * CookieJar: persists cookies across requests (login -> scan).
  * login_form: auto-fill and submit a login form, then capture the
    session cookie for the scanner.
  * login_basic / login_token / login_oauth_token: alternate auth methods.
  * SessionManager: ties it together, exposes a requests.Session-compatible
    object the Requester can use.

Usage:
    mgr = SessionManager(Requester(...))
    mgr.login_form(login_url, {"username": "...", "password": "..."})
    # Now mgr.requester.session has the session cookie.
    scanner = Scanner(requester=mgr.requester, ...)
"""
from __future__ import annotations
import time

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class SessionManager:
    """Wraps a Requester with authentication support.

    The Requester is expected to expose a `.session` attribute (a
    requests.Session).  If it doesn't, login operations will fail
    gracefully.
    """

    def __init__(self, requester):
        self.requester = requester
        self.session = getattr(requester, "session", None)
        self.logged_in = False
        self.login_time = 0.0
        self.refresh_threshold = 1800.0  # 30 minutes
        self._login_url = None
        self._login_data = None
        self._login_method = None
        self._oauth_refresh: dict | None = None
        self._markers: tuple[str | None, str | None] = (None, None)

    def login_form(self, login_url: str, credentials: dict,
                   method: str = "POST",
                   success_marker: str | None = None,
                   failure_marker: str | None = None) -> bool:
        """Submit a login form and capture the session cookie.

        Args:
            login_url: the login form action URL.
            credentials: dict of form fields (username, password, csrf, etc.).
            method: HTTP method (default POST).
            success_marker: substring expected in response on success
                (e.g. "Welcome" or "Logout").  If None, success is
                inferred by absence of the failure_marker.
            failure_marker: substring expected in response on failure
                (e.g. "Invalid credentials").

        Returns True if login succeeded.
        """
        if not self.session:
            return False
        try:
            if method.upper() == "POST":
                resp = self.session.post(login_url, data=credentials,
                                          timeout=self.requester.timeout)
            else:
                resp = self.session.get(login_url, params=credentials,
                                         timeout=self.requester.timeout)
            text = resp.text or ""
            ok = False
            if success_marker:
                ok = success_marker in text
            elif failure_marker:
                ok = failure_marker not in text
            else:
                # Heuristic: any 200/302 response with a Set-Cookie.
                ok = resp.status_code in (200, 302) and bool(resp.cookies)
            if ok:
                self.logged_in = True
                self.login_time = time.time()
                self._login_url = login_url
                self._login_data = credentials
                self._login_method = method
                # Remember the markers so reauth() re-uses the same
                # success/failure test instead of the weaker heuristic.
                self._markers = (success_marker, failure_marker)
            return ok
        except Exception:
            return False

    def looks_logged_out(self, resp) -> bool:
        """Heuristic: does this response mean our session died?

        True on 401/403, or on a redirect (302) whose Location points at
        the login page we authenticated against.
        """
        if resp is None or not self.logged_in:
            return False
        try:
            status = getattr(resp, "status_code", 0) or 0
        except Exception:
            return False
        if status in (401, 403):
            return True
        if status in (301, 302, 303, 307, 308):
            try:
                loc = (resp.headers.get("Location") or "").lower()
            except Exception:
                return False
            if not loc or not self._login_url:
                return False
            from urllib.parse import urlparse
            login_path = urlparse(self._login_url).path.rstrip("/").lower()
            loc_path = urlparse(loc).path.rstrip("/").lower()
            return bool(login_path) and login_path in loc_path
        return False

    def reauth(self) -> bool:
        """Re-authenticate after the session was lost (OAuth refresh or
        form re-login).  Returns True if the session was restored."""
        if not self.logged_in:
            return False
        if self._login_method == "oauth" and getattr(
                self, "_oauth_refresh", None):
            if self._refresh_oauth_token():
                return True
        if self._login_url and self._login_data is not None:
            markers = getattr(self, "_markers", (None, None)) or (None, None)
            return self.login_form(
                self._login_url, self._login_data,
                method=self._login_method or "POST",
                success_marker=markers[0], failure_marker=markers[1])
        return False

    def login_basic(self, username: str, password: str) -> bool:
        """HTTP Basic Auth login."""
        if not self.session:
            return False
        self.session.auth = (username, password)
        self.logged_in = True
        self.login_time = time.time()
        return True

    def login_header(self, header_name: str, header_value: str) -> bool:
        """Set a custom auth header (Bearer token, X-API-Key, etc.)."""
        if not self.session:
            return False
        self.session.headers.update({header_name: header_value})
        self.logged_in = True
        self.login_time = time.time()
        return True

    def login_cookie(self, cookie_name: str, cookie_value: str,
                     domain: str = "") -> bool:
        """Inject a session cookie directly (e.g. extracted from browser)."""
        if not self.session:
            return False
        self.session.cookies.set(cookie_name, cookie_value, domain=domain or None)
        self.logged_in = True
        self.login_time = time.time()
        return True

    def login_token(self, token: str,
                    header_name: str = "Authorization",
                    scheme: str = "Bearer",
                    verify_url: str | None = None,
                    success_marker: str | None = None) -> bool:
        """Authenticate with a bearer/api token via an HTTP header.

        Args:
            token: the raw token value (e.g. JWT, API key).
            header_name: header to carry the token (default ``Authorization``).
            scheme: auth scheme prefix (default ``Bearer``); use ``""`` for
                raw header value (e.g. custom ``X-API-Key``-style tokens).
            verify_url: optional URL to GET after setting the header to
                verify the token is valid.
            success_marker: substring expected in the verify response on
                success (e.g. ``"user_id"``).  Required if ``verify_url``
                is given; without it the token is assumed valid.

        Returns True if the token was set (and, if verified, accepted).
        """
        if not self.session:
            return False
        value = f"{scheme} {token}" if scheme else token
        self.session.headers.update({header_name: value})
        if verify_url:
            try:
                resp = self.session.get(verify_url,
                                        timeout=self.requester.timeout)
                text = resp.text or ""
                if success_marker and success_marker not in text:
                    # Token rejected -- roll back the header.
                    del self.session.headers[header_name]
                    return False
                if resp.status_code >= 400:
                    del self.session.headers[header_name]
                    return False
            except Exception:
                del self.session.headers[header_name]
                return False
        self.logged_in = True
        self.login_time = time.time()
        self._login_method = "token"
        return True

    def login_oauth_token(self, access_token: str,
                          token_type: str = "Bearer",
                          refresh_token: str | None = None,
                          verify_url: str | None = None,
                          client_id: str | None = None,
                          client_secret: str | None = None,
                          token_url: str | None = None) -> bool:
        """Authenticate with an OAuth 2.0 token.

        Sets the access token as an ``Authorization: <token_type> <access_token>``
        header.  If a ``verify_url`` is given, validates the token by
        GETting it.  Stores the refresh token for future ``refresh_if_needed``
        calls when ``token_url`` + ``client_id`` + ``client_secret`` are
        also provided.

        Args:
            access_token: the OAuth access token.
            token_type: token type (default ``Bearer``).
            refresh_token: optional refresh token for token renewal.
            verify_url: optional userinfo/profile endpoint to validate token.
            client_id: client ID for refresh flow.
            client_secret: client secret for refresh flow.
            token_url: token endpoint URL for refresh flow.

        Returns True if the token was set (and, if verified, accepted).
        """
        if not self.session:
            return False
        ok = self.login_token(access_token, header_name="Authorization",
                              scheme=token_type, verify_url=verify_url)
        if not ok:
            return False
        # Store refresh credentials for ``refresh_if_needed``.
        self._login_method = "oauth"
        self._oauth_refresh = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
            "token_url": token_url,
            "token_type": token_type,
        } if (refresh_token and token_url and client_id) else None
        return True

    def refresh_if_needed(self) -> bool:
        """Re-login if the session is older than refresh_threshold.

        Returns True if a refresh was performed and succeeded.
        """
        if not self.logged_in:
            return False
        if time.time() - self.login_time < self.refresh_threshold:
            return False
        # Form-based refresh.
        if self._login_url and self._login_method != "oauth":
            return self.login_form(self._login_url, self._login_data or {},
                                    self._login_method or "POST")
        # OAuth token refresh (RFC 6749 §6).
        if self._login_method == "oauth" and getattr(self, "_oauth_refresh", None):
            return self._refresh_oauth_token()
        return False

    def keep_alive(self, probe_url: str | None = None,
                   relogin_on_loss: bool = False) -> bool:
        """Keep the authenticated session usable during a long scan.

        Two mechanisms (both were implemented but never called from the
        CLI, so sessions simply expired mid-scan):

          1. age-based: re-auth once the session is older than
             ``refresh_threshold`` (OAuth refresh or form re-login).
          2. loss-based (opt-in via ``relogin_on_loss``): probe the target
             and, when the response says we are logged out (401/403 or a
             redirect to the login page), re-authenticate immediately.

        Returns True if a re-authentication was performed and succeeded.
        """
        if not self.logged_in:
            return False
        if self.refresh_if_needed():
            return True
        if not (relogin_on_loss and probe_url and self.session):
            return False
        try:
            resp = self.session.get(probe_url,
                                    timeout=getattr(self.requester,
                                                    "timeout", 20),
                                    allow_redirects=False)
            if self.looks_logged_out(resp):
                return self.reauth()
        except Exception:
            return False
        return False

    def _refresh_oauth_token(self) -> bool:
        """Refresh an expired OAuth access token using the refresh token."""
        cfg = self._oauth_refresh
        if not cfg or not cfg.get("refresh_token") or not cfg.get("token_url"):
            return False
        try:
            resp = self.session.post(
                cfg["token_url"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": cfg["refresh_token"],
                    "client_id": cfg.get("client_id", ""),
                    "client_secret": cfg.get("client_secret", ""),
                },
                timeout=self.requester.timeout,
            )
            if resp.status_code != 200:
                return False
            data = resp.json()
            new_access = data.get("access_token")
            if not new_access:
                return False
            new_refresh = data.get("refresh_token", cfg["refresh_token"])
            new_type = data.get("token_type", cfg.get("token_type", "Bearer"))
            # Update the stored header.
            self.session.headers.update(
                {"Authorization": f"{new_type} {new_access}"})
            cfg["refresh_token"] = new_refresh
            self.login_time = time.time()
            return True
        except Exception:
            return False

    def attach(self, requester) -> None:
        """Watch every response from ``requester``; re-authenticate the
        moment one says the session died, then RETRY that request once.

        Phase 45: ``keep_alive()`` only runs between batch URLs, so a single
        long URL scan (30+ min, thousands of requests) could silently lose
        its session mid-run.  This hook closes that gap: every response
        passing through the Requester is checked with ``looks_logged_out``
        (401/403 or redirect-to-login); on loss, ``reauth()`` runs, the
        fresh cookies / auth headers are copied into the requester that saw
        the logout (worker-thread clones own separate sessions), and the
        request is retried ONCE so the scanner never sees the 401 that
        triggered the recovery.

        The hook returns the retry response (or None to keep the original).
        """
        if getattr(requester, "session", None) is None:
            return

        def _hook(resp, req, method, url, params, data):
            if not self.looks_logged_out(resp):
                return None
            if not self.reauth():
                return None
            # Propagate the refreshed credentials to the requester that saw
            # the logout (clones have independent sessions).
            try:
                req.session.cookies.update(self.session.cookies)
                for h in ("Authorization", "X-API-Key", "X-Auth-Token",
                          "X-Session-Token"):
                    if h in self.session.headers:
                        req.session.headers[h] = self.session.headers[h]
            except Exception:
                pass
            # Retry once with fresh credentials (session-direct, no hook
            # recursion).  If the retry ALSO says logged-out, give up and
            # surface it -- one retry prevents loops.
            try:
                if method == "POST":
                    return req.session.post(url, data=data, params=params,
                                            timeout=req.timeout)
                return req.session.get(url, params=params,
                                       timeout=req.timeout)
            except Exception:
                return None

        try:
            requester.on_response = _hook
        except Exception:
            pass  # requester without the hook attribute (stub) -- skip

    def logout(self) -> None:
        """Clear all auth state."""
        if self.session:
            self.session.auth = None
            self.session.cookies.clear()
            # Remove custom auth headers (Authorization, X-API-Key, etc.).
            for h in list(self.session.headers.keys()):
                if h.lower() in ("authorization", "x-api-key", "x-auth-token",
                                  "x-session-token"):
                    del self.session.headers[h]
        self.logged_in = False
        self.login_time = 0.0
        self._oauth_refresh = None


def extract_csrf_token(html: str, field_name: str = "csrf_token"
                       ) -> str | None:
    """Extract a CSRF token value from an HTML form.

    Looks for <input name="csrf_token" value="...">.
    """
    import re
    if not html:
        return None
    # Try double-quoted value first, then single-quoted.
    patterns = [
        rf'<input[^>]+name\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]+value\s*=\s*"([^"]*)"',
        rf'<input[^>]+name\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]+value\s*=\s*\'([^\']*)\'',
        rf'<input[^>]+value\s*=\s*"([^"]*)"[^>]+name\s*=\s*["\']?{re.escape(field_name)}["\']?',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def login_with_csrf(requester, login_url: str,
                    username: str, password: str,
                    username_field: str = "username",
                    password_field: str = "password",
                    csrf_field: str = "csrf_token") -> bool:
    """Convenience: fetch login page, extract CSRF, then submit.

    Returns True if login succeeded (heuristic: 200/302 + cookie set).
    """
    if not _HAS_REQUESTS or not hasattr(requester, "session"):
        return False
    session = requester.session
    try:
        # 1) GET login page to fetch CSRF token.
        resp = session.get(login_url, timeout=requester.timeout)
        csrf = extract_csrf_token(resp.text or "", csrf_field)
        # 2) POST credentials.
        data = {username_field: username, password_field: password}
        if csrf:
            data[csrf_field] = csrf
        resp = session.post(login_url, data=data, timeout=requester.timeout)
        ok = resp.status_code in (200, 302) and bool(resp.cookies)
        return ok
    except Exception:
        return False
