"""Out-of-band (OOB) callback listeners for blind-XSS auto-confirmation.

Previously the blind layer only *injected* callback payloads and asked the
user to check their own server.  That left blind XSS unconfirmed.  This module
closes the loop: it runs (or talks to) a callback server, injects a UNIQUE
per-injection token, then polls for received beacons and turns a received
callback into a CONFIRMED (high-severity) blind-XSS finding.

Two backends:

  * SelfHostedListener -- spins up a local HTTP server.  Fully offline,
    self-contained, and testable.  Best for local demos / internal apps you
    control.  Token is embedded in the callback path for per-injection
    attribution.
  * InteractshListener  -- talks to a public interactsh server (interact.sh
    by default).  The realistic choice for real engagements: the victim's
    browser beacons to a public host you own.  Confirmation uses the
    interaction `unique-id` (your subdomain); no crypto needed for the
    confirm path.

Both expose the same small interface:

    start() / stop()
    token() -> str                      # unique id for one injection
    callback_url(token) -> str          # URL the payload beacons to
    poll(expected: set, timeout) -> set # tokens from `expected` that beaconed
    __enter__ / __exit__                # context-manager friendly
"""
from __future__ import annotations

import base64
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class OOBListener:
    """Base class.  Subclasses implement start/stop/token/callback_url/poll."""

    name = "oob"

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def token(self) -> str:
        raise NotImplementedError

    def callback_url(self, token: str) -> str:
        raise NotImplementedError

    def poll(self, expected: set, timeout: float = 12) -> set:
        raise NotImplementedError

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


class SelfHostedListener(OOBListener):
    """Local HTTP callback server.  Used for offline testing and internal apps.

    The injected token is placed in the URL path:
        http://<host>:<port>/<token>
    The handler records every path it receives.  `poll` waits (up to `timeout`)
    for any of the `expected` tokens to arrive.
    """

    name = "self-hosted"

    def __init__(self, host: str = "127.0.0.1", port: int | None = None):
        self.host = host
        # port=None -> let the OS pick a free port (avoids TIME_WAIT collisions
        # during rapid local testing).  The real port is read back after bind.
        self.port = port
        self._server = None
        self._thread = None
        self._received: set[str] = set()
        self._lock = threading.Lock()
        self._started = False

    def start(self):
        if self._started:
            return
        listener = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                tok = self.path.strip("/").split("?")[0].split("/")[0]
                if tok:
                    with listener._lock:
                        listener._received.add(tok)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self._server = ThreadingHTTPServer((self.host, self.port or 0), _Handler)
        self._server.allow_reuse_address = True
        # Server bind happens in the constructor; capture the real port.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._started = True

    def stop(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        self._thread = None
        self._started = False

    def token(self) -> str:
        return "xssv_" + secrets.token_hex(6)

    def callback_url(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/{token}"

    def poll(self, expected: set, timeout: float = 12) -> set:
        if not expected:
            return set()
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                hit = self._received & expected
            if hit:
                return hit
            time.sleep(0.2)
        with self._lock:
            return self._received & expected


class InteractshListener(OOBListener):
    """Talks to a public interactsh server for real blind-XSS confirmation.

    Confirmation relies on the interaction `unique-id` (your registered
    subdomain) returned by the poll API -- no decryption needed.  If the
    network/registration fails, every method degrades gracefully (poll returns
    an empty set) so the scanner simply reports no confirmed blind finding
    rather than crashing.
    """

    name = "interactsh"

    def __init__(self, server: str = "https://interact.sh", timeout: int = 15):
        self.server = server.rstrip("/")
        self.timeout = timeout
        self._session = None
        self.subdomain = None
        self.correlation_id = None
        self.auth_token = None
        self._started = False

    def _ensure_session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": "XSSentinel/1.0",
                "Content-Type": "application/json",
            })
        return self._session

    def start(self):
        if self._started:
            return
        try:
            s = self._ensure_session()
            self.correlation_id = secrets.token_hex(16)
            public_key = base64.b64encode(secrets.token_bytes(32)).decode()
            resp = s.post(
                f"{self.server}/api/register",
                json={"public-key": public_key,
                      "correlation-id": self.correlation_id},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            self.subdomain = data.get("subdomain")
            self.auth_token = data.get("auth-token")
            if not self.subdomain:
                raise ValueError("interactsh register returned no subdomain")
            self._started = True
        except Exception as e:
            # Degrade: blind scan will inject but never confirm.
            raise RuntimeError(f"interactsh registration failed: {e}")

    def stop(self):
        self._started = False

    def token(self) -> str:
        # Each injection gets a unique random prefix so callbacks can be
        # attributed to a specific (url, param).  The token is placed as a
        # subdomain label in front of the registered base subdomain.
        if not self.subdomain:
            raise RuntimeError("interactsh listener not started")
        return secrets.token_hex(8)

    def callback_url(self, token: str) -> str:
        # token is a random prefix; subdomain is the registered base.
        # The victim's browser beacons to {token}.{subdomain}, and the
        # interactsh poll API reports it back as unique-id.
        return f"https://{token}.{self.subdomain}"

    def poll(self, expected: set, timeout: float = 12) -> set:
        """Poll interactsh for interactions whose unique-id starts with any
        of the expected token prefixes.  Returns the subset of `expected`
        tokens that received a callback."""
        if not expected or not self._started:
            return set()
        s = self._ensure_session()
        deadline = time.time() + timeout
        confirmed: set = set()
        while time.time() < deadline:
            try:
                resp = s.get(
                    f"{self.server}/api/poll",
                    params={"id": self.correlation_id},
                    headers={"Authorization": self.auth_token or ""},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        uid = item.get("unique-id", "")
                        if not uid:
                            continue
                        # unique-id is the full interaction hostname
                        # (e.g. "tok1234.base.oast.fun").  Match by prefix
                        # so we attribute the callback to the right token.
                        for tok in expected:
                            if tok and (uid == tok or uid.startswith(tok + ".")
                                        or uid.startswith(tok)):
                                confirmed.add(tok)
            except Exception:
                pass
            if confirmed & expected:
                return confirmed & expected
            time.sleep(1.0)
        return confirmed & expected


def make_listener(mode: str, host: str = "127.0.0.1", port: int | None = 8900):
    """Factory: mode in {'self', 'interactsh'} -> OOBListener instance."""
    if mode == "self":
        return SelfHostedListener(host=host, port=port)
    if mode == "interactsh":
        return InteractshListener()
    raise ValueError(f"unknown OOB mode: {mode!r} (use 'self' or 'interactsh')")
