"""Stealth helpers (pentest-readiness, Phase 45).

Two concerns from the pentest audit:

1.  The default User-Agent identified the tool ("XSSentinel/1.0" token) --
    trivially fingerprintable in SIEM/WAF logs.  ``--user-agent`` /
    ``--random-agent`` now feed through here.

2.  Request markers (``xssm_`` / ``xssp_`` / ``xserr_`` /
    ``xssentinel_*``) are recognizable request signatures.  A SIEM rule
    for ``xssm_`` catches every scan.  ``--marker-prefix`` overrides the
    stems via ``set_marker_prefix``; the per-kind hex suffixes stay random
    so markers remain unique, they just no longer spell the tool's name.

Both defaults are unchanged (no behavior change unless the operator opts
in) so the benchmark matrix and all existing tests keep their semantics.
"""
from __future__ import annotations

import os
import random
import threading

# A small pool of plausible, current-ish desktop browser UAs.  Deliberately
# not exhaustive: on an assessment the operator should pass the ACTUAL UA
# of the persona they are emulating via --user-agent.
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 "
    "Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 "
    "Firefox/127.0",
]

_marker_prefix: str | None = None


def pick_user_agent(custom: str | None = None,
                    rotate: bool = False) -> str | None:
    """Resolve the UA to use, or None (keep the Requester default).

    ``custom`` wins; otherwise ``rotate`` picks from the pool.
    """
    if custom:
        return custom
    if rotate:
        return random.choice(UA_POOL)
    return None


def set_marker_prefix(prefix: str | None) -> None:
    """Override every request-marker stem (e.g. 'q' -> 'q_...').

    Empty/None restores the built-in per-kind stems.
    """
    global _marker_prefix
    p = (prefix or "").strip().rstrip("_-")
    _marker_prefix = p or None


def marker(default_stem: str) -> str:
    """Return the marker stem for this scan.

    With no override this is the built-in stem (``xssm_``, ``xssp_`` ...);
    with ``--marker-prefix q`` every stem becomes ``q_`` -- the random hex
    suffix appended by callers keeps markers unique per probe.
    """
    if _marker_prefix:
        return _marker_prefix + "_"
    return default_stem


def marker_override_active() -> bool:
    return _marker_prefix is not None


# ---------------------------------------------------------------------------
# Phase 51: the remaining half of the pentest audit's "stealth" item --
# no proxy pool, no header rotation, no request jitter.  All three are
# opt-in (defaults reproduce the previous behaviour exactly) because an
# assessment-specific persona must stay under the operator's control.
# ---------------------------------------------------------------------------

def jitter_interval(interval: float, ratio: float) -> float:
    """Randomise a pacing interval by +/- ``ratio`` (0 = unchanged).

    A fixed cadence is itself a fingerprint: a WAF/SIEM sees requests
    arrive every 200.0 ms like clockwork.  ``ratio=0.4`` spreads the wait
    uniformly over [0.6x, 1.4x].
    """
    if not interval or interval <= 0 or not ratio or ratio <= 0:
        return max(0.0, float(interval or 0.0))
    r = min(1.0, float(ratio))
    return max(0.0, interval * (1.0 + random.uniform(-r, r)))


# Header bundles a real browser sends alongside each UA family.  Deliberately
# EXCLUDES anything requests must control (Host, Content-Length,
# Content-Type, Accept-Encoding, Connection) and anything the scan itself
# sets (Cookie/Authorization) -- rotating those would break detection or
# the request, not hide it.
_CHROME_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-CH-UA": '"Chromium";v="126", "Google Chrome";v="126", '
                 '"Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

_FIREFOX_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

_SAFARI_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}

# Never emit these from the rotator: requests owns them, and a stale value
# would corrupt the request or the detection semantics.
_FORBIDDEN_ROTATION_HEADERS = {
    "host", "content-length", "content-type", "accept-encoding",
    "connection", "proxy-connection", "cookie", "authorization",
    "user-agent",  # UA is chosen once (--user-agent / --random-agent)
}


def _family_for_ua(ua: str | None) -> str | None:
    if not ua:
        return None
    low = ua.lower()
    if "firefox" in low:
        return "firefox"
    if "safari" in low and "chrome" not in low:
        return "safari"
    if "chrome" in low or "chromium" in low:
        return "chrome"
    return None


class HeaderRotator:
    """Yield browser-plausible header sets, cycled per request.

    The bundle is pinned to the operator's UA family (a Firefox UA must not
    send Chrome-only ``Sec-CH-UA`` headers -- that mismatch is itself a
    bot signal).  Within a family the Accept-Language and navigation
    context vary so consecutive requests don't look byte-identical.
    """

    # Accept-Language rotation is per UA-family and seeded with the family's
    # canonical value first: a fresh Firefox rotator must emit Firefox's
    # real "en-US,en;q=0.5", a Chrome one "en-US,en;q=0.9", and later calls
    # only vary WITHIN family-plausible dialects (sending Chrome's q=0.9
    # under a Firefox UA is itself a fingerprint mismatch).
    _LANG_VARIANTS = {
        "chrome": ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8",
                   "en-CA,en;q=0.9"],
        "firefox": ["en-US,en;q=0.5", "en-GB,en;q=0.5", "en-US,en;q=0.7",
                    "en-CA,en;q=0.5"],
        "safari": ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8",
                   "en-CA,en;q=0.9"],
    }
    _SITE_VARIANTS = ["none", "same-origin", "same-site"]

    def __init__(self, user_agent: str | None = None):
        self.family = _family_for_ua(user_agent)
        self._i = 0
        self._lock = threading.Lock()

    def next_headers(self) -> dict:
        with self._lock:
            i = self._i
            self._i += 1
        fam = self.family or (["chrome", "firefox", "safari"][i % 3])
        base = {"chrome": _CHROME_HEADERS,
                "firefox": _FIREFOX_HEADERS,
                "safari": _SAFARI_HEADERS}[fam]
        h = dict(base)
        langs = self._LANG_VARIANTS[fam]
        h["Accept-Language"] = langs[i % len(langs)]
        h["Sec-Fetch-Site"] = self._SITE_VARIANTS[i % len(self._SITE_VARIANTS)]
        # Drop anything a caller must never see rotated.
        return {k: v for k, v in h.items()
                if k.lower() not in _FORBIDDEN_ROTATION_HEADERS}


class ProxyPool:
    """Round-robin proxy rotation with dead-entry eviction.

    Rotating egress is the difference between "one IP hammering the target"
    and traffic a rate-based WAF can't attribute.  Entries that fail with a
    proxy-level error are marked dead and skipped, so a single dead relay
    in the pool doesn't burn 1/N of every scan.
    """

    def __init__(self, proxies, mode: str = "round-robin", randomize: bool = False):
        self.all = [p for p in (_normalize_proxy(p) for p in (proxies or []))
                    if p]
        # de-duplicate, keep order
        seen = set()
        self.all = [p for p in self.all if not (p in seen or seen.add(p))]
        self.mode = mode
        self.randomize = bool(randomize)
        self.dead: set[str] = set()
        self._i = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self.all)

    @property
    def live(self) -> list[str]:
        return [p for p in self.all if p not in self.dead]

    def next(self) -> str | None:
        live = self.live
        if not live:
            return None
        if self.randomize:
            return random.choice(live)
        with self._lock:
            i = self._i
            self._i += 1
        return live[i % len(live)]

    def mark_dead(self, proxy: str | None) -> None:
        if proxy:
            self.dead.add(proxy)

    def as_kwargs(self) -> dict | None:
        """requests-style ``proxies=`` mapping (None when nothing to use)."""
        p = self.next()
        return None if p is None else {"http": p, "https": p}


def _normalize_proxy(value: str) -> str | None:
    """Accept 'host:port', 'http://host:port', 'socks5://user:pass@host:port'."""
    v = (value or "").strip()
    if not v or v.startswith("#"):
        return None
    if "://" not in v:
        v = "http://" + v
    return v


def load_proxies(spec) -> list[str]:
    """Parse a proxy list from a list / comma string / file path / @file.

    Blank lines and ``#`` comments are ignored; duplicates collapse.
    """
    if not spec:
        return []
    items: list[str] = []
    if isinstance(spec, (list, tuple, set)):
        raw = [str(x) for x in spec]
    else:
        s = str(spec).strip()
        if s.startswith("@"):
            s = s[1:]
        # A filesystem path wins over a comma list.
        if os.path.isfile(s):
            raw = open(s, "r", encoding="utf-8",
                       errors="replace").read().splitlines()
        else:
            raw = s.replace(",", "\n").splitlines()
    for line in raw:
        p = _normalize_proxy(line)
        if p:
            items.append(p)
    seen = set()
    return [p for p in items if not (p in seen or seen.add(p))]
