"""Host scoping for imported targets.

Why this exists: `--har` and `--openapi` expand one file into one target per
captured operation, and a HAR exported from a browser always carries the site's
CDN, analytics, SSO and (increasingly common) advertising domains next to the
application itself.  Before this module the only test an imported target faced
was "does it parse as a URL", so `xssentinel -u https://app.example.com --har
out.har` would send payload-bearing probes, with the scan's session headers, to
hosts the operator never named.  In an engagement that is not a bug report --
it is contacting a third party you have no authorization for.

The rule, and the reason for its shape:

  * hosts the operator typed (`-u`, `--batch`) plus `--allow-host` values are
    the scope baseline -- those are the named authorizations;
  * an imported target outside the baseline is dropped and counted;
  * an import-only run (`--har`/`--openapi` with no `-u`) has no baseline, so
    the file itself defines scope -- but the distinct host set is printed,
    because "I did not realise this HAR carried a CDN and an SSO provider"
    should be visible before those hosts receive traffic, not after;
  * `--allow-any-host` opts out of the filter entirely, with a loud warning.

The baseline is deliberately host-exact rather than "same registrable domain":
`app.example.com` and `internal.example.com` are different assets with possibly
different authorizations, and the person who knows that is the operator, not a
suffix rule here.  A leading dot (`--allow-host .example.com`) is how you say
you mean the whole domain.
"""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlsplit


def host_of(url: str) -> str:
    """Lowercased hostname of a URL, or '' when it has none.

    `.hostname` and not `.netloc`: it already drops the userinfo and the port and
    unwraps IPv6 brackets, which hand-rolling got wrong -- `http://[::1]:9000/x`
    came out as '' and a loopback-v6 target would have been refused as
    out-of-scope.  A comparison check that mis-parses fails *closed* here, which
    is the safe direction for authorization and the wrong one for availability, so
    it has to be right in both directions.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return (host or "").lower().strip("[]")


def _matches(host: str, patterns: Iterable[str]) -> bool:
    if not host:
        return False
    for pat in patterns:
        p = pat.lower().strip()
        if not p:
            continue
        if p.startswith("*."):
            p = "." + p[2:]
        if p.startswith("."):
            if host == p[1:] or host.endswith(p):
                return True
        elif host == p:
            return True
    return False


def baseline_hosts(targets: Iterable[str], extra: Iterable[str] = ()) -> list[str]:
    """Normalized scope patterns from operator-named URLs + `--allow-host`.

    `--allow-host` accepts a URL too, because operators type what they see in the
    address bar; a `https://cdn.example.com/analytics.js` given as a pattern
    would otherwise match nothing and the refusal would look like a bug.
    """
    out: list[str] = []

    def add(value: str) -> None:
        value = (value or "").strip().lower()
        if not value:
            return
        keep_glob = value.startswith(".") or value.startswith("*.")
        host = value if keep_glob else (host_of(value) or value)
        if host and host not in out:
            out.append(host)

    for url in targets:
        add(url)
    for e in extra or ():
        add(e)
    return out


def partition_by_scope(spec_targets: list[dict],
                       patterns: Iterable[str]) -> tuple[list[dict], list[dict]]:
    """Split imported targets into (in scope, dropped).

    Each dropped entry keeps its URL and host so the caller can report both the
    count and *which* third parties were about to receive probes.
    """
    pats = [p for p in patterns if p]
    keep: list[dict] = []
    dropped: list[dict] = []
    for t in spec_targets:
        host = host_of(t.get("url") or "")
        if not pats or _matches(host, pats):
            keep.append(t)
        else:
            dropped.append(dict(t, host=host))
    return keep, dropped


def distinct_hosts(spec_targets: list[dict]) -> list[str]:
    """Sorted host set of the imported targets -- what an import-only run
    should show the operator before it sends anything."""
    return sorted({host_of(t.get("url") or "") for t in spec_targets} - {""})
