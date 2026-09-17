# -*- coding: utf-8 -*-
"""Phase 156: the stored layer must not pay for pairs that cannot confirm.

Measured on benchmark neg-stored-01 before this change: 49 payloads x 12
transform sets x 2 requests = 1176 requests, 25s, verdict TN.  Two thirds of
that was structurally dead:

* a transform that rewrites the token (url/hex encoding, case flips) makes the
  pair UNCONFIRMABLE -- ``verifier.verify_semantic`` matches the token with a
  plain ``str.find``, so a mangled token can never be found in the view page.
  350 of 588 pairs (60%) were dead on arrival;
* 14% of the pairs were the same string after transformation, paid twice.

Both filters are provably verdict-neutral: a pair that cannot confirm could
only ever return "not confirmed".  These tests lock that property without a
browser or a server.
"""
from __future__ import annotations

import re

from xssentinel.core.scanner_stored import StoredBlindMixin

_TOKEN_RE = re.compile(r"xssv_[0-9a-f]{8}")


class _Resp:
    text = "<html><body>nothing stored here</body></html>"
    headers = {}


class _FakeReq:
    """Records every submitted payload; never confirms anything."""

    def __init__(self):
        self.submitted: list[str] = []

    def request(self, method, url, data=None, params=None, json=None):
        if data:
            self.submitted.extend(str(v) for v in data.values())
        if params:
            self.submitted.extend(str(v) for v in params.values())
        return _Resp()

    def get(self, url, **kw):
        return _Resp()


class _Coverage:
    def touch_layer(self, *a, **k):
        pass


class _Host(StoredBlindMixin):
    def __init__(self, req, max_payloads=14, max_transforms=12):
        self.req = req
        self.max_payloads = max_payloads
        self.max_transforms = max_transforms
        self.verbose = False
        self.findings = []
        self.coverage = _Coverage()

    # Scanner surface used by the mixin
    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        pass


def _submitted_payloads():
    req = _FakeReq()
    host = _Host(req)
    host.scan_stored("http://t/store", view_url="http://t/view",
                     method="POST", param="q")
    return req.submitted


def test_every_submitted_payload_carries_an_intact_token():
    """No pair may be sent whose token was mangled by a transform.

    Such a pair can never be confirmed (verify_semantic does a plain
    substring match), so sending it is pure cost.
    """
    submitted = _submitted_payloads()
    assert submitted, "scan_stored submitted nothing"
    for value in submitted:
        assert _TOKEN_RE.search(value), (
            "submitted a payload whose token is missing or mangled: %r"
            % value[:80])


def test_no_duplicate_payload_is_submitted_twice():
    """Two pairs that are the same string after transformation are one test."""
    submitted = _submitted_payloads()
    normalised = [_TOKEN_RE.sub("TOKEN", v) for v in submitted]
    dupes = len(normalised) - len(set(normalised))
    assert dupes == 0, "%d duplicate payload(s) paid for twice" % dupes


def test_cost_stays_far_below_the_unfiltered_matrix():
    """Guards the size of the win without hardcoding today's corpora.

    Unfiltered this is 49 payloads x 12 transform sets x 2 requests = 1176;
    measured after the filters: 464.
    """
    requests = len(_submitted_payloads())
    assert requests <= 520, (
        "stored matrix cost regressed: %d submitted payloads "
        "(unfiltered would be ~588)" % requests)
