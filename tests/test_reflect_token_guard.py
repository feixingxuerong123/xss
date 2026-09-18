# -*- coding: utf-8 -*-
"""Phase 157: the reflection path must not send variants it cannot confirm.

``Scanner._try_payload`` marks the payload (``verifier.mark``) and THEN runs
transform chains over it, and confirms with ``verify_semantic``, which matches
the token with a plain ``str.find``.  A chain that rewrites the token
(url/hex encoding, case flips, ...) therefore produces a variant that can
never be confirmed -- a request that can only ever return "not confirmed".

Static count over the whole corpus (12 transform sets x 1074 payloads):
7218 of 12888 variants (56%) were dead this way.

The same guard exposes a PRE-EXISTING gap: ``verifier.mark`` stamps the token
into an ``alert(...)`` call, so a corpus entry whose payload carries no
literal ``alert(`` (e.g. ``<script>\\u0061lert(1)</script>`` -- a JS-unicode
escape the browser decodes just fine) can never be stamped and therefore can
never be confirmed by this path.  Those payloads used to cost a full 12
requests; they now cost none.  That is not a speed win, it is the gap
becoming visible -- it is asserted here so it cannot be forgotten.
"""
from __future__ import annotations

import re

from xssentinel.core import payloads, verifier
from xssentinel.core.scanner import Scanner

_TOKEN_RE = re.compile(r"xssv_[0-9a-f]{8}")

CONTEXTS = ("html_element", "script_block", "svg_context", "dom_clobber",
            "event_handler", "css_context")


class _Resp:
    status_code = 200
    text = "<html><body>no reflection here</body></html>"
    headers = {}
    url = "http://t/p"


class _FakeReq:
    def __init__(self):
        self.submitted: list[str] = []

    def request(self, method, url, params=None, data=None, **kw):
        for src in (params, data):
            if src:
                self.submitted.extend(str(v) for v in src.values())
        return _Resp()

    def get(self, url, **kw):
        return _Resp()


def _run(payload: str, context: str) -> list[str]:
    req = _FakeReq()
    sc = Scanner(requester=req, max_payloads=14, max_transforms=12,
                 dom_engine="static", verbose=False)
    sc._try_payload(req, "http://t/p", "GET", {}, {}, "q", False,
                    payload, context, {})
    return req.submitted


def _stampable(payload: str) -> bool:
    """Can ANY stamp style carry a token into this payload?

    Phase 166 added the concat style (``window['ale'+'rt']('token')``), which
    arms payloads the plain ``alert(`` stamp cannot touch -- so "unstampable"
    must mean "both styles fail", or the cost assertion below would flag the
    new, correct behaviour of trying the concat stamp on a target that
    rewrites literal callables.
    """
    tok = "xssv_" + "a" * 8
    return any(tok in verifier.mark(payload, tok, style=st)
               for st in ("plain", "concat"))


def test_every_reflected_variant_carries_an_intact_token():
    for ctx in CONTEXTS:
        corpus = payloads.by_context(ctx)
        for entry in corpus[:4]:
            if not _stampable(entry["payload"]):
                continue          # covered by the unstampable test below
            submitted = _run(entry["payload"], ctx)
            assert submitted, "nothing submitted for %s/%s" % (
                ctx, entry["payload"][:30])
            for value in submitted:
                assert _TOKEN_RE.search(value), (
                    "%s: submitted a variant whose token is gone: %r"
                    % (ctx, value[:80]))


def test_dead_variants_are_not_sent():
    """The guard must remove work, not just decorate it.

    Source 1 contributes exactly one variant per transform set (12) when no
    WAF is in play; a healthy context must land clearly under that.
    """
    for ctx in ("html_element", "script_block", "svg_context"):
        corpus = [e for e in payloads.by_context(ctx)
                  if _stampable(e["payload"])]
        if not corpus:
            continue
        submitted = _run(corpus[0]["payload"], ctx)
        assert len(submitted) <= 12, "more variants than transform sets?"
        assert len(submitted) < 12, (
            "%s: no dead variant was filtered out (%d sent)"
            % (ctx, len(submitted)))


def test_unstampable_payloads_cost_nothing():
    """A payload verifier.mark cannot stamp can never be confirmed here.

    Pre-existing gap, now visible: <script>\\u0061lert(1)</script> is a real
    XSS (the browser decodes the JS unicode escape) but no variant of it can
    ever carry a token, so this path cannot confirm it -- and it must not pay
    12 requests to prove that.
    """
    unstampable = [e for ctx in CONTEXTS
                   for e in payloads.by_context(ctx)
                   if not _stampable(e["payload"])]
    assert unstampable, "no unstampable payload found -- corpus changed?"
    for entry in unstampable[:5]:
        assert _run(entry["payload"], entry.get("context", "")) == [], (
            "paid requests for a payload that can never be confirmed: %r"
            % entry["payload"][:60])
