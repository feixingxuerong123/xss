# -*- coding: utf-8 -*-
"""Phase 165: confirmation must require the PAYLOAD to survive, not just the token.

`verify_semantic` answers "did the token land somewhere executable" -- it is
structural (bs4 parsing, RCDATA and CSP gates), not a naive substring check.
But it is blind to a server that REWRITES the payload while returning the
token byte-identical.  Measured on two benchmark cases:

  * filter_keywords rewrites ``alert(`` into ``blocked(`` -- the finding was
    credited and the shipped PoC replayed into ``javascript:blocked(...)``:
    no alert, nothing a human could reproduce;
  * filter_javascript_uri strips a ``data:text/html,`` prefix -- the claimed
    URL carrier is simply gone from the response.

`verifier.payload_survived` is the narrower question, and the scanners (sync
and async, all five reflected sites) now require it before recording a
finding: they keep looking for a variant that does survive.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import payload_survived  # noqa: E402

TOK = "xssv_1234abcd"


def test_verbatim_reflection_survives():
    payload = f"<script>alert('{TOK}')</script>"
    assert payload_survived(f"<div>{payload}</div>", payload) is True


def test_rewritten_callable_does_not_survive():
    """The keyword filter's rewrite: token intact, callable neutered."""
    sent = f"<embed src=javascript:alert('{TOK}')>"
    got = f"<embed src=javascript:blocked('{TOK}')>"
    assert payload_survived(got, sent) is False


def test_stripped_scheme_does_not_survive():
    """The URI filter drops the `data:text/html,` carrier entirely."""
    sent = f"data:text/html,<script>alert('{TOK}')</script>"
    got = f'<a href="<script>alert(\'{TOK}\')</script>">link</a>'
    assert payload_survived(got, sent) is False


def test_url_encoded_reflection_survives():
    """A benign encoding of the whole payload is not mangling."""
    import urllib.parse
    payload = f"<script>alert('{TOK}')</script>"
    encoded = urllib.parse.quote(payload, safe="")
    assert payload_survived(f"<pre>{encoded}</pre>", payload) is True


def test_template_prefix_survives():
    """A server that prepends/appends text is not mangling either."""
    payload = f"<img src=x onerror=alert('{TOK}')>"
    assert payload_survived(f"Results for {payload} (done)", payload) is True


def test_percent_decoded_reflection_survives():
    """The transport encoding is not the reflected form: a transform
    percent-encodes the payload to slip past a naive filter, the app decodes
    it, and the response carries the DECODED payload
    (tests/test_async_budget.py's naivewaf fixture)."""
    import urllib.parse
    payload = f"<img src=x onerror=alert('{TOK}')>"
    sent = urllib.parse.quote(payload, safe="")
    assert payload_survived(f"<div>{payload}</div>", sent) is True


def test_base64_container_decoded_by_the_app_survives():
    """The pre-encoded layer ships a base64 container; the app decodes and
    reflects the inner payload (tests/test_async_pipeline.py).  This is also
    the case that exposed a silently-swallowed NameError: the helper only
    imported base64 inside another function, so its base64 branch produced no
    candidates and the whole pre-encode path stopped confirming."""
    import base64
    inner = f"<script>alert('{TOK}')</script>"
    enc = base64.b64encode(inner.encode()).decode().rstrip("=")
    assert payload_survived(f"<div>{inner}</div>", enc) is True
