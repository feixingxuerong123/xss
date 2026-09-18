# -*- coding: utf-8 -*-
"""Phase 164: the PoC must replay the carrier the payload actually rode.

The PoC generator inferred the carrier from the HTTP method ("POST -> the
payload goes in the body").  That is wrong for every position-shift finding:
`scanner._try_position_shift` re-fires the payload into the OTHER location
precisely to slip past a WAF that guards only the original one, so the shipped
curl put the payload in the one place the WAF inspects.

Measured on benchmark pos-pshift-01 (pseudo-WAF inspects the POST body only):
the shipped PoC replayed into "Sorry, you have been blocked", while
`curl -X POST '<url>?q=<payload>'` returns 200 with the payload reflected.
The findings now carry `param_in`, recorded from `is_body` at confirmation
time, and build_poc honours it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.poc import build_poc  # noqa: E402

PAYLOAD = "<script>alert('xssv_abc12345')</script>"
URL = "http://127.0.0.1:18877/r/ps01"


def _finding(**kw):
    d = {"url": URL, "method": "POST", "param": "q", "type": "reflected",
         "context": "html_element", "payload": PAYLOAD, "transform": [],
         "severity": "high", "confidence": "high", "detail": "d"}
    d.update(kw)
    return d


def test_query_carried_post_puts_the_payload_in_the_url():
    poc = build_poc(_finding(param_in="query"))
    assert "q=" in poc["curl"].split("'")[1], (
        f"payload must ride the query, got: {poc['curl']}")
    assert "--data" not in poc["curl"], (
        "a query-carried POST must not ship a body -- that is where the WAF "
        f"looks: {poc['curl']}")
    assert poc["curl"].startswith("curl -i") and "-X POST" in poc["curl"]
    assert "%3Cscript%3E" in poc["curl"]


def test_body_carried_post_keeps_using_data():
    poc = build_poc(_finding(param_in="body"))
    assert "--data" in poc["curl"], poc["curl"]
    assert "q=" in poc["curl"]


def test_unknown_carrier_keeps_the_old_behaviour():
    """Findings from before this field existed (or other layers) must not
    change shape: a POST without param_in still ships a body."""
    poc = build_poc(_finding())
    assert "--data" in poc["curl"], poc["curl"]


def test_html_poc_does_not_put_a_query_carried_payload_in_a_form():
    poc = build_poc(_finding(param_in="query"))
    html = poc["html"]
    assert "<form" not in html, (
        f"a form would post the payload into the body again: {html}")
    assert "q=" in html and "%3Cscript%3E" in html


def test_cors_finding_ships_the_attacker_origin():
    """Phase 164: a CORS finding has no injectable parameter -- its carrier is
    a request header -- and the PoC used to be an empty placeholder, so a
    client could reproduce nothing at all (measured on pos-cors-01)."""
    poc = build_poc(_finding(type="cors_misconfig", param="",
                             context="cors_header",
                             payload="https://attacker.invalid"))
    assert "Origin: https://attacker.invalid" in poc["curl"], poc["curl"]
    assert "curl" in poc["curl"] and "attacker.invalid" in poc["html"]
