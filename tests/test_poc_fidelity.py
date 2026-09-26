# -*- coding: utf-8 -*-
"""PoC fidelity: the shipped curl must replay what the scanner sent.

A PoC is the one artifact a human pastes into a terminal.  "Reproduces"
means shell-level fidelity, so these tests parse the generated command
with shlex (the same grammar a POSIX shell uses) and assert the parsed
arguments carry the payload on the SAME carrier, in the SAME encoding,
the scanner used on the wire.

Found by this suite (Phase 178b): the (header:X) branch percent-encoded
the payload while transport_layers put it on the wire RAW -- the shipped
curl replayed a value that never existed, and a raw-reflecting target
echoed percent-encoding instead of executable markup.  Fixed: raw value,
shlex-quoted argument.  The cookie branch keeps _enc() because the wire
value IS percent-encoded there (cookie_xss._cookie_encode_value).

No network.
"""
from __future__ import annotations
import os
import shlex
import sys
from urllib.parse import parse_qsl, urlparse, unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import poc as pocmod

RAW_PAYLOAD = "<svg/onload=alert('xsshd_ab12')>"
MARKER_PAYLOAD = "<script>alert(1)</script>"


def _f(**over):
    d = {
        "type": "reflected", "severity": "high", "param": "q",
        "context": "html_element", "payload": MARKER_PAYLOAD,
        "url": "http://t/s?a=1&b=2", "method": "GET",
        "detail": "token confirmed", "confidence": "high",
        "transform": ["raw"],
        "poc": {"curl": "", "url": "", "html": ""},
    }
    d.update(over)
    return d


def _curl_args(curl: str) -> list[str]:
    """Parse the command the way a shell would."""
    toks = shlex.split(curl)
    return [t for t in toks if t not in ("curl", "-i")]


def _hdr_value(curl: str) -> str:
    """The value of the first -H argument, parsed as a shell would."""
    args = shlex.split(curl)
    for i, t in enumerate(args):
        if t == "-H" and i + 1 < len(args):
            return args[i + 1]
    return ""


class TestHeaderCarrierFidelity:
    def test_header_payload_rides_the_wire_exactly_as_sent(self):
        """The regression: _enc() shipped a value the scanner never sent."""
        f = _f(url="http://t/ip", param="(header:True-Client-IP)",
               payload=RAW_PAYLOAD)
        poc = pocmod.build_poc(f)
        assert poc["curl"].startswith("curl -i 'http://t/ip'")
        got = _hdr_value(poc["curl"])
        assert got == f"True-Client-IP: {RAW_PAYLOAD}", (
            f"header PoC must replay the RAW wire value, got {got!r}")

    def test_header_payload_with_quotes_is_shell_safe(self):
        """shlex must round-trip the payload -- single quotes and all."""
        f = _f(url="http://t/ip", param="(header:X-Client-IP)",
               payload=RAW_PAYLOAD)
        poc = pocmod.build_poc(f)
        got = _hdr_value(poc["curl"])
        assert got.endswith(RAW_PAYLOAD)
        # ...and re-splitting the whole command never changes the value.
        assert _hdr_value(poc["curl"]) == got


class TestCookieCarrierFidelity:
    def test_cookie_value_is_percent_encoded_like_the_wire(self):
        """cookie_xss sends _cookie_encode_value() on the wire; the PoC
        must match that convention, not the raw payload."""
        f = _f(param="(cookie:tracking)", payload=RAW_PAYLOAD)
        poc = pocmod.build_poc(f)
        got = _hdr_value(poc["curl"])
        assert got.startswith("Cookie: tracking=")
        encoded = got.split("=", 1)[1]
        assert unquote(encoded) == RAW_PAYLOAD
        assert " " not in encoded and ";" not in encoded, (
            "an encoded cookie value must not contain separators")


class TestQueryCarrierFidelity:
    def test_other_query_params_are_preserved_in_order(self):
        f = _f(payload=RAW_PAYLOAD)
        poc = pocmod.build_poc(f)
        q = dict(parse_qsl(urlparse(poc["url"]).query, keep_blank_values=True))
        assert q["a"] == "1" and q["b"] == "2", "existing params lost"
        assert unquote(q["q"]) == RAW_PAYLOAD
        keys = [k for k, _ in parse_qsl(urlparse(poc["url"]).query)]
        assert keys == ["a", "b", "q"], "param order not preserved"

    def test_cookies_reach_the_query_curl(self):
        poc = pocmod.build_poc(_f(), cookies={"sid": "s3cret"})
        assert "-b 'sid=s3cret'" in poc["curl"]

    def test_post_with_query_carrier_keeps_method_and_no_body(self):
        f = _f(method="POST", param_in="query")
        poc = pocmod.build_poc(f)
        assert "-X POST" in poc["curl"]
        assert "--data" not in poc["curl"], (
            "a query-carried POST must not grow a body it never had")
        q = dict(parse_qsl(urlparse(poc["url"]).query,
                           keep_blank_values=True))
        assert unquote(q["q"]) == MARKER_PAYLOAD


class TestBodyCarrierFidelity:
    def test_post_body_carries_csrf_fields_and_payload(self):
        f = _f(method="POST", param="comment",
               csrf_fields={"csrf_token": "tok123", "parent": "7"})
        poc = pocmod.build_poc(f)
        body = dict(parse_qsl(_data_arg(poc["curl"]),
                              keep_blank_values=True))
        assert body["csrf_token"] == "tok123"
        assert body["parent"] == "7"
        assert body["comment"] == MARKER_PAYLOAD

    def test_injected_param_wins_over_same_name_csrf_field(self):
        f = _f(method="POST", param="comment",
               csrf_fields={"comment": "original"})
        poc = pocmod.build_poc(f)
        body = dict(parse_qsl(_data_arg(poc["curl"])))
        assert body["comment"] == MARKER_PAYLOAD

    def test_cookies_reach_the_body_curl(self):
        f = _f(method="POST", param="comment")
        poc = pocmod.build_poc(f, cookies={"sid": "s3cret"})
        assert "-b 'sid=s3cret'" in poc["curl"]

    def test_cookies_reach_the_upload_curl(self):
        f = _f(method="POST", param="file[filename]",
               type="upload_xss", payload=RAW_PAYLOAD)
        poc = pocmod.build_poc(f, cookies={"sid": "s3cret"})
        assert "-b 'sid=s3cret'" in poc["curl"]
        assert "-F 'file=@/dev/null;filename=" in poc["curl"]


def _data_arg(curl: str) -> str:
    args = shlex.split(curl)
    for i, t in enumerate(args):
        if t == "--data" and i + 1 < len(args):
            return args[i + 1]
    raise AssertionError(f"no --data argument in {curl!r}")


class TestDomMarkerFidelity:
    def test_dom_types_ship_the_sentinel_not_the_scanned_payload(self):
        f = _f(type="dom_dynamic", param="", context="hash innerHTML")
        poc = pocmod.build_poc(f)
        # The sentinel rides the target URL percent-encoded; judge the
        # page after decoding it.
        page = unquote(poc["html"])
        assert pocmod.DOM_POC_PAYLOAD in page
        assert MARKER_PAYLOAD not in page, (
            "the scanned payload is engine-internal; the PoC must use the "
            "DOM sentinel a browser run can confirm")

    def test_search_source_targets_the_query_not_the_hash(self):
        f = _f(type="dom_dynamic", param="", context="search eval")
        poc = pocmod.build_poc(f)
        assert "?xssv_probe=" in poc["html"]
        assert "#" not in _first_target(poc["html"]) or \
            "?xssv_probe=" in _first_target(poc["html"])

    def test_hash_source_targets_the_fragment(self):
        f = _f(type="dom_dynamic", param="", context="hash innerHTML")
        poc = pocmod.build_poc(f)
        assert "#" in poc["html"]


def _first_target(html: str) -> str:
    import re
    m = re.search(r'(?:src|href|action)=["\']([^"\']+)', html)
    return m.group(1) if m else ""
