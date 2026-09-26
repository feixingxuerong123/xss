"""Unit tests for Phase 34: automatic pre-encoding pipeline (base64/JWT/
JSON container detection and same-container payload injection).
"""
from __future__ import annotations
import base64
import json
import os
import sys
from unittest.mock import patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import pre_encode as pe
from xssentinel.core.scanner import Scanner
from xssentinel.core.requester import Requester


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode().rstrip("=")


def b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class TestDetectStructure:
    def test_jwt_detected(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9."          # {"alg":"HS256"}
               "eyJzdWIiOiJhZG1pbiJ9."           # {"sub":"admin"}
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV")
        assert pe.detect_structure(jwt) == "jwt"

    def test_json_b64_detected(self):
        v = b64('{"redirect":"http://x/y"}')
        assert pe.detect_structure(v) == "json_b64"

    def test_double_b64_detected(self):
        v = b64(b64("secret-value=42;"))
        assert pe.detect_structure(v) == "double_b64"

    def test_plain_b64_with_structure_char(self):
        v = b64("next=/admin/dashboard")   # decodes to text with "/"
        assert pe.detect_structure(v) == "b64"

    def test_plain_word_not_mistaken_for_container(self):
        # "helloworld" matches the b64 charset, but its decode is either
        # non-printable garbage or pure alnum -- must stay "none".
        assert pe.detect_structure("helloworld") == "none"
        assert pe.detect_structure("abcdefgh") == "none"

    def test_plain_text_and_short_values(self):
        assert pe.detect_structure("hello world 123") == "none"
        assert pe.detect_structure("abc") == "none"
        assert pe.detect_structure("") == "none"

    def test_urlsafe_b64_detected(self):
        v = b64url('{"next":"a_b"}')
        assert pe.detect_structure(v) in ("json_b64", "b64")


class TestEncodePayload:
    def test_b64_roundtrip(self):
        v = b64("next=/admin")
        enc = pe.encode_payload(v, "b64", "<script>alert(1)</script>")
        assert enc and pe._b64decode(enc).decode() == "<script>alert(1)</script>"

    def test_double_b64_roundtrip(self):
        v = b64(b64("token=abc;"))
        enc = pe.encode_payload(v, "double_b64", "<svg onload=alert(1)>")
        once = pe._b64decode(enc).decode()
        assert pe._b64decode(once).decode() == "<svg onload=alert(1)>"

    def test_json_b64_adds_field(self):
        v = b64('{"redirect":"http://x"}')
        marked = "<script>alert('xssv_abc')</script>"
        enc = pe.encode_payload(v, "json_b64", marked)
        obj = json.loads(pe._b64decode(enc))
        assert obj["xssentinel"] == marked
        # Phase 178c: blind injection REPLACES every existing string field
        # too -- an endpoint that echoes only specific keys (a redirect
        # target, a profile name) never renders our injected field.
        assert obj["redirect"] == marked

    def test_jwt_keeps_header_and_signature(self):
        sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
        jwt = f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.{sig}"
        marked = "<script>alert('xssv_abc')</script>"
        enc = pe.encode_payload(jwt, "jwt", marked)
        h, p, s = enc.split(".")
        assert s == sig                                   # signature kept
        assert pe._b64decode(h).decode() == '{"alg":"HS256"}'
        obj = json.loads(pe._b64decode(p))
        assert obj["xssentinel"] == marked
        # Phase 178c: existing claims are covered as well -- the app
        # renders whichever claim IT reads (Range3 /jwtview renders only
        # "name": 0 findings under the inject-field-only shape).
        assert obj["sub"] == marked

    def test_non_dict_json_returns_none(self):
        v = b64('[1,2,3]')
        assert pe.encode_payload(v, "json_b64", "x") is None

    def test_bad_struct_returns_none(self):
        assert pe.encode_payload("whatever", "nope", "x") is None


class _FakeResp:
    status_code = 200
    headers = {}

    def __init__(self, text):
        self.text = text


class _DecodingFakeReq:
    """Simulates an app that base64-DECODES the q param before echoing it
    UNESCAPED into a <div> -- so a container-wrapped payload becomes live
    markup and the semantic verifier confirms it."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def _maybe_decode(s: str) -> str:
        for _ in range(2):
            try:
                d = base64.b64decode(
                    s.replace("-", "+").replace("_", "/")
                    + "=" * (-len(s) % 4))
                t = d.decode("utf-8")
                if t.isprintable() and t:
                    s = t
                    continue
            except Exception:
                pass
            break
        return s

    def request(self, method, url, params=None, data=None, **kw):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        return _FakeResp(f"<html><body><div>{self._maybe_decode(val)}"
                         f"</div></body></html>")

    def clone(self):
        return self

    def invalidate(self, url):
        pass


class TestPreEncodedScanIntegration:
    def test_container_payload_confirmed_and_plain_loop_skipped(self):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False)
        fake = _DecodingFakeReq()
        orig = b64("next=/admin")          # structured value
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": None, "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": orig}, {}, "q", False)
        findings = [f for f in sc.findings
                    if any("pre_encode" in str(t)
                           for t in (f.data.get("transform") or []))]
        assert findings, "expected a pre-encoded finding"
        f0 = findings[0].data
        assert f0["type"] == "reflected"
        assert f0["confidence"] == "high"
        # The recorded payload is still container-encoded (what was sent).
        assert pe._b64decode(f0["payload"]).decode().startswith("<script>")

    def test_no_pre_encoded_probes_on_plain_values(self):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False)
        fake = _DecodingFakeReq()
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": None, "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": "plain text value!"}, {}, "q", False)
        pre_calls = [c for c in fake.calls
                     if any("xssentinel" in (v or "") and False
                            for v in c["params"].values())]
        assert not pre_calls
        assert not [f for f in sc.findings
                    if "pre_encode" in str(f.data.get("transform"))]
