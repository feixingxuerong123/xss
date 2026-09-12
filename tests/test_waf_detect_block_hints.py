"""Phase 122: WAF block-page hints must be a BODY signal.

Regression for a benchmark-found defect: detect() searched full_blob
(headers + body) for _BLOCK_BODY_HINTS, whose patterns include the
cloudflare/cf-ray FINGERPRINTS -- so every unblocked 200 response from
any fingerprinted WAF was classified as blocked, and _try_payload then
discarded every payload the WAF actually let through.  That silently
killed payload confirmation on ALL WAF'd sites (L2_position_shift was
just the first benchmark case to walk this path).
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xssentinel.core import waf as wafmod


class _R:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


_WAF_HEADERS = {"Server": "cloudflare", "CF-RAY": "7c1f2e3a-SJC"}


class TestBlockHintsAreBodySignals(unittest.TestCase):

    def test_unblocked_200_from_fingerprinted_waf_is_not_blocked(self):
        """The exact defect: WAF fingerprint headers + a normal page
        carrying a REFLECTED PAYLOAD must not read as a block."""
        r = _R(200, dict(_WAF_HEADERS),
               '<div id="search">Results for '
               '<img src=x onerror=alert("xssv_abcd1234")></div>')
        d = wafmod.detect(r)
        self.assertEqual(d["waf"], "Cloudflare")
        self.assertFalse(d["blocked"])
        self.assertEqual(d["reason"], "")

    def test_real_block_page_in_body_is_blocked(self):
        r = _R(200, dict(_WAF_HEADERS),
               "<h1>Attention Required</h1><p> Sorry, you have been "
               "blocked. Ray ID: 7c1f2e3a</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertIn("block page", d["reason"])

    def test_strong_status_blocks_regardless_of_body(self):
        r = _R(406, dict(_WAF_HEADERS), "<p>ok</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["reason"], "HTTP 406")

    def test_soft_block_status_needs_vendor(self):
        r = _R(404, {"Server": "nginx"}, "<p>nope</p>")
        d = wafmod.detect(r)
        self.assertFalse(d["blocked"])

    def test_body_hint_without_vendor_is_generic_block(self):
        r = _R(200, {"Server": "nginx"}, "<p>Request blocked by policy</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["waf"], "Generic/Unknown WAF")

    def test_fingerprint_headers_alone_do_not_invent_a_block(self):
        """A WAF-fingerprinted EMPTY page is still not a block page."""
        r = _R(200, dict(_WAF_HEADERS), "<p>hello</p>")
        d = wafmod.detect(r)
        self.assertFalse(d["blocked"])


if __name__ == "__main__":
    unittest.main()
