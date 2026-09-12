"""Phase 121: param-miner benchmark targets behave as designed.

The hidden-param cases depend on the MODES_CTX handlers reading the
probed value from ctx["query"] (not the pinned param), because the
manifest cases carry param:"" -- a refactor that switches them to
PAGE_MODES would silently break the whole family (the value could
never reach the handler, the vuln case would read as FN, and nothing
else would catch it).
"""
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

server = importlib.import_module("benchmark.server")


def _ctx(query: dict) -> dict:
    return {"headers": {}, "path": "/x", "query": query, "method": "GET"}


class TestParamMinerTargets(unittest.TestCase):

    def test_registered_in_modes_ctx_not_page_modes(self):
        self.assertIn("pm_vuln", server.MODES_CTX)
        self.assertIn("pm_safe", server.MODES_CTX)
        # PAGE_MODES would mean the handler only ever sees the pinned
        # param ("" for these cases) -- the probed value could not land.
        self.assertNotIn("pm_vuln", server.PAGE_MODES)
        self.assertNotIn("pm_safe", server.PAGE_MODES)

    def test_vuln_reflects_hidden_name_into_script_string(self):
        status, headers, body = server.m_pm_vuln("", _ctx({"name": ["XSSTOKEN"]}))
        self.assertEqual(status, 200)
        self.assertIn('<script>var profile = "XSSTOKEN";</script>', body)

    def test_vuln_static_without_param(self):
        status, headers, body = server.m_pm_vuln("", _ctx({}))
        self.assertEqual(status, 200)
        self.assertNotIn("<script>", body)

    def test_safe_echoes_escaped_into_text_only(self):
        status, headers, body = server.m_pm_safe(
            "", _ctx({"name": ['"></script><script>alert(1)</script>']}))
        self.assertEqual(status, 200)
        self.assertNotIn("<script>", body)
        self.assertNotIn('"></script>', body)
        # html.escape(quote=True) encodes < > " &#x27; & -- the payload
        # cannot re-form inside the text node.
        self.assertIn("&lt;", body)

    def test_vuln_ignores_other_probed_params(self):
        # The miner probes 14 candidates; only `name` may reflect, or the
        # reflection-ratio mirror guard would fire and mining would stop.
        status, headers, body = server.m_pm_vuln(
            "", _ctx({"q": ["MARK1"], "query": ["MARK2"], "search": ["MARK3"]}))
        self.assertNotIn("MARK1", body)
        self.assertNotIn("MARK2", body)
        self.assertNotIn("MARK3", body)


if __name__ == "__main__":
    unittest.main()
