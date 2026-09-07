"""Debug: identify which finding is the /safe false positive."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core.oob import SelfHostedListener

BASE = "http://127.0.0.1:8899"
req = Requester(timeout=10)
oob = SelfHostedListener(host="127.0.0.1")
sc = Scanner(requester=req, verbose=False, oob=oob)
sc.scan_endpoint(BASE + "/safe", "GET", {"q": "test"}, {})

print("=== /safe findings ===")
for f in sc.findings:
    d = f.data
    t = d.get("type")
    p = d.get("param")
    c = d.get("context")
    s = d.get("severity")
    detail = (d.get("detail") or d.get("evidence") or "")[:200]
    payload = (d.get("payload") or "")[:200]
    print("  type=%s param=%s ctx=%s sev=%s" % (t, p, c, s))
    print("    detail=%s" % detail)
    print("    payload=%s" % payload)
print("Total:", len(sc.findings))
