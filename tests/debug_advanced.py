"""Debug: test each advanced endpoint individually."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

BASE = "http://127.0.0.1:8899"
req = Requester(timeout=10)

advanced = [
    ("/mxss",      "GET", {"q": "test"}, {}, "mXSS"),
    ("/clobber",   "GET", {"q": "test"}, {}, "DOM clobber"),
    ("/tpl-eval",  "GET", {"q": "test"}, {}, "Template SSTI"),
    ("/jsonp",     "GET", {"callback": "test"}, {}, "JSONP"),
    ("/csp-weak",  "GET", {"q": "test"}, {}, "CSP weak"),
    ("/csp-strong","GET", {"q": "test"}, {}, "CSP strong"),
    ("/css",       "GET", {"q": "test"}, {}, "CSS context"),
    ("/comment",   "GET", {"q": "test"}, {}, "HTML comment"),
]

for path, method, params, data, label in advanced:
    sc = Scanner(requester=Requester(timeout=10), verbose=False)
    sc.scan_endpoint(BASE + path, method, params, data)
    types = [f.data.get("type") for f in sc.findings]
    sevs = [f.data.get("severity") for f in sc.findings]
    print("%-15s %s -> %d finding(s): %s" % (label, path, len(sc.findings),
          list(zip(types, sevs)) if types else "(none)"))
