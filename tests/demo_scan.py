"""Demo: scan the local vulnerable server with XSSentinel and emit consolidated
HTML + JSON + CSV + SARIF reports covering every detection layer.

Self-test only — the target is the bundled vulnerable server.
"""
from __future__ import annotations
import os, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core.oob import SelfHostedListener
from xssentinel.core import report as reportmod

BASE = "http://127.0.0.1:8899"
TARGETS = [
    ("/echo",   "GET", {"q": "test"}, {}),   # L1 reflected - html_element
    ("/attr",   "GET", {"q": "test"}, {}),   # L1 reflected - html_attribute_dq
    ("/script", "GET", {"q": "test"}, {}),   # L1 reflected - script_string_dq
    ("/href",   "GET", {"q": "test"}, {}),   # L1 reflected - url_href
    ("/evt",    "GET", {"q": "test"}, {}),   # L1 reflected - event_handler
    ("/dom",    "GET", {},           {}),    # L3 DOM taint + L6 real-browser confirm
    ("/cdata",  "GET", {"q": "test"}, {}),   # context: CDATA
    ("/meta",   "GET", {"q": "test"}, {}),   # context: meta-refresh
    ("/tpl",    "GET", {"q": "test"}, {}),   # context: {{ }} template
    ("/waf",    "GET", {"q": "test"}, {}),   # L2 WAF-evasion (bypass + confirm)
    ("/blind",  "GET", {"q": "test"}, {}),   # L5 blind XSS (auto-confirm)
    ("/safe",   "GET", {"q": "test"}, {}),   # control: must find nothing
]

req = Requester(timeout=10)
oob = SelfHostedListener(host="127.0.0.1")
sc = Scanner(requester=req, verbose=False, oob=oob)
for path, method, params, data in TARGETS:
    sc.scan_endpoint(BASE + path, method, params, data)

# L4 stored XSS
sc.scan_stored(BASE + "/store", view_url=BASE + "/view", method="POST", param="q")

# L5 blind XSS auto-confirm (poll the callback listener)
sc.collect_oob(timeout=12)

# L7/Step3: collapse duplicates, then generate a reproducible PoC per finding.
sc.dedup()
sc.attach_pocs()

meta = {
    "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "requests": sc.requests_made,
    "waf": sc.waf_name,
}

here = os.path.dirname(os.path.abspath(__file__))
reports = {
    "demo_report.html": reportmod.build_html(sc.findings, BASE, meta),
    "demo_report.json": reportmod.build_json(sc.findings, BASE, meta),
    "demo_report.csv": reportmod.build_csv(sc.findings, BASE, meta),
    "demo_report.sarif": reportmod.build_sarif(sc.findings, BASE, meta),
}
for name, content in reports.items():
    with open(os.path.join(here, name), "w", encoding="utf-8") as f:
        f.write(content)

hi = sum(1 for f in sc.findings if f.data.get("severity") == "high")
print(f"[+] {len(sc.findings)} finding(s) ({hi} high), {sc.requests_made} requests")
print(f"[+] WAF: {sc.waf_name or 'none'}")
print(f"[+] reports: tests/demo_report.{{html,json,csv,sarif}}")
