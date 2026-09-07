"""Crawl demo: deep-crawl /links and emit HTML/JSON/CSV/SARIF reports.
Self-test only — target is the bundled vulnerable server.
Shows the discovery layer (crawler -> dedup -> reproducible PoC) end-to-end.
"""
from __future__ import annotations
import os, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core import report as reportmod

BASE = "http://127.0.0.1:8899"
req = Requester(timeout=10)
sc = Scanner(requester=req, verbose=False, crawl=True, crawl_depth=2,
             dom_engine="auto")
sc.scan_target(BASE + "/links", oob_collect=False)
sc.dedup()
sc.attach_pocs()

meta = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "requests": sc.requests_made, "waf": sc.waf_name}
here = os.path.dirname(os.path.abspath(__file__))
reports = {
    "crawl_demo_report.html": reportmod.build_html(sc.findings, BASE, meta),
    "crawl_demo_report.json": reportmod.build_json(sc.findings, BASE, meta),
    "crawl_demo_report.csv": reportmod.build_csv(sc.findings, BASE, meta),
    "crawl_demo_report.sarif": reportmod.build_sarif(sc.findings, BASE, meta),
}
for name, content in reports.items():
    with open(os.path.join(here, name), "w", encoding="utf-8") as f:
        f.write(content)

hi = sum(1 for f in sc.findings if f.data.get("severity") == "high")
print(f"[+] CRAWL DEMO: {len(sc.findings)} finding(s) ({hi} high), "
      f"{sc.requests_made} requests")
for f in sc.findings:
    d = f.data
    poc = d.get("poc") or {}
    print(f"    - [{d.get('severity')}] {d.get('type'):10} {d.get('url')} "
          f"param={d.get('param')} ctx={d.get('context')} | "
          f"poc_url={'yes' if poc.get('url') else 'no'}")
print(f"[+] reports: tests/crawl_demo_report.{{html,json,csv,sarif}}")
