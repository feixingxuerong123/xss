"""Quick coverage tracker demo (not a pytest test -- standalone run)."""
import sys, os, time, threading, http.server, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import urlparse, parse_qs
from tests.vuln_server import PAGES
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core import report as reportmod


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query).get('q', [''])[0]
        cb = parse_qs(u.query).get('callback', [''])[0]
        key = u.path
        if key in PAGES:
            body = PAGES[key](cb or q).encode()
            extra_hdrs = []
            if key == '/csp-weak':
                extra_hdrs = [('Content-Security-Policy', "script-src 'unsafe-inline'")]
            self.send_response(200)
            for h, v in extra_hdrs:
                self.send_header(h, v)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'not found')

    def do_POST(self):
        u = urlparse(self.path)
        l = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(l).decode() if l else ''
        q = parse_qs(body).get('q', [''])[0]
        if u.path == '/store':
            PAGES['/store'](q)
            self.send_response(200); self.end_headers(); self.wfile.write(b'stored')
        else:
            self.do_GET()


srv = http.server.HTTPServer(('127.0.0.1', 8898), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.3)

req = Requester(timeout=5)
sc = Scanner(requester=req, verbose=False)
sc.scan_endpoint('http://127.0.0.1:8898/echo', 'GET', {'q': 'test'}, {})
sc.scan_endpoint('http://127.0.0.1:8898/safe', 'GET', {'q': 'test'}, {})
sc.scan_endpoint('http://127.0.0.1:8898/csp-weak', 'GET', {'q': 'test'}, {})

cov = sc.coverage.summary()
print('=== Coverage summary ===')
print('Endpoints:', cov['totals']['endpoints'])
print('Params:', cov['totals']['parameters'])
print('Reflected:', cov['totals']['reflected'])
print('Confirmed:', cov['totals']['confirmed'])
print('Payloads dispatched:', cov['totals']['payloads_dispatched'])
print('Requests:', cov['totals']['requests'])
print('Findings:', cov['totals']['findings'])
print('Payload classes:', cov['totals']['payload_classes'])
print()
print('=== Layer coverage ===')
for lid, cnt in sorted(cov['layer_coverage'].items()):
    if cnt > 0:
        print('  {}: {}'.format(lid, cnt))
print()
print('=== Per-endpoint ===')
for ep in cov['endpoints']:
    n_layers = len(ep['layers'])
    print('  {} {}: {} layers, {} params, {} reqs, {} findings'.format(
        ep['method'], ep['url'], n_layers, len(ep['params']),
        ep['requests'], ep['findings']))
    for pk, pv in ep['params'].items():
        loc = 'body' if pv['in_body'] else 'query'
        print('    - {} ({}): reflected={} ctx={} payloads={} classes={} confirmed={}'.format(
            pv['name'], loc, pv['reflected'], pv['context'],
            pv['payloads_sent'], pv['payload_classes'], pv['confirmed']))

html = sc.coverage.to_html()
print()
print('=== HTML rendering ===')
print('Section length:', len(html), 'chars')
print('Has "Scan Coverage Report":', 'Scan Coverage Report' in html)
print('Has "Detection Layer Coverage":', 'Detection Layer Coverage' in html)
print('Has "Per-Endpoint Summary":', 'Per-Endpoint Summary' in html)
print('Has "Per-Parameter Detail":', 'Per-Parameter Detail' in html)
print('Has "Overall Layer Coverage":', 'Overall Layer Coverage' in html)

report_json = reportmod.build_json(
    sc.findings, 'http://127.0.0.1:8898',
    {'coverage': sc.coverage, 'generated': 'now',
     'requests': sc.requests_made, 'waf': sc.waf_name})
parsed = json.loads(report_json)
print()
print('=== JSON report ===')
print('Has coverage key:', 'coverage' in parsed)
if 'coverage' in parsed:
    print('Coverage totals:', parsed['coverage']['totals'])
