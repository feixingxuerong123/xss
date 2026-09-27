# -*- coding: utf-8 -*-
"""Quick verification: start benchmark server, hit every endpoint, check responses."""
import sys, os, io, json, time, threading, http.client
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import run_server, load_routes, MODES

PORT = 18777

def main():
    routes = load_routes()
    print(f"Manifest loaded: {len(routes)} routes")

    # Check all modes have handlers
    missing = set()
    for path, case in routes.items():
        if case["mode"] not in MODES:
            missing.add(case["mode"])
    if missing:
        print(f"ERROR: {len(missing)} modes without handlers: {missing}")
        return 1
    print(f"All {len(set(c['mode'] for c in routes.values()))} unique modes have handlers")

    # Start server in background thread
    started = threading.Event()
    def on_ready(srv):
        started.set()
        # serve_forever is run by run_server itself now

    t = threading.Thread(target=run_server, args=(PORT,), kwargs={"ready_callback": on_ready}, daemon=True)
    t.start()
    started.wait(timeout=5)
    time.sleep(0.3)

    # Test every endpoint
    ok = 0
    fail = 0
    errors = []
    for path, case in sorted(routes.items()):
        param = case.get("param", "q")
        if param:
            url = f"{path}?{param}=test123"
        else:
            url = path
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
            conn.request("GET", url)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            conn.close()
            if resp.status == 200 and len(body) > 10:
                ok += 1
            else:
                fail += 1
                errors.append(f"  {case['id']}: status={resp.status} len={len(body)}")
        except Exception as e:
            fail += 1
            errors.append(f"  {case['id']}: {e}")

    print(f"\nResults: {ok} OK, {fail} FAILED out of {len(routes)} endpoints")
    if errors:
        print("Failures:")
        for e in errors[:20]:
            print(e)

    # Spot-check a few specific behaviors
    print("\n--- Spot checks ---")
    checks = [
        ("/r/elem01?q=<script>alert(1)</script>", "raw element reflects raw"),
        ("/s/esc01?q=<script>alert(1)</script>", "escape element encodes"),
        ("/s/rcd01?q=<script>alert(1)</script>", "textarea RCDATA"),
        ("/s/csp01?q=<script>alert(1)</script>", "CSP header present"),
    ]
    for url, desc in checks:
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
        conn.request("GET", url)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        hdrs = dict(resp.getheaders())
        conn.close()
        if "esc01" in url:
            assert "&lt;script&gt;" in body, f"FAIL {desc}: not escaped"
            print(f"  PASS: {desc}")
        elif "elem01" in url:
            assert "<script>alert(1)</script>" in body, f"FAIL {desc}: not raw"
            print(f"  PASS: {desc}")
        elif "rcd01" in url:
            assert "<textarea>" in body, f"FAIL {desc}: no textarea"
            print(f"  PASS: {desc}")
        elif "csp01" in url:
            csp = hdrs.get("Content-Security-Policy", "")
            assert "script-src" in csp, f"FAIL {desc}: no CSP header"
            print(f"  PASS: {desc} (CSP: {csp[:40]}...)")

    print(f"\n{'ALL PASS' if fail == 0 else 'SOME FAILURES'}")
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
