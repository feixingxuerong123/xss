# -*- coding: utf-8 -*-
"""Phase 173 probe: does the stored value actually EXECUTE in a browser?

The challenge's solveIf() only checks `sanitizedComment.includes('<iframe
src="javascript:alert(`xss`)">')` -- a STRING test.  A stored string that
merely contains those characters is not the same thing as a tag the browser
builds and a javascript: URL the browser runs.  This probe runs a real
Playwright browser OUTSIDE pytest (skill section 9: pytest + playwright hangs
intermittently here) and reports, separately:

  * whether an <iframe> element with a javascript: src exists in the DOM
  * whether a dialog (alert) actually fired
  * what the rendered HTML around the comment looks like

Usage: python _p173_exec.py [port] [--engine static]
"""
from __future__ import annotations

import json
import sys
import urllib.request

PORT = sys.argv[1] if len(sys.argv) > 1 else "3000"
BASE = f"http://127.0.0.1:{PORT}"

ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASS = "admin123"


def login() -> str:
    req = urllib.request.Request(
        BASE + "/rest/user/login",
        data=json.dumps({"email": ADMIN_EMAIL, "password": ADMIN_PASS}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())["authentication"]["token"]


def main() -> int:
    from playwright.sync_api import sync_playwright

    jwt = login()
    print("logged in, jwt len =", len(jwt))

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context()
        # localStorage seeding must be origin-scoped (skill section 18): an
        # init script runs in EVERY frame, so an unscoped write would leak
        # the token into any third-party iframe.
        ctx.add_init_script(
            f"if (location.origin === '{BASE}') "
            f"localStorage.setItem('token', {json.dumps(jwt)});")

        page = ctx.new_page()
        dialogs: list[str] = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

        for route in ("/#/administration", "/#/contact"):
            dialogs.clear()
            page.goto(BASE + route, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(2500)
            frames = page.evaluate(
                "() => [...document.querySelectorAll('iframe,frame')]"
                ".map(e => ({tag: e.tagName, src: e.getAttribute('src')}))")
            js_frames = [f for f in frames if (f.get("src") or "").startswith("javascript:")]
            has_marker = page.evaluate(
                "() => document.body.innerHTML.includes('sanitize-html module')")
            print(f"\n=== {route} ===")
            print("  iframe/frame elements :", frames)
            print("  javascript: frames    :", js_frames)
            print("  comment text present  :", has_marker)
            print("  dialogs fired         :", dialogs)

        # Also check whether the raw feed API hands back the tag as data
        try:
            req = urllib.request.Request(
                BASE + "/api/Feedbacks", headers={"Authorization": f"Bearer {jwt}"})
            with urllib.request.urlopen(req, timeout=20) as r:
                _d = json.loads(r.read())
            comments = [f.get("comment") for f in _d.get("data", [])]
            hit = [c for c in comments if c and "javascript:alert" in c]
            print("\n=== /api/Feedbacks (as admin) ===")
            print("  entries:", len(comments), "| entries carrying the payload:", len(hit))
            if hit:
                print("  raw:", repr(hit[0]))
        except Exception as exc:  # noqa: BLE001
            print("\n/api/Feedbacks read failed:", exc)

        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
