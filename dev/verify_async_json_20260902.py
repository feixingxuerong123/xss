"""Phase 47 regression check: async JSON-body carrier (async_scanner.py).

Before Phase 47 the --async path NEVER parsed JSON bodies: every body probe
went out form-encoded, so JSON APIs (the majority of modern POST endpoints)
were scanned against zero body params.  This script proves the carrier end
to end against a REAL aiohttp server that ONLY accepts application/json and
reflects a NESTED leaf (user.name) raw into HTML:

  1. baseline POST carries the JSON document as application/json;
  2. L1 enumerates leaf paths of the document (user.name, not just top keys);
  3. body probes go out as application/json (aiohttp json=) and a genuine
     nested reflection is confirmed as a Finding.

A form-encoded body would make request.json() raise -> 400 -> no reflection
-> no finding, so a pass here is also proof the carrier switch happened.

Usage:  python dev/verify_async_json_20260902.py
Exit code 0 = all checks passed.  Output is written to stdout; redirect to
a file when the loopback is flaky.
"""
from __future__ import annotations
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web  # noqa: E402

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402
from xssentinel.core.requester import JsonBody  # noqa: E402


# ---------------------------------------------------------------------------
# JSON-only test endpoint: nested leaf reflected raw into HTML
# ---------------------------------------------------------------------------
async def json_echo_handler(request: web.Request) -> web.Response:
    if request.content_type != "application/json":
        return web.Response(status=415, text="json only")
    try:
        doc = await request.json()
    except Exception:
        return web.Response(status=400, text="bad json")
    # Nested leaf -- only reachable if the carrier preserved the document.
    name = ((doc.get("user") or {}).get("name")) or ""
    return web.Response(
        text=f"<html><body><div>{name}</div></body></html>",
        content_type="text/html",
    )


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/api", json_echo_handler)
    return app


# ---------------------------------------------------------------------------
# AsyncScanner JSON-mode run
# ---------------------------------------------------------------------------
async def scan_once(port: int) -> list:
    json_body = {"user": {"name": "orig"}, "tags": ["a"]}
    asc = AsyncScanner(
        max_concurrent=2,
        max_payloads=6,
        max_transforms=1,
        timeout=8,
        json_body=json_body,
    )
    asc._semaphore = asyncio.Semaphore(2)
    found = []
    async for f in asc.scan(f"http://127.0.0.1:{port}/api", method="POST",
                            params={}, data={}):
        found.append(f)
    return found, asc


async def main() -> int:
    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    checks = []
    try:
        for attempt in range(3):  # loopback may reset mid-run (WinError 10054)
            try:
                found, asc = await scan_once(port)
                break
            except (ConnectionResetError, ConnectionAbortedError,
                    OSError) as e:
                print(f"  attempt {attempt + 1} connection issue: {e!r}")
                found, asc = [], None
                await asyncio.sleep(0.5)
        print(f"[1] requests_made: {getattr(asc, 'requests_made', 0)}")
        types = [f.data.get("type") for f in found]
        params = [f.data.get("param") for f in found]
        print(f"[2] findings: {len(found)}  types={types}  params={params}")
        checks.append(("baseline+probes ran (requests_made>0)",
                       bool(getattr(asc, "requests_made", 0) > 0)))
        checks.append(("reflected finding confirmed",
                       any(t == "reflected" for t in types)))
        checks.append(("nested leaf 'user.name' was probed/confirmed",
                       any(p == "user.name" for p in params)))
    finally:
        await runner.cleanup()

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    # Sanity: JsonBody still translates at the async boundary (_body_kwargs).
    from xssentinel.core.async_scanner import _body_kwargs
    kw = _body_kwargs(JsonBody({"a": 1}))
    checks.append(("_body_kwargs maps JsonBody -> json=", kw.get("json") == {"a": 1}))
    print(f"[{'PASS' if kw.get('json') == {'a': 1} else 'FAIL'}] "
          f"_body_kwargs maps JsonBody -> json=")
    return 0 if (ok and kw.get("json") == {"a": 1}) else 1


if __name__ == "__main__":
    code = asyncio.run(main())
    sys.exit(code)
