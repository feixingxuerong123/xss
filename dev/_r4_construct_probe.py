# -*- coding: utf-8 -*-
"""Range4 construct-validity probe (2026-09-28).

Before any verdict means anything, the NEGATIVE cases must be shown, with
no browser involved, to not contain the attacker string in server HTML.
Range4 draft #1 failed exactly this: the "safe" twin reflected the param
into a server-side JS config line -- itself a script-string sink -- so
every variant confirmed and the control measured FP.

Usage:  python dev/_r4_construct_probe.py
"""
from __future__ import annotations

import pathlib
import re
import sys
import threading
import time

import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "range4"))

from server import run_server  # noqa: E402

PORT = 19706
MARK = "zzcanary9zz"
CASES = [("/react", "search"), ("/react-safe", "search"),
         ("/vue", "msg"), ("/vue-safe", "msg")]


def main() -> int:
    started = threading.Event()
    threading.Thread(target=run_server, args=(PORT,),
                     kwargs={"ready_callback": lambda s: started.set()},
                     daemon=True).start()
    if not started.wait(10):
        print("[!] server failed to start")
        return 1
    time.sleep(0.3)

    ok = True
    for path, param in CASES:
        r = requests.get(f"http://127.0.0.1:{PORT}{path}?{param}={MARK}",
                         timeout=5)
        body = r.text
        reflected = MARK in body
        cfg = re.search(r"__INITIAL__ = \{(.*?)\}", body)
        expect = path.endswith("-safe") is False
        good = (reflected == expect)
        ok = ok and good
        print(f"{path:14} status={r.status_code} len={len(body):5} "
              f"server_reflect={reflected!s:5} expected={expect!s:5} "
              f"{'OK' if good else '*** INVALID ***'}")
        print(f"               config line: {cfg.group(1) if cfg else None!r}")
        app = re.search(r'src="(/app_[^"]+)"', body)
        print(f"               app bundle : {app.group(1) if app else None}")
    print("\nconstruct validity:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
