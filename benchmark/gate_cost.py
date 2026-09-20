"""Attribute the sandbox gate's real cost, and the benchmark's.

Why this exists: `tests/test_benchmark_fp.py` went from ~100s (all of block D,
137 tests) to >2300s for one file.  `sandbox.judge` -- wired into
`verify_semantic` as of this round -- was the prime suspect, so the claim needs
a number instead of an argument.

Two independent measurements:

1. gate cost, offline: run `judge()` over the 900 browser-measured documents in
   `results/browser_dom_oracle.json` (deliberately adversarial HTML) and over
   the JS reader in isolation.  No sockets, so no machine-load noise.
2. loopback health, live: time `connect()` to a local listener.  This is the
   step `test_benchmark_fp.py` actually spends its time in.

Usage: python benchmark/gate_cost.py
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from xssentinel.core import sandbox  # noqa: E402

ORACLE = pathlib.Path(__file__).resolve().parent / "results" / "browser_dom_oracle.json"
TOKEN = "__x()"               # the oracle's quote-free sentinel, present in payload
SINKS = ("parser", "innerhtml")


def gate_cost() -> float:
    data = json.loads(ORACLE.read_text(encoding="utf-8"))
    docs = [r["document"] for r in data["rows"]]

    sandbox.judge(docs[0], TOKEN, sink="parser")   # warm imports/regex compile

    t0 = time.perf_counter()
    n = 0
    states = {"live": 0, "inert": 0, "unknown": 0}
    for d in docs:
        for sink in SINKS:
            states[sandbox.judge(d, TOKEN, sink=sink).state] += 1
            n += 1
    dt = time.perf_counter() - t0

    mb = sum(len(d) for d in docs) / 1e6
    print(f"[1] gate cost (offline, {len(docs)} documents, {mb:.2f} MB)")
    print(f"    judge() over {len(SINKS)} sinks: {dt:.3f}s for {n} calls "
          f"-> {dt/n*1000:.3f} ms per call")
    print(f"    state tally       : {states}")

    # the two suspects, isolated: pure parse+serialise vs the esprima JS read
    t0 = time.perf_counter()
    for d in docs:
        sandbox.serialize(sandbox.parse(d).root)
    t_parse = time.perf_counter() - t0
    t0 = time.perf_counter()
    for d in docs:
        sandbox.js_state_at(d, TOKEN)
    t_js = time.perf_counter() - t0
    print(f"    parse+serialize   : {t_parse:.3f}s")
    print(f"    js_state_at       : {t_js:.3f}s")
    print(f"    the gate is ONE call per response: {dt/n*1000:.3f} ms "
          f"-> {dt/n*185:.2f}s across a 185-case benchmark")
    return dt / n


def loopback_health() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept() -> None:
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                c.settimeout(2.0)
                try:
                    c.recv(4096)
                except OSError:
                    pass
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass        # client hung up mid-handshake; not a listener fault
            finally:
                c.close()

    th = threading.Thread(target=accept, daemon=True)
    th.start()
    print(f"[2] loopback connect() health (local listener on 127.0.0.1:{port})")
    lats = []
    for _ in range(40):
        t0 = time.perf_counter()
        c = socket.create_connection(("127.0.0.1", port), timeout=10)
        lats.append((time.perf_counter() - t0) * 1000)
        c.close()
    stop.set()
    srv.close()
    lats.sort()
    print(f"    connect() p50={lats[len(lats)//2]:.2f}ms  "
          f"p95={lats[int(len(lats)*.95)]:.2f}ms  worst={lats[-1]:.2f}ms")
    print(f"    pid {os.getpid()}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    gate_cost()
    print()
    loopback_health()
