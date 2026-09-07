# -*- coding: utf-8 -*-
"""Phase 99: MITM end-to-end drill -- interception -> capture -> scan -> finding.

test_passive_mitm.py proves the TRANSPORT layer (TLS terminated, params
reach the capture queue).  The operator-facing value, however, is the
FULL chain: browse an HTTPS target through the proxy once and the
captured endpoint comes back as a verified finding with a replayable
PoC -- zero URL list, zero manual step.  Nothing covered that chain
before this file.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy
from tests.test_passive_mitm import _TlsOrigin, _self_signed_cert, _tunneled_get

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


def test_mitm_to_finding_to_poc(tmp_path):
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    from xssentinel.core.passive_proxy import PassiveProxy, drain_captures
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    certbase = _self_signed_cert(tmp_path)
    origin = _TlsOrigin(certbase)
    origin.start()

    # proxy: relay to the self-signed origin must skip verification
    proxy = PassiveProxy(
        port=0, host="127.0.0.1", scope="127.0.0.1",
        requester=Requester(timeout=10, verify_ssl=False),
        mitm_ca=str(tmp_path / "mitm" / "ca.pem"))
    # scanner: re-probes the origin directly (also self-signed) and must
    # be small-budget so the drain finishes fast
    scanner = Scanner(
        requester=Requester(timeout=10, verify_ssl=False),
        verbose=False, max_payloads=6, max_transforms=4)
    scanner.use_headless = False
    stop = threading.Event()
    worker = threading.Thread(target=drain_captures,
                              args=(proxy, scanner),
                              kwargs={"stop_event": stop}, daemon=True)
    worker.start()

    ca_cert = str(tmp_path / "mitm" / "ca-cert.pem")
    proxy.start()
    try:
        # The operator's browser hits the HTTPS target through the proxy.
        status, body = _tunneled_get(
            proxy.port, f"{origin.base}/vuln?q=login", ca_cert)
        assert status == 200 and "login" in body

        deadline = time.time() + 90
        while proxy.stats["scans"] < 1 and time.time() < deadline:
            time.sleep(0.2)
        assert proxy.stats["mitm"] >= 1, proxy.stats
        assert proxy.stats["scans"] >= 1, (
            f"captured endpoint was never scanned: {proxy.stats}")

        assert scanner.findings, (
            "full MITM chain produced no finding -- capture -> scan "
            "pipeline is broken for HTTPS targets")
        f = scanner.findings[0]
        assert f.data.get("url", "").startswith("https://"), f.data
        assert f.data.get("param") == "q"

        shim_finding = scanner
        scanner.attach_pocs()
        poc = f.data.get("poc") or {}
        assert poc.get("curl"), f"no curl PoC for MITM finding: {poc}"
        assert "https://" in poc["curl"]
        # the PoC must replay the CONFIRMED payload, not the benign browse
        assert "q=" in poc["curl"] and "login" not in poc["curl"].split("curl")[-1] \
            or "%3C" in poc["curl"] or "<" in poc["curl"], poc["curl"]
    finally:
        stop.set()
        worker.join(timeout=5)
        proxy.stop()
        origin.stop()
