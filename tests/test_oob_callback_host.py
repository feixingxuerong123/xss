"""Phase 134: the callback host must be independent of the bind address.

Before this, ``SelfHostedListener`` had a single ``host`` field that drove
both the local bind AND the host written into ``callback_url``.  The
default (``127.0.0.1``) therefore produced a callback URL pointing at the
*victim's own* loopback, so against a remote target the injected payload
could never come back -- ``--oob self`` looked wired up while silently
confirming nothing.  Binding a public address instead was the only way to
make it work, and that fails on any host that is behind NAT or does not
own the address.

Now: ``host`` binds, ``public_host`` is advertised, and the CLI warns when
a loopback callback meets a non-loopback target.

The lifecycle test uses a REAL loopback server and deliberately binds
``0.0.0.0`` while advertising ``127.0.0.1``, which proves the two fields
are wired separately rather than aliased.
"""
from __future__ import annotations

import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import oob  # noqa: E402
from xssentinel.core.oob import (  # noqa: E402
    SelfHostedListener,
    callback_host_is_unreachable,
    callback_reachability_warning,
    make_listener,
    oob_callback_warning,
)


# --------------------------------------------------------------------------
# 1. bind address and advertised host are separate
# --------------------------------------------------------------------------

def test_callback_url_uses_the_public_host():
    lst = SelfHostedListener(host="0.0.0.0", port=8900,
                             public_host="cb.example.test")
    assert lst.host == "0.0.0.0"          # binds everywhere
    assert lst.callback_url("tok") == "http://cb.example.test:8900/tok"


def test_public_host_defaults_to_the_bind_host():
    """Backwards compatible: existing callers pass only ``host``."""
    lst = SelfHostedListener(host="127.0.0.1", port=8900)
    assert lst.public_host == "127.0.0.1"
    assert lst.callback_url("tok") == "http://127.0.0.1:8900/tok"


def test_make_listener_threads_public_host():
    lst = make_listener("self", host="0.0.0.0", port=8900,
                        public_host="10.0.0.9")
    assert isinstance(lst, SelfHostedListener)
    assert lst.callback_url("t") == "http://10.0.0.9:8900/t"


def test_make_listener_interactsh_ignores_the_local_knobs():
    assert make_listener("interactsh", host="0.0.0.0",
                         public_host="x.example").name == "interactsh"


def test_end_to_end_callback_arrives_while_bind_differs_from_public_host():
    """Bind 0.0.0.0, advertise 127.0.0.1: the two are genuinely independent."""
    lst = SelfHostedListener(host="0.0.0.0", port=None,
                             public_host="127.0.0.1")
    lst.start()
    try:
        assert lst.host == "0.0.0.0"
        assert lst.public_host == "127.0.0.1"
        token = lst.token()
        url = lst.callback_url(token)
        assert "127.0.0.1" in url
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
        assert lst.poll({token}, timeout=5) == {token}
    finally:
        lst.stop()


# --------------------------------------------------------------------------
# 2. the reachability warning
# --------------------------------------------------------------------------

def test_warns_when_a_loopback_callback_faces_a_remote_target():
    msg = callback_reachability_warning("http://127.0.0.1:8900/tok",
                                        "http://target.example/x")
    assert msg and "--oob-host" in msg, msg


def test_silent_for_a_local_target():
    """A local target beacons from this machine, so loopback is correct."""
    for target in ("http://127.0.0.1:8080/x", "http://localhost:8080/x"):
        assert callback_reachability_warning(
            "http://127.0.0.1:8900/tok", target) is None, target


def test_silent_when_the_public_host_is_reachable():
    assert callback_reachability_warning(
        "http://cb.example.test:8900/tok", "http://target.example/x") is None


def test_warns_for_every_127_0_0_x_address():
    assert callback_host_is_unreachable("127.0.0.1")
    assert callback_host_is_unreachable("127.9.9.9")
    assert callback_host_is_unreachable("localhost")
    assert callback_host_is_unreachable("::1")
    assert callback_host_is_unreachable("0.0.0.0")
    assert not callback_host_is_unreachable("cb.example.test")
    assert not callback_host_is_unreachable("10.0.0.9")


def test_oob_callback_warning_never_raises_on_an_unstarted_interactsh():
    """InteractshListener.token() raises before registration; stay quiet."""
    listener = make_listener("interactsh")
    assert oob_callback_warning(listener, ["http://target.example/x"]) is None


def test_oob_callback_warning_reports_for_a_self_hosted_listener():
    listener = make_listener("self", port=8900)
    msg = oob_callback_warning(listener, ["http://target.example/x"])
    assert msg and "127.0.0.1" in msg, msg


def test_oob_callback_warning_quiet_when_targets_are_all_local():
    listener = make_listener("self", port=8900)
    assert oob_callback_warning(
        listener, ["http://127.0.0.1:1/x", "http://localhost:2/y"]) is None


def test_oob_callback_warning_tolerates_empty_targets():
    listener = make_listener("self", port=8900)
    assert oob_callback_warning(listener, []) is None
    assert oob_callback_warning(listener, None) is None
