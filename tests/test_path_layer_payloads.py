# -*- coding: utf-8 -*-
"""Phase 109: the path-injection layer must use PATH-SAFE payloads.

Found by the first benchmark cases ever written for this vector family
(before that the layer had zero coverage): _scan_path_xss hard-coded
``<svg/onload=alert('token')>`` and concatenated it into the path RAW.
That payload contains a SLASH, so it arrived split into two segments and
no target that echoes a single segment could reflect it -- the layer was
effectively dead against real targets.

path_xss.py already shipped the right tools (PATH_PAYLOADS without any
'/', build_test_url() encoding with safe=""), they just were not used.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import path_xss as px


def test_no_declared_payload_survives_as_a_raw_slash_in_the_url():
    """The invariant that matters is on the BUILT URL.

    Some declared payloads legitimately contain '/' (``</script>``,
    ``';alert(1);//``); build_test_url() percent-encodes with safe=""
    so none of them may reach the wire as a raw segment separator.
    """
    for p in px.path_payloads():
        if p == "xssentinel":
            continue
        url = px.build_test_url("http://h.example/r/x?q=1", "x", p)
        if "/" in p:
            assert "%2F" in url, (
                f"a payload slash must arrive encoded, not raw: "
                f"{p!r} -> {url!r}")
        # whatever the payload, the route itself must still be intact
        assert url.startswith("http://h.example/r/"), url


def test_build_test_url_encodes_slash_and_markup():
    url = px.build_test_url("http://h.example/r/x?q=1", "x",
                            "<svg/onload=alert('tok')>")
    assert "%2F" in url, "slash must be percent-encoded, not left raw"
    assert "<" not in url and ">" not in url
    assert "onload" in url  # the payload is there, just encoded


def test_build_test_url_replaces_the_segment_not_appends_blindly():
    url = px.build_test_url("http://h.example/r/pth01?q=1", "pth01", "PAY")
    assert url.startswith("http://h.example/r/"), url
    assert "PAY" in url
    assert "?q=1" in url, "original query must survive"


def test_layer_uses_module_payloads_not_an_inline_one():
    """Guard the wiring, not just the helpers.

    The bug was that transport_layers built its own payload; assert the
    layer calls the module's payload list / URL builder.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(here, "xssentinel", "core", "layers",
                            "transport_layers.py"), encoding="utf-8").read()
    fn = src.split("def _scan_path_xss", 1)[1].split("\ndef ", 1)[0]
    assert "path_mod.path_payloads()" in fn, (
        "path layer must use the module's path-safe payload set")
    assert "path_mod.build_test_url(" in fn, (
        "path layer must build its URL with build_test_url (safe=\"\")")
    # only inspect CODE lines -- the docstring above deliberately quotes
    # the old broken payload to explain the bug
    code = "\n".join(ln for ln in fn.splitlines()
                     if not ln.strip().startswith("#"))
    code = code.split('"""')[0] if '"""' in code else code
    assert "new_path = parsed.path.rstrip" not in code, (
        "the raw path concatenation must be gone")
    assert 'payload = f"<svg/onload' not in code, (
        "the slash-bearing inline payload must be gone")
