# -*- coding: utf-8 -*-
"""Phase 115: every layer_id used in touch_layer() must be registered.

The Phase 111 matrix said '28 layers, 14 uncovered' and both numbers
were wrong: eleven DISPATCHED layers (graphql, websocket, trusted_types,
import_map, sanitizer_bypass, sri_bypass, css_injection, dangling_markup,
svg_xss, csp_nonce, cookie_tossing) used touch_layer() with layer_ids
that were never put into coverage.LAYERS.  record_layer()'s
unknown-layer fallback kept the DATA alive but the stats, the summary
and the matrix never saw them -- new layers silently vanished from every
report the moment someone forgot to register them.

This test is the missing reconciliation: statically collect every
layer_id passed to touch_layer() across the engine and assert each one
is registered in coverage.LAYERS.
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.coverage import LAYERS

_CORE = Path(__file__).resolve().parent.parent / "xssentinel" / "core"

# touch_layer(url, "Lx_yyy", ...) -- layer_id is the first quoted argument
# after the url; calls may span lines, hence DOTALL.
_TOUCH_RE = re.compile(
    r'touch_layer\(\s*[^,]+,\s*"([Ll][0-9][0-9a-z_]*|[a-z_]+)"', re.S)


def _used_layer_ids():
    ids = set()
    for path in _CORE.rglob("*.py"):
        src = path.read_text(encoding="utf-8", errors="replace")
        for m in _TOUCH_RE.finditer(src):
            ids.add(m.group(1))
    return ids


def test_every_touch_layer_id_is_registered():
    registered = {lid for lid, _, _ in LAYERS}
    used = _used_layer_ids()
    missing = sorted(used - registered)
    assert not missing, (
        f"layer_ids used by touch_layer() but missing from "
        f"coverage.LAYERS (they vanish from every report): {missing}")


def test_registered_ids_look_like_layer_ids():
    for lid, _, _ in LAYERS:
        assert re.match(r"^L\d+", lid), (
            f"LAYERS entry {lid!r} does not look like a layer_id (L<digit>...)")
