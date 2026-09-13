# -*- coding: utf-8 -*-
"""Phase 126: second-order benchmark targets (L4_second_order).

Two contracts are locked here, both learned the hard way while writing the
case:

1. A **viewer** handler must be registered in a CTX-AWARE registry
   (MODES_CTX / POST_MODES).  The GET dispatcher resolves
   `MODES_CTX.get(mode) or POST_MODES.get(mode)` first, and only falls back
   to PAGE_MODES with an EMPTY ctx -- and a viewer without ctx["path"]
   cannot resolve VIEW_TO_INJECT, so it silently renders an empty store.
   The case then fails as a false negative that looks like "the detector
   doesn't work".  (This is how stored_view has always been registered.)

2. The two-page flow must genuinely differ between the twins: A stores
   verbatim -> B renders raw; A stores escaped -> B renders text.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark.server as srv

PAYLOAD = "<img src=x onerror=alert('tok')>"


@pytest.fixture(autouse=True)
def _clean_store():
    routes = srv.load_routes()          # also (re)builds VIEW_TO_INJECT
    srv._STORE.clear()
    yield
    srv._STORE.clear()
    assert routes is not None


def test_viewer_modes_are_ctx_aware():
    """A viewer in PAGE_MODES gets an empty ctx -> empty store -> silent FN."""
    routes = srv.load_routes()
    viewers = {"/v/st01", "/r/so2view01", "/s/so2view01"}
    seen = set()
    for path, case in routes.items():
        if path not in viewers:
            continue
        seen.add(path)
        mode = case.get("mode")
        assert mode in srv.MODES_CTX or mode in srv.POST_MODES, (
            f"{path}: viewer mode {mode!r} must live in a ctx-aware registry "
            f"(MODES_CTX/POST_MODES); PAGE_MODES is called with an empty ctx")
    assert seen == viewers, f"viewer routes missing: {viewers - seen}"


def test_second_order_view_paths_are_registered_and_distinct():
    routes = srv.load_routes()
    assert "/r/so2in01" in routes and "/r/so2view01" in routes
    assert "/s/so2in01" in routes and "/s/so2view01" in routes
    # the twins must not share a store, or one twin's data leaks into the
    # other's viewer (the safe twin would then beacon off the vuln case)
    assert srv.VIEW_TO_INJECT["/r/so2view01"] == "/r/so2in01"
    assert srv.VIEW_TO_INJECT["/s/so2view01"] == "/s/so2in01"
    assert (srv.VIEW_TO_INJECT["/r/so2view01"]
            != srv.VIEW_TO_INJECT["/s/so2view01"])


def test_vulnerable_twin_stores_raw_and_renders_raw():
    srv.m_stored_write(PAYLOAD, {"path": "/r/so2in01"})
    body = srv.m_stored_view("", {"path": "/r/so2view01"})[2]
    assert PAYLOAD in body, "B must render what A stored, verbatim"


def test_safe_twin_stores_escaped_and_renders_text():
    srv.m_stored_write_escaped(PAYLOAD, {"path": "/s/so2in01"})
    body = srv.m_stored_view("", {"path": "/s/so2view01"})[2]
    assert PAYLOAD not in body
    assert "&lt;img" in body, "escaped twin must render an entity, not a tag"


def test_twins_do_not_cross_contaminate():
    srv.m_stored_write(PAYLOAD, {"path": "/r/so2in01"})
    safe_body = srv.m_stored_view("", {"path": "/s/so2view01"})[2]
    assert PAYLOAD not in safe_body, (
        "the safe viewer must not render the vulnerable pair's payload")
