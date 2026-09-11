# -*- coding: utf-8 -*-
"""Phase 118: keep the coverage matrix honest about the manifest.

Phases 116/117/118 added cases (dangling_markup, import_map,
sanitizer_bypass, sri_bypass, graphql, trusted_types, websocket, waf)
without updating layer_coverage.py's layer->modes map, so the matrix
kept reporting those layers as uncovered while cases for them existed.

Same drift class as Phase 115 (LAYERS vs touch_layer).  Two checks close
it:
  * the matrix must not reference modes that do not exist (typos /
    stale entries);
  * every VULNERABLE case's mode must be claimed by some layer -- if a
    case exists whose mode no layer maps to, the coverage matrix is
    silently understating coverage.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.layer_coverage import COVERAGE, coverage_modes

_MANIFEST = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "benchmark", "manifest.json")


def _cases():
    with open(_MANIFEST, "r", encoding="utf-8") as f:
        return json.load(f)["cases"]


def _matches(mode, pattern):
    if pattern.endswith("*"):
        return mode.startswith(pattern[:-1])
    return mode == pattern


def _modes():
    return {c["mode"] for c in _cases() if c.get("mode")}


def test_matrix_references_only_existing_modes():
    """No typo'd / stale mode patterns in the layer->modes map."""
    modes = _modes()
    stale = sorted(
        p for p in coverage_modes()
        if not p.endswith("*") and p not in modes
        and not any(_matches(m, p) for m in modes))
    assert not stale, f"matrix references modes that do not exist: {stale}"


def test_every_vulnerable_case_mode_is_claimed_by_a_layer():
    """The drift this file was written for: a case exists, but no layer's
    mode list mentions it, so the matrix calls the layer uncovered."""
    patterns = coverage_modes()
    unclaimed = sorted({
        c["mode"] for c in _cases()
        if c.get("ground_truth") == "vulnerable" and c.get("mode")
        and not any(_matches(c["mode"], p) for p in patterns)})
    assert not unclaimed, (
        "vulnerable cases whose mode no layer claims -- the matrix "
        f"understates coverage for: {unclaimed}")


def test_coverage_map_covers_every_registered_layer():
    from xssentinel.core.coverage import LAYERS
    registered = {lid for lid, _, _ in LAYERS}
    missing = sorted(registered - set(COVERAGE))
    assert not missing, (
        f"layers registered in coverage.LAYERS but absent from the "
        f"coverage matrix: {missing}")
