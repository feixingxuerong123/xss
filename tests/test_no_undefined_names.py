"""Static gate: no module-level name may be referenced without being imported.

Bug family this locks (found 2026-09-14):

* ``core/scanner_layers.py`` had eleven methods referencing ``pre_mod``,
  ``wafmod``, ``rp_mod``, ``pocmod``, ``cvss_mod``, ``replay_mod`` and
  ``SEVERITY_ORDER`` -- none of which are defined in that module.  They
  were harmless only because ``Scanner`` happened to shadow every one of
  them; activating any of them would have raised ``NameError``.
* ``cli_runner.py`` referenced ``sys`` (twice) and ``load_wordlist``
  without importing either -- live ``NameError`` paths: passing
  ``--param-wordlist``, or combining ``--async`` with any sync-only flag
  (the code that printed "this flag is ignored" crashed instead).

Python resolves a function's globals against the module where the function
was *defined*, so a copy of a method moved into another module silently
loses its imports.  Nothing in the test suite catches that until the code
path is executed, which is exactly how both of these survived.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(ROOT, "xssentinel")

try:
    import pyflakes  # noqa: F401
    _HAS_PYFLAKES = True
except Exception:
    _HAS_PYFLAKES = False


@pytest.mark.skipif(not _HAS_PYFLAKES, reason="pyflakes not installed")
def test_no_undefined_names_in_package():
    """pyflakes must report zero `undefined name` findings."""
    proc = subprocess.run(
        [sys.executable, "-m", "pyflakes", PACKAGE],
        capture_output=True, text=True, cwd=ROOT,
    )
    hits = [ln for ln in (proc.stdout or "").splitlines()
            if "undefined name" in ln]
    assert not hits, (
        "names referenced but never imported (these raise NameError when the "
        "code path is finally executed):\n  " + "\n  ".join(hits))


def test_no_duplicate_future_imports():
    """`from __future__ import annotations` twice is a merge artefact and
    hides the fact that the second copy was appended rather than checked."""
    offenders = []
    for dirpath, _dirnames, filenames in os.walk(PACKAGE):
        if "__pycache__" in dirpath:
            continue
        for name in filenames:
            if not name.endswith(".py") or ".bak" in name:
                continue
            path = os.path.join(dirpath, name)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except Exception:
                continue
            seen = [n.lineno for n in tree.body
                    if isinstance(n, ast.ImportFrom)
                    and n.module == "__future__"]
            if len(seen) > 1:
                offenders.append(f"{os.path.relpath(path, ROOT)}{seen}")
    assert not offenders, "duplicate __future__ imports: " + ", ".join(offenders)
