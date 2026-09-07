"""BeautifulSoup parser selection helper.

Centralized so every module that builds a ``BeautifulSoup`` tree uses the
same parser backend: ``lxml`` when available (faster and more forgiving on
malformed HTML), falling back to the stdlib ``html.parser`` otherwise.
"""
from __future__ import annotations


def bs_parser() -> str:
    """Return the best available BeautifulSoup parser name.

    The result is cached after the first call.
    """
    cached = getattr(bs_parser, "_cached", None)
    if cached is not None:
        return cached
    try:
        import lxml  # noqa: F401
        bs_parser._cached = "lxml"
    except ImportError:
        bs_parser._cached = "html.parser"
    return bs_parser._cached
