"""Tests for the Phase 44 outdated-JS-library scan (XSStrike retireJS-style).

Version extraction (anchored to the library name) and the vulnerable-range
matching are unit-tested; scan_html() is verified against realistic page
HTML including negative cases (new versions, unresolvable versions, and
version-like path prefixes that must NOT leak).
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import retire_js as rj


class TestExtractVersion:
    def test_filename_prefix(self):
        assert rj._extract_version_from_url(
            "/js/jquery-1.12.4.min.js", rj._LIBS[0]) == (1, 12, 4)

    def test_path_version(self):
        assert rj._extract_version_from_url(
            "/jquery/3.1.0/jquery.min.js", rj._LIBS[0]) == (3, 1, 0)

    def test_at_scope(self):
        assert rj._extract_version_from_url(
            "vue@2.6.14/dist/vue.min.js", rj._LIBS[3]) == (2, 6, 14)

    def test_path_prefix_must_not_leak(self):
        assert rj._extract_version_from_url(
            "/static/v2/jquery.min.js", rj._LIBS[0]) is None

    def test_sibling_lib_name_no_digits(self):
        assert rj._extract_version_from_url(
            "vue-router.js", rj._LIBS[3]) is None


class TestVersionRanges:
    def test_inside_range(self):
        assert rj._version_in_ranges((1, 12, 4), [((0,), (3, 4, 0))])

    def test_boundary_exclusive_upper(self):
        # 3.5.0 is NOT < 3.5.0 -> safe
        assert not rj._version_in_ranges(
            (3, 5, 0), [((0,), (3, 4, 0)), ((3, 4, 0), (3, 5, 0))])

    def test_below_range(self):
        assert not rj._version_in_ranges((0, 0, 1), [((1,), (2,))])

    def test_unbounded_upper(self):
        assert rj._version_in_ranges((9, 9, 9), [((10,), None)]) is False
        assert rj._version_in_ranges((11, 0), [((10,), None)])


class TestScanHtml:
    def test_old_libs_flagged(self):
        html = (
            "<script src='/static/js/jquery-1.12.4.min.js'></script>"
            "<script src='/js/vue-2.6.9.js'></script>"
            "<script src='/js/react-18.2.0.js'></script>"  # not in table
        )
        finds = rj.scan_html(html, "http://example.com/")
        names = {(f["library"], f["version"]) for f in finds}
        assert ("jQuery", "1.12.4") in names
        assert ("Vue.js", "2.6.9") in names
        assert all(f["type"] == "outdated_js_lib" for f in finds)
        assert all(f["confidence"] == "high" for f in finds)

    def test_new_versions_not_flagged(self):
        html = "<script src='/js/jquery-3.6.0.min.js'></script>"
        assert rj.scan_html(html) == []

    def test_unresolvable_version_not_flagged(self):
        html = "<script src='/js/jquery.min.js'></script>"
        assert rj.scan_html(html) == []

    def test_plugin_files_not_reported_as_core_jquery(self):
        """Regression: jquery-ui / jquery-migrate / jquery-mobile carry
        their OWN versions and are NOT core jQuery -- reporting them with
        core-jQuery CVEs is a false positive (silent-FP bug)."""
        html = (
            "<script src='/static/jquery-migrate-3.3.2.min.js'></script>"
            "<script src='/static/js/jquery-ui-1.12.1.custom.min.js'></script>"
            "<script src='/js/jquery-mobile-1.4.5.min.js'></script>"
        )
        assert rj.scan_html(html) == []

    def test_core_jquery_with_version_still_flagged(self):
        html = "<script src='/static/js/jquery-1.12.4.min.js'></script>"
        finds = rj.scan_html(html)
        assert any(f["library"] == "jQuery" for f in finds)

    def test_dedupe_same_lib(self):
        html = (
            "<script src='/a/jquery-1.8.0.js'></script>"
            "<script src='/b/jquery-1.8.0.js'></script>"
        )
        finds = rj.scan_html(html)
        assert len(finds) == 1

    def test_empty(self):
        assert rj.scan_html(None) == []
        assert rj.scan_html("") == []

    def test_script_src_extraction(self):
        html = ('<script src="/a.js"></script>'
                "<script>var x=1;</script>"
                "<script src='b.js'></script>")
        assert rj.extract_script_srcs(html) == ["/a.js", "b.js"]
