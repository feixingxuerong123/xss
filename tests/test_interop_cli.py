"""Phase 49: report-format dispatch through the CLI seam (_write_report).

The exporters live in core.report (covered in test_report.py); this file
proves the format strings a user passes on the command line reach the right
exporter and produce the right artifact shape (file for burp, directory of
templates for nuclei), including extension fallbacks.
"""
from __future__ import annotations
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.cli_runner import _write_report


def _stub_scanner(findings):
    class _S:
        pass

    s = _S()
    s.findings = findings
    s.requests_made = 7
    s.waf_name = None
    s.coverage = None
    return s


def _f(ftype="reflected", sev="high", param="q"):
    return {
        "type": ftype, "severity": sev, "param": param,
        "context": "html_element", "payload": "<script>alert(1)</script>",
        "url": "http://t/s?q=x", "method": "GET",
        "detail": "token confirmed", "confidence": "high",
        "transform": ["raw"],
        "poc": {"curl": "curl 'http://t/s?q=...'", "url": "http://t/s?q=x"},
    }


class TestWriteReportBurp:
    def test_writes_xml_and_appends_extension(self, tmp_path):
        out = str(tmp_path / "out")          # no extension given
        ret = _write_report(_stub_scanner([_f()]), "http://t/s", out, "burp")
        assert ret == out + ".xml"
        root = ET.fromstring(open(out + ".xml", encoding="utf-8").read())
        assert root.tag == "issues"
        assert len(root.findall("issue")) == 1

    def test_respects_explicit_xml_extension(self, tmp_path):
        out = str(tmp_path / "r.xml")
        _write_report(_stub_scanner([_f()]), "http://t/s", out, "burp")
        assert os.path.isfile(out)


class TestWriteReportNuclei:
    def test_writes_template_dir_without_extension(self, tmp_path):
        out = str(tmp_path / "templates")    # plain dir path
        ret = _write_report(_stub_scanner([_f(), _f(ftype="stored")]),
                            "http://t/s", out, "nuclei")
        assert ret == out                      # returns the directory
        assert os.path.isdir(out)
        files = sorted(os.listdir(out))
        assert len(files) == 2 and all(f.endswith(".yaml") for f in files)

    def test_strips_nuclei_suffix_to_dir_name(self, tmp_path):
        out = str(tmp_path / "scan.nuclei")   # CLI-style artifact name
        ret = _write_report(_stub_scanner([_f()]), "http://t/s", out, "nuclei")
        assert ret == out[:-len(".nuclei")]   # dir, not a file named *.nuclei
        assert os.path.isdir(out[:-len(".nuclei")])
        assert not os.path.exists(out)

    def test_empty_findings_produce_empty_dir(self, tmp_path):
        out = str(tmp_path / "none")
        ret = _write_report(_stub_scanner([]), "http://t/s", out, "nuclei")
        assert ret == out and os.listdir(out) == []
