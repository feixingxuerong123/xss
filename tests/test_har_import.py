"""Phase 88 (P1): HAR import tests.

Covers xssentinel.core.har_import:
  * flattening a HAR log.entries into scan targets
  * dedup (same method+url+body)
  * filtering (aborted requests / non-HTTP / non-2xx-5xx responses)
  * POST form body -> urlencoded data; JSON body preserved raw
  * cookie / header carry-over
  * error paths (missing file, bad JSON, no entries)
"""
import json

import pytest

from xssentinel.core.har_import import (
    HarImportError,
    har_to_scan_targets,
    target_to_scan_args,
)


def _entry(method="GET", url="http://h/a?q=1", status=200, body="",
           content_type="application/x-www-form-urlencoded",
           cookies=None, headers=None):
    req = {"method": method, "url": url}
    if body:
        req["postData"] = {"mimeType": content_type, "text": body}
    if content_type:
        req.setdefault("headers", []).append(
            {"name": "Content-Type", "value": content_type})
    hdrs = [{"name": "Content-Type", "value": content_type}] if content_type else []
    hdrs += (headers or [])
    req["headers"] = hdrs
    req["cookies"] = [{"name": k, "value": v} for k, v in (cookies or {}).items()]
    return {"request": req,
            "response": {"status": status, "statusText": "ok"}}


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def _write_har(tmp_path, entries, name="cap.har"):
    p = tmp_path / name
    p.write_text(json.dumps(_har(entries)), encoding="utf-8")
    return str(p)


class TestHarFlatten:
    def test_basic_get_entries(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url="http://h/a?q=1"),
            _entry(url="http://h/b"),
        ])
        tgts = har_to_scan_targets(p)
        assert len(tgts) == 2
        assert tgts[0]["method"] == "GET"
        assert tgts[0]["url"] == "http://h/a?q=1"

    def test_dedup_exact(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url="http://h/a?q=1"),
            _entry(url="http://h/a?q=1"),
            _entry(url="http://h/a?q=2"),  # different query -> kept
        ])
        tgts = har_to_scan_targets(p)
        assert [t["url"] for t in tgts] == ["http://h/a?q=1",
                                            "http://h/a?q=2"]

    def test_filters_failed_and_non_http(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url="http://h/ok", status=200),
            _entry(url="http://h/err", status=0),       # aborted
            _entry(url="http://h/nohttp", status=304),  # keep
        ])
        tgts = har_to_scan_targets(p)
        assert [t["url"] for t in tgts] == ["http://h/ok", "http://h/nohttp"]

    def test_post_form_body_encoded(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(method="POST", url="http://h/login",
                   body="user=a&pass=b%26c",
                   content_type="application/x-www-form-urlencoded"),
        ])
        tgts = har_to_scan_targets(p)
        assert tgts[0]["method"] == "POST"
        assert tgts[0]["data"] == "user=a&pass=b%26c"

    def test_post_json_body_raw(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(method="POST", url="http://h/api",
                   body='{"name":"x"}',
                   content_type="application/json"),
        ])
        tgts = har_to_scan_targets(p)
        assert tgts[0]["data"] == '{"name":"x"}'
        assert tgts[0]["content_type"] == "application/json"

    def test_cookies_and_headers_carried(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url="http://h/a", cookies={"sid": "abc123"},
                   headers=[{"name": "X-Api-Key", "value": "k9"}]),
        ])
        tgts = har_to_scan_targets(p)
        assert tgts[0]["cookies"] == ["sid=abc123"]
        assert any("X-Api-Key: k9" in h for h in tgts[0]["headers"])

    def test_skips_host_cookie_transport_headers(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url="http://h/a",
                   headers=[{"name": "Host", "value": "h"},
                            {"name": "Cookie", "value": "x=1"},
                            {"name": "Accept-Encoding", "value": "gzip"},
                            {"name": "X-Real", "value": "kept"}]),
        ])
        tgts = har_to_scan_targets(p)
        hs = tgts[0]["headers"]
        assert all("Host:" not in h and "Cookie:" not in h
                   and "Accept-Encoding" not in h for h in hs)
        assert any("X-Real: kept" in h for h in hs)

    def test_max_entries_cap(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(url=f"http://h/{i}") for i in range(10)
        ])
        tgts = har_to_scan_targets(p, max_entries=3)
        assert len(tgts) == 3

    def test_target_to_scan_args(self, tmp_path):
        p = _write_har(tmp_path, [
            _entry(method="POST", url="http://h/x?keep=1",
                   body="a=1", cookies={"sid": "s"},
                   headers=[{"name": "X-K", "value": "v"}]),
        ])
        tgt = har_to_scan_targets(p)[0]
        args = target_to_scan_args(tgt)
        assert args["url"] == "http://h/x?keep=1"
        assert args["method"] == "POST"
        assert args["data"] == "a=1"
        assert args["cookies"] == "sid=s"
        assert "X-K: v" in args["headers"]


class TestHarErrors:
    def test_missing_file(self):
        with pytest.raises(HarImportError):
            har_to_scan_targets("Z:/no/har.json")

    def test_bad_json(self, tmp_path):
        p = tmp_path / "bad.har"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(HarImportError):
            har_to_scan_targets(str(p))

    def test_no_entries(self, tmp_path):
        p = tmp_path / "empty.har"
        p.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
        with pytest.raises(HarImportError):
            har_to_scan_targets(str(p))

    def test_all_filtered(self, tmp_path):
        p = _write_har(tmp_path, [_entry(url="http://h/x", status=0)])
        with pytest.raises(HarImportError):
            har_to_scan_targets(str(p))
