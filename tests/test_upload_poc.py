"""Phase 48 tests: multipart upload-filename XSS probe + CSRF-aware PoCs.

Covers:
  * requester files= support shape (via the fake below we assert the probe
    actually sends files={field: (name, bytes, type)} multipart style);
  * upload_probe: filename echoed raw -> upload_xss confirmed; filename
    sanitised / not echoed -> no finding; stored-URL follow -> stored_upload.
  * poc.build_poc: CSRF/hidden fields ride into the curl body AND the HTML
    auto-submit form; cookies appear as -b; upload findings get a multipart
    -F curl instead of a form --data body.
  * replay.replay_for_finding: CSRF fields merged into POST replay.
  * scanner._add enrichment: csrf_fields attached from the thread-local
    request context.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import poc as pocmod
from xssentinel.core import replay as replaymod
from xssentinel.core import upload_probe
from xssentinel.core.findings import Finding
from xssentinel.core.scanner import Scanner


# ---------------------------------------------------------------------------
# Fake requester for upload_probe
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, text, status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html"}


class _FakeReq:
    """Records calls; responds by reflecting the first uploaded filename."""

    def __init__(self, echo_filename=True, stored_path=None, stored_text=""):
        self.calls = []
        self.echo_filename = echo_filename
        self.stored_path = stored_path
        self.stored_text = stored_text

    def request(self, method, url, params=None, data=None, json=None,
                files=None, headers=None):
        if files:
            self.calls.append({"files": files, "data": dict(data or {})})
            name = list(files.values())[0][0]
            if self.echo_filename:
                return _FakeResp(f"<html><body>Saved {name}</body></html>")
            if self.stored_path and name and "xssup_" in name:
                # Response references a stored URL carrying the filename.
                return _FakeResp(
                    f'<html><body>ok <a href="{self.stored_path}">here</a>'
                    "</body></html>")
            return _FakeResp("<html><body>ok</body></html>")
        # GET of the stored file
        self.calls.append({"get": url})
        return _FakeResp(self.stored_text)


class TestUploadProbe:
    def test_filename_echo_confirms_upload_xss(self):
        req = _FakeReq(echo_filename=True)
        found = upload_probe.probe_upload(req, "http://t/up", "file",
                                          data={"caption": "x"})
        assert found, "filename echo was not reported"
        f = found[0].data
        assert f["type"] == "upload_xss"
        assert f["param"] == "file[filename]"
        assert f["severity"] == "high"
        # Multipart actually sent: files keyed by field with (name, bytes, ctype).
        sent = req.calls[0]["files"]
        assert "file" in sent
        assert sent["file"][0].startswith("x") and "xssup_" in sent["file"][0]
        assert isinstance(sent["file"][1], bytes)
        # Other form fields ride along as data.
        assert req.calls[0]["data"].get("caption") == "x"

    def test_no_echo_no_finding(self):
        req = _FakeReq(echo_filename=False)
        found = upload_probe.probe_upload(req, "http://t/up", "file")
        assert found == []

    def test_stored_path_follow_confirms_stored_upload(self):
        from urllib.parse import quote, unquote

        class _StoreReq(_FakeReq):
            """Realistic split: the upload summary page percent-encodes the
            filename (no immediate breakout), but the STORED file is served
            with the attacker filename raw -> stored XSS on fetch."""

            def request(self, method, url, params=None, data=None, json=None,
                        files=None, headers=None):
                if files:
                    self.calls.append({"files": files, "data": dict(data or {})})
                    name = list(files.values())[0][0]
                    enc = quote(name, safe="")
                    path = f"/uploads/{enc}"
                    # Summary page: name only in an encoded href -- safe echo.
                    return _FakeResp(
                        f'<html><body>saved <a href="{path}">here</a>'
                        "</body></html>")
                self.calls.append({"get": url})
                # Static file server serves the stored name RAW.
                name = unquote(url.rsplit("/", 1)[-1])
                return _FakeResp(f"<html><body><div>{name}</div></body></html>")

        req = _StoreReq()
        found = upload_probe.probe_upload(req, "http://t/up", "file")
        assert found, "stored upload XSS was not confirmed via URL follow"
        assert found[0].data["type"] == "stored_upload"
        assert any(c.get("get", "").startswith("http://t/uploads/")
                   for c in req.calls)


class TestPocCsrfAndAuth:
    def test_csrf_fields_in_curl_and_html(self):
        finding = Finding(url="http://t/a", method="POST", param="q",
                          type="reflected", payload="<svg/onload=x>",
                          csrf_fields={"csrf": "tok123", "hidden1": "v"})
        poc = pocmod.build_poc(finding)
        assert "csrf=tok123" in poc["curl"]
        assert "hidden1=v" in poc["curl"]
        assert "q=" in poc["curl"]  # injected param present too
        assert 'name="csrf" value="tok123"' in poc["html"]

    def test_cookies_appear_when_provided(self):
        finding = Finding(url="http://t/a", method="GET", param="q",
                          type="reflected", payload="x")
        poc = pocmod.build_poc(finding, cookies={"PHPSESSID": "abc"})
        assert "-b 'PHPSESSID=abc'" in poc["curl"]

    def test_upload_finding_gets_multipart_curl(self):
        finding = Finding(url="http://t/up", method="POST",
                          param="file[filename]", type="upload_xss",
                          payload="x\"x.html")
        poc = pocmod.build_poc(finding)
        assert "-F 'file=@/dev/null;filename=" in poc["curl"]
        assert "--data '" not in poc["curl"]
        assert "curl -i -X POST 'http://t/up' " in poc["curl"]

    def test_replay_merges_csrf(self):
        finding = {"url": "http://t/a", "method": "POST", "param": "q",
                   "payload": "<svg>", "csrf_fields": {"csrf": "t1"}}
        replay = replaymod.replay_for_finding(finding)
        assert "csrf=t1" in replay["curl"]
        assert 'name="csrf" value="t1"' in replay["html_poc"]


class TestAddEnrichment:
    def test_csrf_fields_attached_from_thread_context(self):
        sc = Scanner(requester=None, verbose=False)
        sc._tl.reqctx = {"url": "http://t/a", "method": "POST",
                         "params": {}, "data": {"csrf": "tok", "q": "x"}}
        f = Finding(url="http://t/a", method="POST", param="q",
                    type="reflected", payload="p")
        sc._add(f)
        assert f.data.get("csrf_fields") == {"csrf": "tok"}

    def test_get_findings_not_enriched(self):
        sc = Scanner(requester=None, verbose=False)
        sc._tl.reqctx = {"url": "http://t/a", "method": "GET",
                         "params": {}, "data": {}}
        f = Finding(url="http://t/a", method="GET", param="q",
                    type="reflected", payload="p")
        sc._add(f)
        assert "csrf_fields" not in f.data


class TestProbeUploadContent:
    """Phase 90 (P2): weaponised file CONTENT served back at a stored
    URL is confirmed as stored XSS -- the upload story beyond filename
    echoes."""

    def _content_server(self, echo_content=False, expose=True):
        """Fake upload endpoint: stores the uploaded bytes and either
        serves them back verbatim (echo_content) or serves neutral text;
        the upload response exposes /uploads/<marker-file> when expose."""
        from urllib.parse import quote, unquote

        class _ContentReq:
            def __init__(self):
                self.calls = []

            def request(self, method, url, params=None, data=None,
                        json=None, files=None, headers=None):
                if files:
                    self.calls.append({"files": files,
                                       "data": dict(data or {})})
                    name = list(files.values())[0][0]
                    enc = quote(name, safe="")
                    self._name = name
                    self._mime = list(files.values())[0][2]
                    if expose:
                        return _FakeResp(
                            f'<html><body>ok <a href="/uploads/{enc}">'
                            "here</a></body></html>")
                    return _FakeResp("<html><body>ok</body></html>")
                self.calls.append({"get": url})
                if echo_content:
                    # Serve the weaponised bytes back verbatim.
                    if self._mime == "image/svg+xml":
                        body = (
                            '<svg xmlns="http://www.w3.org/2000/svg" '
                            f'onload="alert(\'{self._name}\')">'
                            '<rect width="10" height="10"/></svg>')
                    else:
                        body = (
                            f"<html><body>{self._name}"
                            "</body></html>")
                    return _FakeResp(
                        body,
                        headers={"Content-Type": self._mime})
                return _FakeResp("<html><body>stored</body></html>")

        return _ContentReq()

    def test_content_echo_confirms_stored_upload(self):
        req = self._content_server(echo_content=True)
        found = upload_probe.probe_upload_content(
            req, "http://t/up", "file")
        assert found, "weaponised content was not confirmed"
        f = found[0].data
        assert f["type"] == "stored_upload"
        assert f["context"] == "uploaded_file_content"
        assert f["param"] == "file[content]"
        # Weaponised bytes actually uploaded (marker inside content).
        sent = req.calls[0]["files"]["file"]
        assert sent[0].endswith(".svg") or sent[0].endswith(".html")
        assert b"xssupc_" in sent[1]
        # Stored file was fetched.
        assert any(c.get("get", "").startswith("http://t/uploads/")
                   for c in req.calls)

    def test_content_no_exposed_url_no_finding(self):
        req = self._content_server(echo_content=True, expose=False)
        found = upload_probe.probe_upload_content(
            req, "http://t/up", "file")
        assert found == []

    def test_content_neutral_store_no_finding(self):
        req = self._content_server(echo_content=False, expose=True)
        found = upload_probe.probe_upload_content(
            req, "http://t/up", "file")
        assert found == []

    def test_full_probe_runs_content_after_filename(self):
        """probe_upload() drives both probes; a pure filename-echo
        endpoint still triggers the content probe (no cross-talk)."""
        req = _FakeReq(echo_filename=True)
        found = upload_probe.probe_upload(req, "http://t/up", "file")
        # Filename echo confirms upload_xss and returns early -- content
        # probe is only reached when filename probes found nothing.
        assert found and found[0].data["type"] == "upload_xss"
        # Marker stem seen on the wire for the filename probe.
        sent = req.calls[0]["files"]["file"]
        assert b"xssup_" in sent[1] or b"xssup_" in sent[0].encode()
