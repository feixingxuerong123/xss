"""Phase 152: scan_stored_dom -- stored XSS verified by the real browser.

Pure-logic tests: a fake host (the StoredBlindMixin needs req / _add /
_bump / coverage / max_payloads / verbose), a recording requester, and a
fake DOM engine replaying analyze() results.  No network, no subprocess,
no Playwright.

Locks the contract that the Juice-Shop-shaped flow (§17/§18 of the
delivery report) depends on:
  * submits BOTH a form-encoded and a JSON body variant (SPA write
    endpoints are JSON; classic guestbooks are form),
  * passes the submission token to engine.analyze(marker=...),
  * emits a stored_dom finding only when the browser reports a hit,
  * self-view (no explicit view URL) is confidence=medium,
  * payloads without an alert() call are skipped (mark() would leave
    them token-free -- the hooks could never see them),
  * extra_fields (companion fields real write APIs demand -- password,
    csrf, captcha) ride along in BOTH encodings, payload in `param`.
"""
from __future__ import annotations

import pytest

from xssentinel.core.scanner_stored import StoredBlindMixin
from xssentinel.core import payloads as payloads_mod


HIT = [{"sink": "Element.innerHTML", "snippet": "<li>...xssv_tok...</li>"}]


class _FakeEngine:
    def __init__(self, hits):
        self._hits = hits
        self.calls = []

    def available(self):
        return True

    def analyze(self, url, marker=None):
        self.calls.append((url, marker))
        return list(self._hits)


class _FakeCoverage:
    def touch_layer(self, *a, **k):
        pass


class _RecordingReq:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, json=None,
                files=None, headers=None):
        self.calls.append({"method": method, "url": url, "data": data,
                           "json": json})
        return object()  # truthy response stand-in


class _Host(StoredBlindMixin):
    """Minimal Scanner stand-in for the mixin."""

    def __init__(self, engine):
        self.req = _RecordingReq()
        self.engine = engine
        self.findings = []
        self.verbose = False
        self.max_payloads = 5
        self.max_transforms = 3
        self.coverage = _FakeCoverage()

    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        pass

    def _resolve_dom_engine(self):
        return self.engine


def test_hit_emits_stored_dom_and_submits_form_plus_json():
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view",
                              param="comment")
    assert ok is True
    assert len(host.findings) == 1
    f = host.findings[0].data
    assert f["type"] == "stored_dom"
    assert f["severity"] == "high"
    assert f["confidence"] == "high"
    # The engine DID run a browser here, so this finding must stop filing as
    # "never checked" (`headless` used to be None on this exact path).
    assert f["evidence_class"] == "browser-executed"
    assert f["headless"]["outcome"] == "fired"
    assert f["method"] == "POST" and f["param"] == "comment"
    proof = f["proof"]
    assert proof["view_url"] == "http://t/view"
    assert proof["token"].startswith("xssv_")
    # The token submitted is the token the engine was told to expect.
    assert eng.calls and eng.calls[0][0] == "http://t/view"
    assert proof["token"] in eng.calls[0][1]
    # Both encodings were submitted with the same token-carrying variant.
    submissions = [c for c in host.req.calls if c["method"] == "POST"]
    assert len(submissions) == 2
    assert submissions[0]["data"] == {"comment": submissions[0]["data"]["comment"]}
    assert submissions[1]["json"] is not None
    assert proof["token"] in submissions[0]["data"]["comment"]
    assert proof["token"] in submissions[1]["json"]["comment"]


def test_no_browser_hit_means_no_finding():
    host = _Host(_FakeEngine([]))
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view")
    assert ok is False
    assert host.findings == []


def test_json_body_flag_narrows_the_encodings():
    host = _Host(_FakeEngine([]))
    host.scan_stored_dom("http://t/write", view_url="http://t/view",
                         json_body=True)
    posts = [c for c in host.req.calls if c["method"] == "POST"]
    assert posts and all(c["json"] is not None and c["data"] is None
                         for c in posts)


def test_unavailable_engine_is_a_clean_noop():
    class _Dead:
        def available(self):
            return False

        def analyze(self, url, marker=None):  # pragma: no cover
            raise AssertionError("analyze must not be called")

    host = _Host(_Dead())
    assert host.scan_stored_dom("http://t/write",
                                view_url="http://t/view") is False
    assert host.req.calls == []
    assert host.findings == []


def test_self_view_is_downgraded_to_medium_confidence():
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    # view_url omitted -> self-view -> medium + explicit note.
    ok = host.scan_stored_dom("http://t/write")
    assert ok is True
    assert host.findings[0].data["confidence"] == "medium"
    # Execution and persistence are separate claims: the browser DID fire the
    # marker here, so the tier says so -- and the grading must not spend that
    # fact to upgrade a confidence number that is about "renders for OTHER
    # viewers", which self-view has not shown.
    _d = host.findings[0].data
    assert _d["evidence_class"] == "browser-executed"
    assert _d["confidence"] == "medium", "grading must not raise this"
    assert _d["severity"] == "high", "severity is impact, not belief"


def test_alertless_payloads_are_skipped(monkeypatch):
    """A payload whose text never carries the token can never be seen by
    the sink hooks -- mark() leaves alert-less payloads unchanged, so the
    flow must skip them instead of burning browser passes on nothing."""

    def _fake_by_context(name):
        return [{"payload": "<script>fetch('/x')</script>"}]  # no alert()

    monkeypatch.setattr(payloads_mod, "by_context", _fake_by_context)
    host = _Host(_FakeEngine(HIT))
    ok = host.scan_stored_dom("http://t/write", view_url="http://t/view")
    assert ok is False
    assert host.findings == []
    assert all(c["method"] != "POST" for c in host.req.calls)


def test_extra_fields_ride_along_in_both_encodings():
    """Phase 152b (Juice Shop): register/profile write APIs reject a POST
    that carries only the payload field -- companion fields (password,
    securityAnswer, ...) must be merged into every submission while the
    payload still rides in ``param``."""
    eng = _FakeEngine(HIT)
    host = _Host(eng)
    extras = {"password": "Xss-T3st!", "securityAnswer": "x"}
    ok = host.scan_stored_dom("http://t/users", view_url="http://t/admin",
                              param="email", extra_fields=extras)
    assert ok is True
    posts = [c for c in host.req.calls if c["method"] == "POST"]
    assert len(posts) == 2
    for sub in posts:
        body = sub["json"] if sub["json"] is not None else sub["data"]
        assert body["password"] == "Xss-T3st!"
        assert body["securityAnswer"] == "x"
        assert body["email"].startswith("<")  # payload field intact
    # the payload field must be the only marker-carrying field
    assert eng.calls and eng.calls[0][1] in posts[1]["json"]["email"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
