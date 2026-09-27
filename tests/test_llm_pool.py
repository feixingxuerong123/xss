"""Phase 176: LLM failover pool tests.

Everything here runs against a *local* OpenAI-compatible mock server over real
HTTP -- no monkeypatching of ``requests``.  That matters: the behaviours under
test (status-code classification, body-sniffing for ambiguous 403s, empty-200
bodies, per-candidate vs per-key cooldown scope, on-disk cooldown persistence)
all live in the HTTP boundary, so mocking the transport would test nothing.

No test in this file touches the network or a real provider.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xssentinel.core.llm_pool import (
    Candidate,
    LLMConfigError,
    LLMPool,
    LLMPoolExhausted,
    _classify,
    _extract_text,
    _normalize_endpoint,
    mask_key,
)


# ---------------------------------------------------------------------------
# Local mock provider
# ---------------------------------------------------------------------------

def _ok(text="hello"):
    return (200, {"choices": [{"message": {"role": "assistant",
                                           "content": text}}]})


def _empty():
    return (200, {"choices": [{"message": {"role": "assistant", "content": ""}}]})


def _rate_limit(model="m", limit=8):
    return (429, {"detail": {"error": {
        "message": f"Model '{model}' is at its concurrency limit ({limit}); "
                   f"please retry later"}}})


def _blocked_account():
    return (403, {"error": {"message": "Inference is blocked on this account. "
                                       "Please contact support@openrouter.ai.",
                            "code": 403}})


def _not_in_plan():
    return (403, {"error": {"message": "model is not available in the current "
                                       "token plan",
                            "code": "permission_denied_error"}})


def _gone(model="z-ai/glm-5.2"):
    return (410, {"detail": f"The model '{model}' has reached its end of life"})


def _no_credits():
    return (402, {"error": {"message": "Insufficient credits. This account "
                                       "never purchased credits."}})


class MockLLM:
    """Scripted OpenAI-compatible endpoint.

    ``script`` maps a model name to a list of ``(status, payload)``; the Nth
    call for that model gets the Nth entry (the last entry repeats).  A model
    absent from the script answers 200 "ok".
    """

    def __init__(self, script: dict[str, list] | None = None):
        self.script = script or {}
        self.calls: list[dict] = []
        self._counts: dict[str, int] = {}
        self._server = None
        self._thread = None
        self.port = None

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            # HTTP/1.0 => one connection per request.  This host's loopback is
            # intermittently killed by local security software, and keep-alive
            # makes that worse: a pooled connection survives into the next
            # test, and when the previous server instance is shut down the
            # reuse lands on a dead socket (WinError 10054).  A new connection
            # per request removes the stale-socket class of flake entirely.
            protocol_version = "HTTP/1.0"

            def do_POST(self):
                try:
                    self._respond()
                except (ConnectionResetError, ConnectionAbortedError,
                        BrokenPipeError):
                    # The client went away mid-write; nothing to do but let the
                    # handler finish instead of spraying a traceback.
                    pass

            def _respond(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                try:
                    req = json.loads(raw or b"{}")
                except ValueError:
                    req = {}
                model = req.get("model")
                outer.calls.append({
                    "model": model,
                    "auth": self.headers.get("Authorization", ""),
                    "path": self.path,
                    "body": req,
                })
                i = outer._counts.get(model, 0)
                outer._counts[model] = i + 1
                seq = outer.script.get(model) or [_ok()]
                status, payload = seq[min(i, len(seq) - 1)]
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/v1"


@pytest.fixture
def mock_llm():
    m = MockLLM().start()
    yield m
    m.stop()


def _cfg(mock: MockLLM, providers=None, **over) -> dict:
    """Pool config pointing every provider at the local mock."""
    cfg = {
        "version": 1,
        "timeout": 10,
        "max_attempts": 12,
        "cooldown": {"rate_limit": 0.2, "auth_error": 0.2, "server_error": 0.2,
                     "timeout": 0.2, "model_not_found": 0.2,
                     "empty_response": 0.2, "backoff_factor": 1, "max": 1},
        "generation": {"max_tokens": 32, "temperature": 0.0},
        "providers": providers if providers is not None else [
            {"id": "p1", "base_url": mock.base_url, "keys": ["key-aaaa-1111"],
             "models": ["m1"]},
        ],
    }
    cfg.update(over)
    return cfg


def _pool(tmp_path, mock, providers=None, **over) -> LLMPool:
    return LLMPool(_cfg(mock, providers, **over), source=str(tmp_path / "pool.json"),
                   state_path=str(tmp_path / "state.json"))


MSG = [{"role": "user", "content": "hi"}]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_normalize_endpoint_accepts_base_and_full_path():
    assert _normalize_endpoint("https://x/v1") == "https://x/v1/chat/completions"
    assert (_normalize_endpoint("https://x/v1/chat/completions")
            == "https://x/v1/chat/completions")
    assert _normalize_endpoint("https://x/v1/") == "https://x/v1/chat/completions"
    with pytest.raises(LLMConfigError):
        _normalize_endpoint("   ")


@pytest.mark.parametrize("status,body,expect", [
    (429, "", "rate_limit"),
    (429, "concurrency limit (8)", "rate_limit"),
    (401, "", "auth_error"),
    (402, "never purchased credits", "auth_error"),
    (403, "Inference is blocked on this account", "auth_error"),
    (403, "model is not available in the current token plan", "model_error"),
    (404, '{"error":{"message":"model_not_found"}}', "model_error"),
    (410, "has reached its end of life", "model_error"),
    (500, "", "server_error"),
    (503, "", "server_error"),
    (408, "", "server_error"),
    (400, "malformed request", "bad_request"),
])
def test_classify_maps_live_failure_shapes(status, body, expect):
    """The exact shapes recorded during live probing must land in the right
    bucket -- notably the two opposite meanings of 403."""
    assert _classify(status, body) == expect


def test_classify_timeout_and_network():
    import requests
    assert _classify(None, "", requests.exceptions.ConnectTimeout()) == "timeout"
    assert _classify(None, "", requests.exceptions.ConnectionError()) == "network_error"


def test_extract_text_tolerates_broken_shapes():
    assert _extract_text({"choices": [{"message": {"content": "x"}}]}) == "x"
    assert _extract_text({"choices": []}) == ""
    assert _extract_text({"choices": [None]}) == ""
    assert _extract_text({}) == ""
    # reasoning models: answer parked in reasoning_content
    assert _extract_text({"choices": [{"message": {"content": "",
                                                   "reasoning_content": "r"}}]}) == "r"


def test_mask_key_never_leaks_the_key():
    # Synthetic fixture only: this test used to carry a REAL production
    # key's shape, which is exactly how keys leak into test files.
    k = "sk-synthetic1234567890abcdef"
    m = mask_key(k)
    assert k not in m
    assert m == "sk-syn***cdef"
    assert mask_key("short") == "***"
    assert mask_key("") == "***"


# ---------------------------------------------------------------------------
# Candidate expansion
# ---------------------------------------------------------------------------

def test_candidates_expand_model_outer_key_inner(tmp_path, mock_llm):
    """Keys are quota redundancy for the same model list, so the preferred
    model is tried across every key before a lesser model is used."""
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "a", "base_url": mock_llm.base_url,
         "keys": ["k1-aaaaaaaa", "k2-bbbbbbbb"], "models": ["m1", "m2"]},
        {"id": "b", "base_url": mock_llm.base_url,
         "keys": ["k3-cccccccc"], "models": ["m3"]},
    ])
    got = [(c.provider_id, c.model, c.key_index) for c in pool.candidates]
    assert got == [("a", "m1", 0), ("a", "m1", 1),
                   ("a", "m2", 0), ("a", "m2", 1),
                   ("b", "m3", 0)]
    assert len(pool.candidates) == 5


def test_disabled_provider_is_excluded(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "off", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"], "enabled": False},
        {"id": "on", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    assert [c.provider_id for c in pool.candidates] == ["on"]


def test_no_usable_candidate_raises_config_error(tmp_path, mock_llm):
    with pytest.raises(LLMConfigError):
        _pool(tmp_path, mock_llm, providers=[
            {"id": "x", "base_url": mock_llm.base_url, "keys": [],
             "models": ["m1"]}])


def test_env_key_override(tmp_path, mock_llm, monkeypatch):
    monkeypatch.setenv("XSSENTINEL_LLM_KEY_P1", "envkey-99999999")
    pool = _pool(tmp_path, mock_llm)
    assert pool.candidates[0].key == "envkey-99999999"


def test_model_filter_limits_candidates(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "a", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]}])
    assert [c.model for c in pool.available(models=["m2"])] == ["m2"]
    assert [c.model for c in pool.available(models=["nope"])] == []


# ---------------------------------------------------------------------------
# Failover -- the core requirement
# ---------------------------------------------------------------------------

def test_first_candidate_wins_and_only_one_call_is_made(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm)
    res = pool.complete(MSG)
    assert res.text == "hello"
    assert res.failovers == 0
    assert len(mock_llm.calls) == 1
    assert "first try" in res.routing_note()


def test_429_fails_over_to_the_next_candidate(tmp_path, mock_llm):
    """The headline requirement: a rate-limited provider must not stop the
    report -- the pool moves to the next one."""
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("second")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m1"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "second"
    assert res.candidate.provider_id == "p2"
    assert res.failovers == 1
    assert res.attempts[0].kind == "rate_limit"
    assert res.attempts[0].status == 429
    assert res.attempts[1].ok


def test_rate_limit_cooldown_is_candidate_scoped(tmp_path, mock_llm):
    """AMD's live 429 is per-MODEL ("Model 'GLM-5.3-Flash' is at its
    concurrency limit").  A 429 on one model must not take out the other
    models behind the same key."""
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]},
    ])
    res = pool.complete(MSG)
    assert res.candidate.model == "m2"      # m2 went first while m1 cools
    cooled = [c.model for c in pool.cooling()]
    assert cooled == ["m1"]
    assert "m2" in [c.model for c in pool.available()]


def test_account_block_cooldown_is_key_scoped(tmp_path, mock_llm):
    """A 403 'blocked on this account' means every model behind that key is
    unusable, so the whole key cools (not just the one model tried) -- and the
    sibling is skipped rather than given its own doomed call."""
    mock_llm.script = {"m1": [_blocked_account()],
                       "m2": [_blocked_account()]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]},
    ])
    with pytest.raises(LLMPoolExhausted) as ei:
        pool.complete(MSG)
    assert [c.model for c in pool.cooling()] == ["m1", "m2"]
    # Only m1 was actually contacted: m2 was already cooled via the shared key.
    assert len(mock_llm.calls) == 1
    assert len(ei.value.attempts) == 1


def test_sibling_of_a_key_scoped_failure_is_not_contacted(tmp_path, mock_llm):
    """Live regression: two AMD candidates timed out back to back (~90s of a
    116s run).  Once the key is cooling, its other candidates must be skipped
    in the same pass, so the pool reaches a different provider immediately."""
    mock_llm.script = {"m1": [(500, {"error": {"message": "upstream boom"}})],
                       "m2": [_ok("sibling should not be called")],
                       "m9": [_ok("other provider")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "slow", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]},
        {"id": "fast", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m9"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "other provider"
    assert res.candidate.provider_id == "fast"
    # m1 was tried, m2 was skipped (same cooling key), m9 answered.
    assert [c["model"] for c in mock_llm.calls] == ["m1", "m9"]


def test_token_plan_403_is_model_scoped_not_account_scoped(tmp_path, mock_llm):
    """SenseNova live: deepseek-v4.1-flash is 403 'not available in the
    current token plan' while its sibling models answer fine.  Getting this
    wrong would disable a perfectly good key."""
    mock_llm.script = {"m1": [_not_in_plan()], "m2": [_ok("sibling")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "sibling"
    assert res.candidate.model == "m2"
    assert [c.model for c in pool.cooling()] == ["m1"]


def test_empty_200_body_counts_as_failure_and_fails_over(tmp_path, mock_llm):
    """Live finding: flash-class models answer 200 with an EMPTY body
    intermittently.  Treating that as success would ship a blank report."""
    mock_llm.script = {"m1": [_empty(), _empty()], "m2": [_ok("real text")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "real text"
    assert res.attempts[0].kind == "empty_response"
    assert res.attempts[0].status == 200


def test_truncated_200_body_fails_over_when_a_floor_is_set(tmp_path, mock_llm):
    """Live: sensenova/glm-5.2 returned 200 with only 95 characters of answer
    after spending its entire token budget on the reasoning channel.  A 200 is
    not evidence of a usable completion, so callers that know how long their
    output should be pass ``min_chars`` and get a failover instead."""
    mock_llm.script = {"m1": [_ok("## 执行摘要\n太短")],
                       "m2": [_ok("X" * 500)]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    res = pool.complete(MSG, min_chars=200)
    assert res.text == "X" * 500
    assert res.attempts[0].kind == "truncated_response"
    assert res.attempts[0].status == 200
    assert res.failovers == 1


def test_no_floor_accepts_a_short_completion(tmp_path, mock_llm):
    """min_chars defaults to 0, so the pool stays generic for callers that do
    not care about length."""
    mock_llm.script = {"m1": [_ok("短")]}
    pool = _pool(tmp_path, mock_llm)
    res = pool.complete(MSG)
    assert res.text == "短"
    assert res.attempts[0].ok


def test_truncated_response_cools_only_the_candidate(tmp_path, mock_llm):
    """A reasoning-heavy model is a per-model trait, not a per-account one."""
    mock_llm.script = {"m1": [_ok("stub")], "m2": [_ok("Y" * 400)]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]}])
    res = pool.complete(MSG, min_chars=200)
    assert res.candidate.model == "m2"
    assert [c.model for c in pool.cooling()] == ["m1"]


def test_eol_model_410_fails_over(tmp_path, mock_llm):
    """NVIDIA's z-ai/glm-5.2 is 410 Gone (EOL 2026-08-21); the successor in
    the same pool must still serve."""
    mock_llm.script = {"m1": [_gone("m1")], "m2": [_ok("successor")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "successor"
    assert res.attempts[0].kind == "model_error"
    assert res.attempts[0].status == 410


def test_no_credits_402_fails_over(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_no_credits()], "m2": [_ok("paid pool")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "paid pool"
    assert res.attempts[0].kind == "auth_error"


def test_every_candidate_rate_limited_raises_exhausted(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")], "m2": [_rate_limit("m2")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    with pytest.raises(LLMPoolExhausted) as ei:
        pool.complete(MSG)
    assert len(ei.value.attempts) == 2
    assert all(a.kind == "rate_limit" for a in ei.value.attempts)
    summary = ei.value.summary()
    assert "rate_limit" in summary
    # The summary must never contain a raw key.
    assert "k1-aaaaaaaa" not in summary and "k2-bbbbbbbb" not in summary


def test_multi_key_provider_fails_over_between_its_own_keys(tmp_path, mock_llm):
    """SenseNova ships 3 keys for the same models; a per-key quota error on
    key 1 must fall through to key 2, not skip the provider."""
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("key2 answered")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "sn", "base_url": mock_llm.base_url,
         "keys": ["k1-aaaaaaaa", "k2-bbbbbbbb"], "models": ["m1"]},
    ])
    res = pool.complete(MSG)
    assert res.text == "key2 answered"
    assert res.candidate.key_index == 1
    assert res.failovers == 1


def test_candidate_that_errored_is_skipped_without_a_second_call(tmp_path, mock_llm):
    """After a 429, the same candidate must not be hammered on the next
    complete() -- it is in cooldown, so it is not even contacted."""
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("should not be used")],
                       "m2": [_ok("ok2")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ])
    pool.complete(MSG)                      # m1 429s and cools
    calls_after_first = len(mock_llm.calls)
    res = pool.complete(MSG)                # m1 must be skipped entirely
    assert res.candidate.model == "m2"
    assert len(mock_llm.calls) == calls_after_first + 1


def test_forced_try_when_every_candidate_is_cooling(tmp_path, mock_llm):
    """Degrade instead of dying: with everything cooling the pool still makes
    exactly one attempt (the soonest to recover)."""
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("recovered")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
    ])
    with pytest.raises(LLMPoolExhausted):
        pool.complete(MSG)
    assert pool.available() == []            # nothing ready
    res = pool.complete(MSG)                 # forced through anyway
    assert res.text == "recovered"
    assert res.attempts[0].forced is True


def test_forced_try_can_be_disabled(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]}], force_try_when_all_cooling=False)
    with pytest.raises(LLMPoolExhausted):
        pool.complete(MSG)
    with pytest.raises(LLMPoolExhausted) as ei:
        pool.complete(MSG)
    assert ei.value.attempts[0].kind == "cooling_down"


def test_max_attempts_budget_is_respected(tmp_path, mock_llm):
    mock_llm.script = {f"m{i}": [_rate_limit(f"m{i}")] for i in range(5)}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": [f"m{i}" for i in range(5)]}], max_attempts=2)
    with pytest.raises(LLMPoolExhausted) as ei:
        pool.complete(MSG)
    assert len(ei.value.attempts) == 2
    assert len(mock_llm.calls) == 2


# ---------------------------------------------------------------------------
# Cooldown persistence + exponential backoff
# ---------------------------------------------------------------------------

def test_cooldown_survives_a_new_pool_instance(tmp_path, mock_llm):
    """A rate-limit window must outlive the process: a batch run that spawns
    a second pool should not re-burn the same 429."""
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("nope")], "m2": [_ok("m2")]}
    providers = [
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]},
        {"id": "p2", "base_url": mock_llm.base_url, "keys": ["k2-bbbbbbbb"],
         "models": ["m2"]},
    ]
    state = str(tmp_path / "shared_state.json")
    p1 = LLMPool(_cfg(mock_llm, providers), source=str(tmp_path / "pool.json"),
                 state_path=state)
    p1.complete(MSG)
    assert len(p1.cooling()) == 1

    p2 = LLMPool(_cfg(mock_llm, providers), source=str(tmp_path / "pool.json"),
                 state_path=state)
    assert [c.cid for c in p2.cooling()] == [p1.cooling()[0].cid]
    res = p2.complete(MSG)
    assert res.candidate.model == "m2"        # m1 stayed parked


def test_backoff_grows_with_repeated_failures(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]}],
        cooldown={"rate_limit": 1, "backoff_factor": 3, "max": 3600})
    cand = pool.candidates[0]
    pool._penalize(cand, "rate_limit")
    first = pool.failure_count(cand)
    r1 = pool.cooldown_remaining(cand)
    pool._penalize(cand, "rate_limit")
    r2 = pool.cooldown_remaining(cand)
    assert pool.failure_count(cand) == first + 1
    assert r2 > r1                             # 1s -> 3s


def test_backoff_is_capped(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm, cooldown={"rate_limit": 10,
                                               "backoff_factor": 10,
                                               "max": 15})
    cand = pool.candidates[0]
    for _ in range(6):
        pool._penalize(cand, "rate_limit")
    assert pool.cooldown_remaining(cand) <= 15.001


def test_success_clears_cooldown_and_tally(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1"), _ok("finally")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p1", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1"]}])
    cand = pool.candidates[0]
    with pytest.raises(LLMPoolExhausted):
        pool.complete(MSG)
    assert pool.failure_count(cand) == 1
    time.sleep(0.25)                           # let the 0.2s cooldown lapse
    pool.complete(MSG)
    assert pool.failure_count(cand) == 0
    assert pool.cooldown_remaining(cand) == 0


def test_reset_state_clears_everything(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm)
    with pytest.raises(LLMPoolExhausted):
        pool.complete(MSG)
    assert pool.cooling()
    pool.reset_state()
    assert pool.cooling() == []


# ---------------------------------------------------------------------------
# Input validation / API surface
# ---------------------------------------------------------------------------

def test_empty_messages_rejected(tmp_path, mock_llm):
    from xssentinel.core.llm_pool import LLMError
    pool = _pool(tmp_path, mock_llm)
    with pytest.raises(LLMError):
        pool.complete([])


def test_status_rows_are_masked_and_complete(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm)
    with pytest.raises(LLMPoolExhausted):
        pool.complete(MSG)
    rows = pool.status()
    assert len(rows) == 1
    row = rows[0]
    assert row["provider"] == "p1" and row["model"] == "m1"
    assert row["last_kind"] == "rate_limit"
    assert row["fail_count"] == 1
    assert row["cooldown_remaining"] > 0
    assert "key-aaaa" not in json.dumps(rows)


def test_probe_ignores_cooldowns_and_reports_each_candidate(tmp_path, mock_llm):
    mock_llm.script = {"m1": [_rate_limit("m1")], "m2": [_ok("healthy")]}
    pool = _pool(tmp_path, mock_llm, providers=[
        {"id": "p", "base_url": mock_llm.base_url, "keys": ["k1-aaaaaaaa"],
         "models": ["m1", "m2"]}])
    # m1 rate-limits (candidate-scoped) so m2 serves -- but m1 ends up cooling.
    res = pool.complete(MSG)
    assert res.candidate.model == "m2"
    assert len(pool.cooling()) == 1
    rows = pool.probe()
    assert len(rows) == 2                       # probed despite the cooldown
    assert {r["model"] for r in rows} == {"m1", "m2"}
    by_model = {r["model"]: r for r in rows}
    assert by_model["m2"]["ok"] is True
    assert by_model["m1"]["ok"] is False


def test_request_payload_is_openai_shaped(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm, generation={"max_tokens": 77,
                                                 "temperature": 0.25})
    pool.complete(MSG)
    sent = mock_llm.calls[0]
    assert sent["path"].endswith("/v1/chat/completions")
    assert sent["auth"] == "Bearer key-aaaa-1111"
    assert sent["body"]["model"] == "m1"
    assert sent["body"]["max_tokens"] == 77
    assert sent["body"]["temperature"] == 0.25
    assert sent["body"]["stream"] is False
    assert sent["body"]["messages"] == MSG


def test_complete_accepts_per_call_overrides(tmp_path, mock_llm):
    pool = _pool(tmp_path, mock_llm)
    pool.complete(MSG, max_tokens=11, temperature=0.9)
    body = mock_llm.calls[0]["body"]
    assert body["max_tokens"] == 11 and body["temperature"] == 0.9


def test_http_error_does_not_leak_key_into_exception_text(tmp_path, mock_llm,
                                                          monkeypatch):
    """Exception text reaches logs and reports; keys must not."""
    mock_llm.script = {"m1": [_rate_limit("m1")]}
    pool = _pool(tmp_path, mock_llm)
    with pytest.raises(LLMPoolExhausted) as ei:
        pool.complete(MSG)
    text = str(ei.value) + ei.value.summary()
    assert "key-aaaa-1111" not in text


def test_from_file_missing_config_raises(tmp_path):
    with pytest.raises(LLMConfigError):
        LLMPool.from_file(str(tmp_path / "nope.json"))


def test_from_file_env_override(tmp_path, mock_llm, monkeypatch):
    cfg_path = tmp_path / "custom.json"
    cfg_path.write_text(json.dumps(_cfg(mock_llm)), encoding="utf-8")
    monkeypatch.setenv("XSSENTINEL_LLM_CONFIG", str(cfg_path))
    pool = LLMPool.from_file()
    assert pool.source == str(cfg_path)


def test_shipped_default_pool_config_is_valid():
    """The config that ships in the package must load and expand -- a typo
    there would silently disable --ai-report for everyone.

    Resolved via the package path directly rather than a bare
    ``LLMPool.from_file()``: tests/conftest.py points XSSENTINEL_LLM_CONFIG at
    a non-existent file so a test can never reach a live provider, and this
    test is specifically about the file that ships.
    """
    import os
    from xssentinel.core import llm_pool as _lp
    shipped = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(_lp.__file__))),
        "data", "llm_providers.example.json")
    pool = LLMPool.from_file(shipped)
    assert len(pool.candidates) >= 5
    ids = {c.provider_id for c in pool.candidates}
    assert "amd" in ids and "sensenova" in ids
    # OpenRouter is shipped disabled (account blocked) -- it must not appear.
    assert "openrouter" not in ids
    # Every candidate must resolve to a usable endpoint.
    for c in pool.candidates:
        assert c.endpoint.endswith("/chat/completions")
        assert c.key and c.model
