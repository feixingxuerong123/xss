"""Multi-provider LLM failover pool (Phase 176).

Why this exists
---------------
XSSentinel's *detection* is fully deterministic: no model decides whether a
target is vulnerable.  The LLM has exactly one job, and it is a
non-authoritative one -- writing the prose of the report (executive summary,
per-finding cause + remediation, reproduction notes).  Every fact in that
prose is handed to the model as input; the model never invents a finding.

Because that job is non-authoritative, it must never be able to break a scan
or hang a pipeline.  This module therefore treats LLM access as *unreliable by
design*:

  * several providers x several keys x several models -> one ordered candidate
    list (order = the order in the config file)
  * a candidate that answers 429 / 401 / 403 / 5xx / timeout / **empty body**
    goes into a cooldown (exponential backoff, persisted to disk so a
    rate-limit window survives across processes) and the pool moves on to the
    next candidate
  * if every candidate is cooling down, exactly one (the soonest to recover)
    is tried anyway, so the pool degrades instead of dying
  * if all of them fail, :class:`LLMPoolExhausted` is raised and the caller
    falls back to the deterministic template report (see ``report_ai.py``)

Why the classifier reads the response BODY, not just the status code
-------------------------------------------------------------------
Written against live probe results (2026-09-22) from the pools in
``data/llm_providers.json``:

    AMD  GLM-5.3-Flash       429  "Model 'GLM-5.3-Flash' is at its
                                   concurrency limit (8); please retry later"
    AMD  Qwen3.8-Flash-Next  200  empty body (reasoning ate max_tokens)
    SenseNova deepseek-v4-flash 200 empty body, 3 of 7 probes
    SenseNova deepseek-v4.1-flash 403 "model is not available in the current
                                   token plan"   <- model-scoped, NOT account
    NVIDIA z-ai/glm-5.2      410  Gone (end of life 2026-08-21)
    OpenRouter (any model)   403  "Inference is blocked on this account."

Two 403s with opposite meanings (model not in plan vs. whole account blocked)
are why status alone is insufficient.  Empty-but-200 is why a blank completion
counts as a soft failure rather than success.

Cooldown scope
--------------
A failure is charged to either the *candidate* (one provider+key+model) or the
whole *key*:

    candidate-scoped: rate_limit, model_error, empty_response, bad_request
        The live probe shows AMD's concurrency cap is per-MODEL ("Model
        'GLM-5.3-Flash' is at its concurrency limit"), so a 429 on one model
        must NOT take out the other models behind the same key.
    key-scoped: auth_error, server_error, timeout, network_error
        A quota / billing / account problem, or a provider that is simply
        unreachable, applies to every model behind that key.

Zero new dependencies: plain ``requests`` plus the stdlib.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .logger import get_logger

_log = get_logger("llm_pool")

# ---------------------------------------------------------------------------
# Config discovery / defaults
# ---------------------------------------------------------------------------

#: Shipped pool (the user's note transcribed + live probed).
DEFAULT_CONFIG_NAME = os.path.join("data", "llm_providers.json")
#: Runtime cooldown state, written next to the resolved config file.
DEFAULT_STATE_NAME = "llm_state.json"
#: Env var pointing at an alternate pool config.
ENV_CONFIG = "XSSENTINEL_LLM_CONFIG"
#: Env var prefix for per-provider key override, e.g. XSSENTINEL_LLM_KEY_AMD.
ENV_KEY_PREFIX = "XSSENTINEL_LLM_KEY_"

_DEFAULT_COOLDOWN = {
    "rate_limit": 20,
    "auth_error": 600,
    "server_error": 15,
    "timeout": 20,
    "network_error": 20,
    "model_not_found": 900,
    "empty_response": 8,
    "truncated_response": 8,
    "bad_request": 60,
    "backoff_factor": 2,
    "max": 900,
}

#: kind -> which unit of the pool pays for it.
_SCOPE = {
    "rate_limit": "candidate",
    "model_error": "candidate",
    "empty_response": "candidate",
    "truncated_response": "candidate",
    "bad_request": "candidate",
    "auth_error": "key",
    "server_error": "key",
    "timeout": "key",
    "network_error": "key",
}

# Body fingerprints.  Checked only after the status code, and only where the
# status is ambiguous (403) or generic (4xx).
_MODEL_HINTS = (
    "model_not_found", "not available", "does not exist", "no such model",
    "unknown model", "unsupported model", "end of life", "token plan",
    "not exist", "deprecated", "no longer available",
)
_RATE_HINTS = (
    "rate limit", "rate_limit", "ratelimit", "too many requests",
    "concurrency limit", "quota exceeded", "overloaded", "capacity",
    "try again later", "please retry",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LLMError(Exception):
    """Base class for pool errors."""


class LLMConfigError(LLMError):
    """Pool config missing / malformed / contains no usable candidate."""


class LLMPoolExhausted(LLMError):
    """Every candidate failed.  Callers MUST degrade, not crash.

    ``attempts`` carries one :class:`Attempt` per try so the caller can report
    *why* (rate limited? account blocked? all timing out?) instead of a bare
    "LLM unavailable".
    """

    def __init__(self, message: str, attempts: list["Attempt"] | None = None):
        super().__init__(message)
        self.attempts = attempts or []

    def summary(self) -> str:
        """One-line-per-candidate digest, safe to print (keys masked)."""
        if not self.attempts:
            return "no candidates were attempted"
        lines = []
        for a in self.attempts:
            tag = a.kind if not a.ok else "ok"
            if a.status:
                tag = f"{tag}/{a.status}"
            extra = f" -- {a.detail}" if a.detail else ""
            lines.append(f"{a.candidate.provider_id}:{a.candidate.model} "
                         f"[{a.candidate.masked_key()}] {tag}{extra}")
        return "; ".join(lines)


# ---------------------------------------------------------------------------
# Data holders
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """One callable slot: a provider + a specific key + a specific model."""

    provider_id: str
    label: str
    endpoint: str
    key: str
    model: str
    key_index: int = 0
    order: int = 0
    verify_ssl: bool = True

    @property
    def cid(self) -> str:
        """Candidate-scoped state key."""
        return f"{self.provider_id}#{self.key_index}#{self.model}"

    @property
    def kid(self) -> str:
        """Key-scoped state key (all models behind one key)."""
        return f"{self.provider_id}#{self.key_index}#*"

    def masked_key(self) -> str:
        return mask_key(self.key)

    def describe(self) -> str:
        return f"{self.provider_id}/{self.model} [{self.masked_key()}]"


@dataclass
class Attempt:
    """Record of a single call attempt (kept for diagnostics + tests)."""

    candidate: Candidate
    ok: bool
    kind: str = "ok"
    status: int | None = None
    elapsed: float = 0.0
    detail: str = ""
    forced: bool = False

    def to_dict(self) -> dict:
        return {
            "provider": self.candidate.provider_id,
            "model": self.candidate.model,
            "key": self.candidate.masked_key(),
            "ok": self.ok,
            "kind": self.kind,
            "status": self.status,
            "elapsed": round(self.elapsed, 2),
            "detail": self.detail,
            "forced": self.forced,
        }


@dataclass
class LLMResult:
    """A successful completion plus the trail of what was tried first."""

    text: str
    candidate: Candidate
    attempts: list[Attempt] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def failovers(self) -> int:
        """How many candidates were burned before one answered."""
        return max(0, len(self.attempts) - 1)

    def routing_note(self) -> str:
        if self.failovers == 0:
            return f"{self.candidate.describe()} (first try)"
        return (f"{self.candidate.describe()} "
                f"(after {self.failovers} failover(s): "
                f"{', '.join(a.kind for a in self.attempts[:-1])})")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mask_key(key: str) -> str:
    """Never let a full API key reach a log line, report, or exception."""
    if not key:
        return "***"
    if len(key) <= 14:
        return "***"
    return f"{key[:6]}***{key[-4:]}"


def _normalize_endpoint(base: str) -> str:
    """Accept either a base URL or a full /chat/completions URL.

    The user-supplied note mixes both styles (OpenRouter/NVIDIA give the full
    path, AMD gives a bare /v1), so normalise instead of guessing per provider.
    """
    b = (base or "").strip().rstrip("/")
    if not b:
        raise LLMConfigError("provider base_url is empty")
    if b.endswith("/chat/completions"):
        return b
    return b + "/chat/completions"


def _classify(status: int | None, body: str = "",
              exc: BaseException | None = None) -> str:
    """Map an HTTP outcome to a cooldown kind.

    See the module docstring for the live responses this was written against.
    """
    if exc is not None:
        if isinstance(exc, requests.exceptions.Timeout):
            return "timeout"
        if isinstance(exc, requests.exceptions.RequestException):
            return "network_error"
        return "network_error"

    low = (body or "").lower()

    if status == 429:
        return "rate_limit"
    if status in (401, 402):
        return "auth_error"
    if status in (404, 410):
        # 404: model_not_found.  410: NVIDIA's "end of life" — same treatment.
        return "model_error"
    if status == 403:
        # Ambiguous by design: "model is not available in the current token
        # plan" (model-scoped) vs "Inference is blocked on this account"
        # (key-scoped).  Probe both live in the same session.
        if any(h in low for h in _MODEL_HINTS):
            return "model_error"
        return "auth_error"
    if status == 408 or (status is not None and status >= 500):
        return "server_error"

    if any(h in low for h in _MODEL_HINTS):
        return "model_error"
    if any(h in low for h in _RATE_HINTS):
        return "rate_limit"
    return "bad_request"


def _extract_text(payload: dict) -> str:
    """Pull the assistant text out of an OpenAI-compatible response.

    Tolerates the shapes seen live: missing ``choices``, ``choices`` holding a
    null entry, ``message`` absent, and reasoning models that put the answer in
    ``reasoning_content`` with an empty ``content``.
    """
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    msg = first.get("message")
    if isinstance(msg, dict):
        text = msg.get("content")
        if isinstance(text, str) and text.strip():
            return text
        # Some providers split out a reasoning channel.
        for alt in ("reasoning_content", "reasoning"):
            v = msg.get(alt)
            if isinstance(v, str) and v.strip():
                return v
    # Streaming-style / legacy shape.
    text = first.get("text")
    if isinstance(text, str):
        return text
    return ""


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

class LLMPool:
    """Ordered failover pool over OpenAI-compatible chat endpoints."""

    def __init__(self, config: dict, source: str = "",
                 state_path: str | None = None):
        if not isinstance(config, dict):
            raise LLMConfigError("pool config must be a JSON object")
        self.config = config
        self.source = source
        self._lock = threading.RLock()

        cov = config.get("cooldown") or {}
        self.cooldown_cfg = dict(_DEFAULT_COOLDOWN)
        self.cooldown_cfg.update({k: v for k, v in cov.items()
                                  if isinstance(v, (int, float))})
        self.timeout = float(config.get("timeout") or 90)
        self.max_attempts = int(config.get("max_attempts") or 12)
        gen = config.get("generation") or {}
        self.max_tokens = int(gen.get("max_tokens") or 4000)
        self.temperature = float(gen.get("temperature", 0.3))
        # A pool whose every candidate is cooling still gets ONE forced try
        # (soonest to recover) so a scan is never left without a narrative.
        self.force_when_all_cooling = bool(
            config.get("force_try_when_all_cooling", True))

        self._candidates = self._build_candidates(config)
        if not self._candidates:
            raise LLMConfigError(
                "no enabled LLM candidate in config"
                + (f" ({source})" if source else "")
                + " -- every provider is disabled or has no key/model")

        if state_path is None:
            base_dir = os.path.dirname(os.path.abspath(source)) if source else os.getcwd()
            state_path = os.path.join(base_dir, DEFAULT_STATE_NAME)
        self.state_path = state_path
        self._state: dict[str, dict] = {}
        self._load_state()

    # -- construction ------------------------------------------------------

    @classmethod
    def _build_candidates(cls, config: dict) -> list[Candidate]:
        out: list[Candidate] = []
        order = 0
        for p in config.get("providers") or []:
            if not isinstance(p, dict) or not p.get("enabled", True):
                continue
            pid = str(p.get("id") or f"provider{order}")
            label = str(p.get("label") or pid)
            try:
                endpoint = _normalize_endpoint(p.get("base_url") or p.get("endpoint") or "")
            except LLMConfigError as e:
                _log.warning("llm pool: skipping provider %s: %s", pid, e)
                continue
            keys = [k for k in (p.get("keys") or ([p["api_key"]] if p.get("api_key") else []))
                    if isinstance(k, str) and k.strip()]
            env = os.environ.get(ENV_KEY_PREFIX + pid.upper())
            if env:
                keys = [k.strip() for k in env.split(",") if k.strip()]
            models = [m for m in (p.get("models") or []) if isinstance(m, str) and m.strip()]
            if not keys or not models:
                _log.warning("llm pool: provider %s has no %s -- skipped",
                             pid, "key" if not keys else "model")
                continue
            verify = bool(p.get("verify_ssl", config.get("verify_ssl", True)))
            # Model-outer / key-inner expansion.  A provider's several keys are
            # usually *quota redundancy for the same model list* (SenseNova
            # ships 3 keys for one model set), so the pool should try the
            # preferred model across every key before falling back to a lesser
            # model.  Key-outer would burn all of key 1's models first and only
            # then discover that key 2 was healthy the whole time.
            for model in models:
                for ki, key in enumerate(keys):
                    out.append(Candidate(
                        provider_id=pid, label=label, endpoint=endpoint,
                        key=key, model=model, key_index=ki, order=order,
                        verify_ssl=verify,
                    ))
                    order += 1
        return out

    @classmethod
    def from_file(cls, path: str | None = None,
                  state_path: str | None = None) -> "LLMPool":
        """Load the pool from an explicit path, else the discovery order."""
        resolved = path or os.environ.get(ENV_CONFIG) or _default_config_path()
        if not resolved or not os.path.isfile(resolved):
            raise LLMConfigError(
                "LLM pool config not found"
                + (f": {resolved}" if resolved else
                   " (looked for data/llm_providers.json in the package)"))
        try:
            with open(resolved, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise LLMConfigError(f"cannot read pool config {resolved}: {e}") from None
        return cls(cfg, source=resolved, state_path=state_path)

    # -- candidate access --------------------------------------------------

    @property
    def candidates(self) -> list[Candidate]:
        """All candidates, in config order."""
        return list(self._candidates)

    def available(self, models: list[str] | None = None) -> list[Candidate]:
        """Candidates that are not cooling down (config order preserved)."""
        with self._lock:
            cands = [c for c in self._candidates if self._matches(c, models)]
            return [c for c in cands if self.cooldown_remaining(c) <= 0]

    def cooling(self) -> list[Candidate]:
        with self._lock:
            return [c for c in self._candidates if self.cooldown_remaining(c) > 0]

    @staticmethod
    def _matches(c: Candidate, models: list[str] | None) -> bool:
        if not models:
            return True
        lower = {m.lower() for m in models}
        return c.model.lower() in lower

    def cooldown_remaining(self, c: Candidate) -> float:
        """Seconds until this candidate is usable again (0 = ready)."""
        now = time.time()
        best = 0.0
        with self._lock:
            for skey in (c.cid, c.kid):
                st = self._state.get(skey)
                if st:
                    best = max(best, float(st.get("cooldown_until", 0)) - now)
        return max(0.0, best)

    def failure_count(self, c: Candidate) -> int:
        with self._lock:
            st = self._state.get(c.cid) or {}
            return int(st.get("fail_count", 0))

    # -- state persistence -------------------------------------------------

    def _load_state(self) -> None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            entries = raw.get("entries") if isinstance(raw, dict) else None
            self._state = entries if isinstance(entries, dict) else {}
        except (OSError, json.JSONDecodeError):
            self._state = {}

    def _save_state(self) -> None:
        tmp = self.state_path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "updated": time.time(),
                           "entries": self._state}, fh, indent=2,
                          ensure_ascii=False)
            os.replace(tmp, self.state_path)
        except OSError as e:
            # A read-only checkout must not break a scan over a cache file.
            _log.debug("llm pool: cannot persist state to %s: %s",
                       self.state_path, e)

    def _penalize(self, c: Candidate, kind: str, detail: str = "") -> float:
        """Charge a failure to the candidate or its whole key; return seconds."""
        scope = _SCOPE.get(kind, "candidate")
        skey = c.cid if scope == "candidate" else c.kid
        base = float(self.cooldown_cfg.get(kind, 60))
        # ``model_not_found`` in config maps onto the internal ``model_error``.
        if kind == "model_error":
            base = float(self.cooldown_cfg.get("model_not_found", base))
        factor = float(self.cooldown_cfg.get("backoff_factor", 2) or 1)
        cap = float(self.cooldown_cfg.get("max", 900))
        with self._lock:
            st = self._state.setdefault(skey, {})
            fails = int(st.get("fail_count", 0)) + 1
            st["fail_count"] = fails
            st["last_kind"] = kind
            st["last_error"] = (detail or "")[:300]
            st["last_failure_at"] = time.time()
            secs = min(base * (factor ** (fails - 1)), cap) if base > 0 else 0.0
            st["cooldown_until"] = time.time() + secs
            # Candidate-scoped failures also bump the key-level tally so
            # ``status()`` can show a chronically sick provider.
            if skey != c.kid:
                ks = self._state.setdefault(c.kid, {})
                ks["last_kind"] = kind
            self._save_state()
        _log.debug("llm pool: %s -> %s, cooling %.0fs", c.describe(), kind, secs)
        return secs

    def _recover(self, c: Candidate) -> None:
        """Clear cooldown + failure tally after a good answer."""
        with self._lock:
            for skey in (c.cid, c.kid):
                st = self._state.get(skey)
                if st:
                    st["fail_count"] = 0
                    st["cooldown_until"] = 0
                    st["last_kind"] = "ok"
                    st["last_success_at"] = time.time()
            self._save_state()

    def reset_state(self) -> None:
        """Drop every cooldown (``--ai-reset`` / tests)."""
        with self._lock:
            self._state = {}
            self._save_state()

    # -- the call ----------------------------------------------------------

    def complete(self, messages: list[dict], *,
                 models: list[str] | None = None,
                 max_tokens: int | None = None,
                 temperature: float | None = None,
                 timeout: float | None = None,
                 min_chars: int = 0) -> LLMResult:
        """Run ``messages`` through the pool, failing over until one answers.

        ``min_chars`` is a floor on the length of a *successful* completion.
        It exists because of a live failure mode: reasoning models may spend
        their entire token budget on the thinking channel and return 200 with
        a near-empty body (``sensenova/glm-5.2`` returned the requested 1500
        tokens but only 95 characters of answer).  A caller that knows how long
        its output should be passes a floor here and gets a failover instead of
        a truncated artefact.

        Raises :class:`LLMPoolExhausted` when every candidate has been tried
        and failed -- callers degrade to the deterministic template instead of
        propagating the error.
        """
        if not isinstance(messages, list) or not messages:
            raise LLMError("messages must be a non-empty list")

        t_start = time.time()
        pool = [c for c in self._candidates if self._matches(c, models)]
        if not pool:
            raise LLMPoolExhausted(
                f"no candidate matches model filter {models!r}")

        ready = [c for c in pool if self.cooldown_remaining(c) <= 0]
        forced = False
        if not ready:
            if not self.force_when_all_cooling:
                raise LLMPoolExhausted(
                    "every candidate is cooling down", self._cooldown_attempts(pool))
            # Degrade instead of dying: retry the one that recovers soonest.
            forced = True
            ready = [min(pool, key=self.cooldown_remaining)]
            _log.warning("llm pool: all %d candidate(s) cooling; forcing %s",
                         len(pool), ready[0].describe())

        attempts: list[Attempt] = []
        for cand in ready:
            if len(attempts) >= self.max_attempts:
                _log.warning("llm pool: attempt budget %d reached", self.max_attempts)
                break
            # Re-check the cooldown *inside* the loop: a key-scoped failure
            # (timeout / 5xx / auth) cools the whole key, so a sibling from
            # that same key -- already sitting in this ready list -- is now
            # doomed as well.  Chasing it would burn another full timeout.
            # Live: two AMD candidates timed out back to back, costing ~90s of
            # a 116s report run before the pool reached a working provider.
            if not forced and self.cooldown_remaining(cand) > 0:
                _log.debug("llm pool: skipping %s (cooled by a sibling)",
                           cand.describe())
                continue
            att = self._try_one(cand, messages, max_tokens, temperature,
                                timeout, forced, min_chars)
            attempts.append(att)
            if att.ok:
                self._recover(cand)
                return LLMResult(text=att.detail, candidate=cand,
                                 attempts=attempts,
                                 elapsed=time.time() - t_start)
            self._penalize(cand, att.kind, att.detail)

        raise LLMPoolExhausted(
            f"all {len(attempts)} attempt(s) failed", attempts)

    def _cooldown_attempts(self, pool: list[Candidate]) -> list[Attempt]:
        """Synthesise attempts for a pool that never got to make a real call."""
        return [Attempt(candidate=c, ok=False, kind="cooling_down",
                        detail=f"{self.cooldown_remaining(c):.0f}s left")
                for c in pool]

    def _try_one(self, cand: Candidate, messages: list[dict],
                 max_tokens: int | None, temperature: float | None,
                 timeout: float | None, forced: bool,
                 min_chars: int = 0) -> Attempt:
        payload = {
            "model": cand.model,
            "messages": messages,
            "max_tokens": int(max_tokens or self.max_tokens),
            "temperature": (self.temperature if temperature is None
                            else float(temperature)),
            "stream": False,
        }
        headers = {
            "Authorization": f"Bearer {cand.key}",
            "Content-Type": "application/json",
        }
        t0 = time.time()
        try:
            resp = requests.post(
                cand.endpoint,
                headers=headers,
                json=payload,
                timeout=(10.0, float(timeout or self.timeout)),
                verify=cand.verify_ssl,
            )
        except requests.exceptions.RequestException as e:
            kind = _classify(None, "", e)
            return Attempt(candidate=cand, ok=False, kind=kind,
                           elapsed=time.time() - t0,
                           detail=f"{type(e).__name__}: {str(e)[:160]}",
                           forced=forced)

        elapsed = time.time() - t0
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                return Attempt(candidate=cand, ok=False, kind="bad_request",
                               status=200, elapsed=elapsed,
                               detail="200 but response was not JSON",
                               forced=forced)
            text = _extract_text(data)
            if not text.strip():
                # Seen live: flash-class models intermittently return an empty
                # body with a 200.  Treat as a soft failure and fail over --
                # otherwise the report would be silently blank.
                return Attempt(candidate=cand, ok=False, kind="empty_response",
                               status=200, elapsed=elapsed,
                               detail="200 with empty completion", forced=forced)
            if min_chars and len(text.strip()) < min_chars:
                # Seen live: sensenova/glm-5.2 burned the whole 1500-token
                # budget on its reasoning channel and returned 95 characters
                # of answer.  A 200 is not evidence of a usable completion.
                return Attempt(candidate=cand, ok=False,
                               kind="truncated_response", status=200,
                               elapsed=elapsed,
                               detail=(f"200 but only {len(text.strip())} chars "
                                       f"(floor {min_chars}); reasoning may "
                                       f"have consumed the budget"),
                               forced=forced)
            return Attempt(candidate=cand, ok=True, kind="ok",
                           status=200, elapsed=elapsed, detail=text,
                           forced=forced)

        body = (resp.text or "")[:400].replace("\n", " ")
        kind = _classify(resp.status_code, body)
        return Attempt(candidate=cand, ok=False, kind=kind,
                       status=resp.status_code, elapsed=elapsed,
                       detail=body[:200], forced=forced)

    # -- diagnostics -------------------------------------------------------

    def status(self) -> list[dict]:
        """Per-candidate health, safe to print (keys masked)."""
        out = []
        for c in self._candidates:
            with self._lock:
                st = self._state.get(c.cid) or {}
            out.append({
                "provider": c.provider_id,
                "model": c.model,
                "key": c.masked_key(),
                "order": c.order,
                "cooldown_remaining": round(self.cooldown_remaining(c), 1),
                "fail_count": int(st.get("fail_count", 0)),
                "last_kind": st.get("last_kind", ""),
                "last_error": st.get("last_error", ""),
            })
        return out

    def probe(self, prompt: str = "Reply with the single word: ok",
              models: list[str] | None = None) -> list[dict]:
        """Live-call every candidate once (ignores cooldowns) for health checks.

        Deliberately bypasses the cooldown state: this is the "which of my keys
        still work?" tool, not the failover path.  Costs one tiny call per
        candidate, so it is never called implicitly.
        """
        out = []
        pool = [c for c in self._candidates if self._matches(c, models)]
        for c in pool:
            att = self._try_one(c, [{"role": "user", "content": prompt}],
                                max_tokens=16, temperature=0.0, timeout=None,
                                forced=False)
            row = att.to_dict()
            row["endpoint"] = c.endpoint
            if att.ok:
                row["reply"] = att.detail[:60]
            out.append(row)
        return out


def _default_config_path() -> str | None:
    """Discovery order: env var -> package data dir -> user home."""
    env = os.environ.get(ENV_CONFIG)
    if env:
        return env
    pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       DEFAULT_CONFIG_NAME)
    if os.path.isfile(pkg):
        return pkg
    for home_name in (".xssentinel/llm_providers.json",):
        p = os.path.join(os.path.expanduser("~"), *home_name.split("/"))
        if os.path.isfile(p):
            return p
    return pkg  # report the package path in the error message


def default_pool(config_path: str | None = None) -> LLMPool:
    """Convenience constructor honouring the discovery order."""
    return LLMPool.from_file(config_path)
