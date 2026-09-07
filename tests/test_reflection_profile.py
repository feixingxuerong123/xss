"""Unit tests for the reflection-profile module (Phase 31).

Covers the sandwich-probe classification and the profile-driven
payload/transform prioritization without needing the vuln_server.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import reflection_profile as rp


class TestBuildProbe:
    def test_probe_carries_token_and_all_chars(self):
        probe = rp.build_probe("tok123")
        assert probe.startswith("tok123")
        for ch in "\"'><>()=/;":
            assert ch in probe


class TestProfileReflection:
    def test_full_reflection(self):
        # PROBE_CHARS now includes the backtick (Phase 32).
        all_chars = rp.PROBE_CHARS
        prof = rp.profile_reflection(f"x tok123{all_chars} y", "tok123")
        assert prof["reflected"] is True
        assert prof["full_reflection"] is True
        assert prof["chars_stripped"] == []
        assert prof["chars_encoded"] == []

    def test_stripped_chars_detected(self):
        # Server stripped < and = before echoing ("'<>()=/; minus < and =).
        prof = rp.profile_reflection('tok123"\'>>() ;', "tok123")
        assert prof["reflected"] is True
        assert prof["full_reflection"] is False
        assert "<" in prof["chars_stripped"]
        assert "=" in prof["chars_stripped"]
        assert '"' in prof["chars_kept"]

    def test_html_entities_classified_as_encoded(self):
        prof = rp.profile_reflection(
            'tok123&quot;&lt;&#39;&gt;()=/; z', "tok123")
        assert prof["full_reflection"] is False
        for ch in ('"', "<", "'", ">"):
            assert ch in prof["chars_encoded"]
        for ch in "()/;":
            assert ch in prof["chars_kept"]

    def test_double_encoded_entity_is_encoded(self):
        prof = rp.profile_reflection("tok123&amp;lt;()=/; z", "tok123")
        assert "<" in prof["chars_encoded"]

    def test_percent_encoding_classified_as_encoded(self):
        prof = rp.profile_reflection("tok123%22%27%3c%3e()=/; z", "tok123")
        for ch in ('"', "'", "<", ">"):
            assert ch in prof["chars_encoded"]

    def test_no_reflection(self):
        prof = rp.profile_reflection("nothing here", "tok123")
        assert prof["reflected"] is False
        assert prof["full_reflection"] is False

    def test_empty_inputs_return_none(self):
        assert rp.profile_reflection("", "tok123") is None
        assert rp.profile_reflection("body", "") is None


class TestPrioritizePayloads:
    def _prof(self, kept):
        return {"full_reflection": False, "chars_kept": kept,
                "chars_stripped": [], "chars_encoded": []}

    def test_quote_survival_reorders(self):
        prof = self._prof(["'", "(", ")", "/", ";"])
        cands = [
            {"payload": "<svg onload=alert(1)>"},   # needs < > =
            {"payload": "'-alert(1)-'"},            # single-quote breakout
            {"payload": '" onfocus=alert(1) x="'},  # double-quote breakout
        ]
        out = rp.prioritize_payloads(prof, cands)
        assert out[0]["payload"] == "'-alert(1)-'"

    def test_full_reflection_keeps_order(self):
        prof = {"full_reflection": True, "chars_kept": list(rp.PROBE_CHARS)}
        cands = [{"payload": "<b>"}, {"payload": "<i>"}]
        assert rp.prioritize_payloads(prof, cands) is cands

    def test_stable_sort_preserves_ties(self):
        prof = self._prof(["'", "(", ")", "/", ";"])
        cands = [{"payload": "'a'"}, {"payload": "'b'"}]
        out = rp.prioritize_payloads(prof, cands)
        assert [c["payload"] for c in out] == ["'a'", "'b'"]

    def test_plain_string_candidates_supported(self):
        prof = self._prof(["'", "(", ")", "/", ";"])
        out = rp.prioritize_payloads(prof, ["<b>x</b>", "plain'text"])
        assert out[0] == "plain'text"


class TestPrioritizeTransforms:
    def _base(self, kept=(), encoded=()):
        return {"full_reflection": False, "chars_kept": list(kept),
                "chars_stripped": [], "chars_encoded": list(encoded)}

    def test_full_reflection_returns_none(self):
        prof = {"full_reflection": True, "chars_kept": list(rp.PROBE_CHARS)}
        assert rp.prioritize_transforms(prof) is None

    def test_lt_encoded_prefers_entity_restore(self):
        pri = rp.prioritize_transforms(self._base(kept=['"', "'"],
                                                  encoded=["<", ">"]))
        assert pri and pri[0] == "html5_entities"
        # mixed_case cannot restore an ENCODED < -- must not be prioritized.
        assert "mixed_case" not in pri

    def test_lt_stripped_prefers_fullwidth(self):
        prof = {"full_reflection": False, "chars_kept": ['"', "'"],
                "chars_stripped": ["<"], "chars_encoded": []}
        pri = rp.prioritize_transforms(prof)
        assert pri and pri[0] == "fullwidth"

    def test_quote_loss_surfaces_quote_restore(self):
        pri = rp.prioritize_transforms(self._base(kept=["<", ">"],
                                                  encoded=['"']))
        assert "url_encode_selective" in pri

    def test_no_loss_keeps_default_order(self):
        # Everything kept except chars with no restore family -> None.
        prof = {"full_reflection": False, "chars_kept": list(rp.PROBE_CHARS),
                "chars_stripped": [], "chars_encoded": []}
        # full_reflection False but nothing missing -> no families -> None
        pri = rp.prioritize_transforms(prof)
        assert pri is None

    def test_families_deduplicated(self):
        prof = {"full_reflection": False, "chars_kept": [";"],
                "chars_stripped": ["<"], "chars_encoded": []}
        pri = rp.prioritize_transforms(prof)
        assert len(pri) == len(set(pri))
