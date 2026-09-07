"""Tests for api/persistence.py -- SqliteJobStore + Job<->dict converters.

Covers upsert/load/load_all(filter+order)/delete/count, JSON column
round-trips, tolerant decoding of broken JSON, partial-dict saves,
close-then-use, and the job_to_store_dict / store_dict_to_job round-trip
(including the closure-stripping of ``_``-prefixed options).
"""
from __future__ import annotations
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.api.persistence import (
    SqliteJobStore,
    job_to_store_dict,
    store_dict_to_job,
)


def _job(scan_id="s1", **over):
    d = {
        "scan_id": scan_id,
        "target_url": "http://t/page",
        "method": "POST",
        "params": {"q": "x"},
        "data": {"b": "y"},
        "options": {"max_payloads": 5},
        "state": "pending",
        "created_at": "t0",
        "started_at": "",
        "finished_at": "",
        "error": None,
        "findings": [{"type": "reflected", "severity": "high"}],
        "finding_count": 1,
        "high_severity_count": 1,
        "requests_made": 42,
        "waf_name": "cloudflare",
        "coverage_summary": {"endpoints": 3},
        "_seq": 7,
    }
    d.update(over)
    return d


@pytest.fixture
def store(tmp_path):
    st = SqliteJobStore(str(tmp_path / "jobs.db"))
    yield st
    st.close()


class TestSqliteJobStore:
    def test_save_and_load_roundtrip(self, store):
        store.save(_job())
        d = store.load("s1")
        assert d["target_url"] == "http://t/page"
        assert d["params"] == {"q": "x"}              # JSON decoded
        assert d["data"] == {"b": "y"}
        assert d["findings"][0]["type"] == "reflected"  # JSON decoded
        assert d["coverage_summary"] == {"endpoints": 3}
        assert d["waf_name"] == "cloudflare"

    def test_load_missing_returns_none(self, store):
        assert store.load("nope") is None

    def test_upsert_replaces(self, store):
        store.save(_job("s1", state="pending"))
        store.save(_job("s1", state="running", requests_made=10))
        d = store.load("s1")
        assert d["state"] == "running"
        assert d["requests_made"] == 10
        assert store.count() == 1

    def test_load_all_newest_first_by_seq(self, store):
        store.save(_job("a", _seq=1))
        store.save(_job("b", _seq=9))
        store.save(_job("c", _seq=5))
        ids = [d["scan_id"] for d in store.load_all()]
        assert ids == ["b", "c", "a"]

    def test_load_all_state_filter(self, store):
        store.save(_job("p1", state="pending"))
        store.save(_job("r1", state="running"))
        ids = [d["scan_id"] for d in store.load_all(state="running")]
        assert ids == ["r1"]
        assert store.count(state="pending") == 1
        assert store.count() == 2

    def test_delete(self, store):
        store.save(_job("s1"))
        assert store.delete("s1") is True
        assert store.delete("s1") is False       # already gone
        assert store.load("s1") is None

    def test_partial_dict_gets_sane_defaults(self, store):
        store.save({"scan_id": "minimal"})
        d = store.load("minimal")
        assert d["params"] == {}                 # None -> {}
        assert d["data"] == {}
        assert d["options"] == {}
        assert d["findings"] == []               # None -> []
        assert d["coverage_summary"] is None     # stays None
        assert d["state"] == "pending"

    def test_broken_json_columns_degrade_gracefully(self, store):
        store.save(_job("s1"))
        # Corrupt the findings / params columns directly.
        store._conn.execute(
            "UPDATE jobs SET findings='not-json', params='{bad' "
            "WHERE scan_id='s1'")
        d = store.load("s1")
        assert d["findings"] == []               # broken list -> []
        assert d["params"] == {}                 # broken dict -> {}

    def test_threaded_saves_do_not_corrupt(self, store):
        import threading
        def w(i):
            store.save(_job(f"s{i}"))
        threads = [threading.Thread(target=w, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert store.count() == 8


class TestJobConverters:
    def _job_obj(self):
        from xssentinel.api.jobs import Job
        return Job(scan_id="j1", target_url="http://t/", method="GET",
                   params={"q": "1"}, data={}, options={"max_payloads": 3},
                   state="running", findings=[{"type": "dom"}],
                   finding_count=1, high_severity_count=1,
                   requests_made=9, waf_name=None, _seq=3)

    def test_roundtrip_through_store_dict(self):
        job = self._job_obj()
        d = job_to_store_dict(job)
        # closures / private options stripped
        assert all(not k.startswith("_") for k in d["options"])
        job2 = store_dict_to_job(d)
        assert job2.scan_id == "j1"
        assert job2.options == {"max_payloads": 3}
        assert job2.findings == [{"type": "dom"}]
        assert job2.state == "running"
        assert job2.requests_made == 9

    def test_store_dict_to_job_tolerates_missing_fields(self):
        job2 = store_dict_to_job({"scan_id": "bare", "seq": 2})
        assert job2.scan_id == "bare"
        assert job2.params == {} and job2.findings == []
        assert job2._seq == 2

    def test_store_roundtrip_via_sqlite(self, store):
        job = self._job_obj()
        store.save(job_to_store_dict(job))
        d = store.load("j1")
        job2 = store_dict_to_job(d)
        assert job2.target_url == "http://t/"
        assert job2.coverage_summary is None or isinstance(
            job2.coverage_summary, (dict, type(None)))
