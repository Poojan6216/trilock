"""Taint persists on what an agent writes and re-attaches when it is read back."""

from __future__ import annotations

import json
from pathlib import Path

from trilock.taint.labels import IDENTITY, TOP, Sensitivity, TaintLabel, TrustLevel
from trilock.taint.sinks import SinkStore

UNTRUSTED = TaintLabel(trust=TrustLevel.UNTRUSTED)


def test_a_tainted_write_taints_a_later_read_of_the_same_identifier() -> None:
    sinks = SinkStore()
    assert sinks.record("memory.store", {"key": "k1", "value": "hunter2"}, TOP) == 2
    assert sinks.lookup({"key": "k1"}) == TOP
    assert sinks.lookup({"key": "other"}) == IDENTITY


def test_a_clean_write_records_nothing() -> None:
    sinks = SinkStore()
    assert (
        sinks.record("notes.write_note", {"name": "plan.md", "content": "ship it"}, IDENTITY) == 0
    )
    assert len(sinks) == 0


def test_identifiers_are_stored_hashed_never_raw(tmp_path: Path) -> None:
    path = tmp_path / "sinks.json"
    sinks = SinkStore(path)
    sinks.record("memory.store", {"key": "k1", "value": "hunter2-STAGING-9f31"}, TOP)
    sinks.save()
    text = path.read_text()
    assert "hunter2" not in text and "k1" not in text
    assert json.loads(text)["sinks"]


def test_sinks_survive_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "sinks.json"
    SinkStore(path).record("memory.store", {"key": "k1", "value": "x"}, UNTRUSTED)
    first = SinkStore(path)
    first.record("memory.store", {"key": "k1", "value": "x"}, UNTRUSTED)
    first.save()
    reloaded = SinkStore(path)
    assert reloaded.lookup({"key": "k1"}).is_untrusted


def test_ttl_expires_and_bound_holds() -> None:
    sinks = SinkStore(max_entries=3, ttl_s=0.0)
    sinks.record("t", {"a": "one", "b": "two"}, UNTRUSTED)
    # ttl 0: already expired on lookup
    assert sinks.lookup({"a": "one"}) == IDENTITY
    bounded = SinkStore(max_entries=2)
    bounded.record("t", {"a": "one", "b": "two", "c": "three"}, UNTRUSTED)
    assert len(bounded) == 2


def test_join_toward_danger_on_re_record() -> None:
    sinks = SinkStore()
    sinks.record("t", {"k": "key1"}, UNTRUSTED)
    sinks.record("t", {"k": "key1"}, TaintLabel(sensitivity=Sensitivity.SENSITIVE))
    assert sinks.lookup({"k": "key1"}) == TOP


def test_single_characters_are_not_identifiers() -> None:
    sinks = SinkStore()
    assert sinks.record("t", {"k": "a"}, TOP) == 0
    assert sinks.record("t", {"k": "k1"}, TOP) == 1
