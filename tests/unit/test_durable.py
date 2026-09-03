"""Durable sessions: legs and fingerprints survive a reconnect; raw tokens never do."""

from __future__ import annotations

import json
import time
from pathlib import Path

from trilock.taint import durable
from trilock.taint.labels import TOP, TaintLabel, new_call_id
from trilock.taint.store import SessionKey, SessionLedger

KEY = SessionKey(kind="stdio-process", value="pid-1")
SECRET = "hunter2-STAGING-9f31"


def _ledger() -> SessionLedger:
    led = SessionLedger(key=KEY)
    led.record("mail", "search", new_call_id(), f"the password is {SECRET} do not share", TOP)
    led.record("notes", "list", new_call_id(), "plan.md", TaintLabel())
    return led


def test_snapshot_restores_legs_and_fingerprints() -> None:
    led = _ledger()
    snap = durable.snapshot(led, untrusted_input=True, sensitive_access=True)
    fresh = SessionLedger(key=KEY)
    untrusted, sensitive = durable.restore(fresh, snap)
    assert untrusted and sensitive
    assert len(fresh) == 2 and fresh.seq == led.seq
    restored = next(iter(fresh))
    assert restored.ngrams == next(iter(led)).ngrams
    assert fresh.session_label().is_untrusted and fresh.session_label().is_sensitive


def test_snapshot_never_carries_raw_tokens_or_content(tmp_path: Path) -> None:
    store = durable.DurableSessions(tmp_path)
    store.save("k", durable.snapshot(_ledger(), untrusted_input=True, sensitive_access=True))
    text = store.path_for("k").read_text()
    assert SECRET not in text and "password" not in text
    assert json.loads(text)["entries"][0]["exact_tokens" if False else "content_hash"]
    fresh = SessionLedger(key=KEY)
    durable.restore(fresh, json.loads(text))
    assert all(e.exact_tokens == frozenset() for e in fresh)


def test_restored_sessions_are_conservative_about_attribution() -> None:
    fresh = SessionLedger(key=KEY)
    durable.restore(
        fresh, durable.snapshot(_ledger(), untrusted_input=True, sensitive_access=False)
    )
    assert not fresh.attribution_complete, (
        "a restored ledger lost its exact tokens; it must not claim completeness"
    )


def test_ttl_expiry_starts_clean(tmp_path: Path) -> None:
    store = durable.DurableSessions(tmp_path, ttl_s=0.01)
    store.save("k", durable.snapshot(_ledger(), untrusted_input=True, sensitive_access=True))
    time.sleep(0.05)
    assert store.load("k") is None
    assert not store.path_for("k").exists()


def test_durable_key_is_per_user_and_config(tmp_path: Path) -> None:
    a = durable.durable_key(tmp_path / "a.yaml", user="alice")
    assert a == durable.durable_key(tmp_path / "a.yaml", user="alice")
    assert a != durable.durable_key(tmp_path / "b.yaml", user="alice")
    assert a != durable.durable_key(tmp_path / "a.yaml", user="bob")
