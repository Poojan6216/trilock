"""Task 1.2 verification: the ledger is bounded, and eviction only ever widens.

The headline test is `test_a_denied_call_stays_denied_after_eviction`: if
forgetting a source could turn a DENY into an ALLOW, an attacker exfiltrates by
being patient — flood the ledger with benign results until the poisoned one
falls out, then retry the call that was refused.
"""

from __future__ import annotations

from trilock.taint.labels import (
    IDENTITY,
    TOP,
    Sensitivity,
    TaintLabel,
    TrustLevel,
    new_call_id,
)
from trilock.taint.store import LedgerStore, SessionKey, SessionLedger

UNTRUSTED = TaintLabel(trust=TrustLevel.UNTRUSTED)
SENSITIVE = TaintLabel(sensitivity=Sensitivity.SENSITIVE)
KEY = SessionKey(kind="mcp-session", value="s-1")


def ledger(max_sources: int = 500) -> SessionLedger:
    return SessionLedger(key=KEY, max_sources=max_sources)


def test_records_are_ordered_and_hashed_not_stored() -> None:
    led = ledger()
    entry = led.record("mail", "search", new_call_id(), "the quick brown fox jumps over", UNTRUSTED)
    assert entry.source.seq == 0
    assert entry.source.server == "mail"
    assert len(entry.content_hash) == 64
    assert entry.length == len("the quick brown fox jumps over")
    assert entry.ngrams  # a fingerprint, not the text
    rendered = entry.to_json()
    assert "fox" not in str(rendered)
    assert rendered["ngrams"] == len(entry.ngrams)

    second = led.record("notes", "read_note", new_call_id(), "another", IDENTITY)
    assert second.source.seq == 1
    assert len(led) == 2


def test_session_label_joins_everything_ingested() -> None:
    led = ledger()
    assert led.session_label() == IDENTITY
    led.record("mail", "search", new_call_id(), "untrusted mail body", UNTRUSTED)
    assert led.session_label().is_untrusted
    assert not led.session_label().is_sensitive
    led.record("mail", "drafts", new_call_id(), "private thread", SENSITIVE)
    assert led.session_label().is_untrusted and led.session_label().is_sensitive


def test_the_ledger_is_bounded() -> None:
    led = ledger(max_sources=10)
    for i in range(50):
        led.record("web", "fetch", new_call_id(), f"benign document number {i}", IDENTITY)
    assert len(led) == 10
    assert led.evicted_count == 40


def test_a_denied_call_stays_denied_after_eviction() -> None:
    """Eviction must widen, never narrow. This is the flood-to-launder attack."""
    led = ledger(max_sources=5)
    led.record("mail", "search", new_call_id(), "attacker controlled instruction", TOP)
    before = led.session_label()
    assert before.is_untrusted and before.is_sensitive

    # Flood with benign content until the poisoned source is evicted.
    for i in range(50):
        led.record("web", "fetch", new_call_id(), f"harmless page {i}", IDENTITY)
    assert led.evicted_count > 0

    after = led.session_label()
    assert after.dominates(before), "eviction narrowed the session label — laundering is possible"
    assert after.is_untrusted and after.is_sensitive
    assert not led.attribution_complete, "a negative attribution must stop being evidence"


def test_eviction_is_lru_and_touch_keeps_a_source_alive() -> None:
    led = ledger(max_sources=3)
    keep = led.record("mail", "search", new_call_id(), "keep me around", UNTRUSTED)
    for i in range(2):
        led.record("web", "fetch", new_call_id(), f"page {i}", IDENTITY)
    led.touch(keep.source)  # most recently used again
    led.record("web", "fetch", new_call_id(), "one more page", IDENTITY)
    assert keep.source in led.entries
    assert led.evicted_count == 1


def test_attribution_complete_latches_false() -> None:
    led = ledger(max_sources=1)
    assert led.attribution_complete
    led.record("web", "fetch", new_call_id(), "a", IDENTITY)
    assert led.attribution_complete
    led.record("web", "fetch", new_call_id(), "b", IDENTITY)
    assert not led.attribution_complete
    # It never latches back, even though nothing further is evicted.
    for _ in range(3):
        led.record("web", "fetch", new_call_id(), "c", IDENTITY)
    assert not led.attribution_complete


def test_untrusted_sources_are_reported() -> None:
    led = ledger()
    a = led.record("mail", "search", new_call_id(), "x", UNTRUSTED)
    led.record("fs", "read", new_call_id(), "y", SENSITIVE)
    assert led.untrusted_sources() == frozenset({a.source})


def test_store_keys_sessions_and_bounds_them() -> None:
    store = LedgerStore(max_sources=4, max_sessions=2)
    a = store.get(SessionKey(kind="mcp-session", value="a"))
    b = store.get(SessionKey(kind="connection", value="b"))
    assert store.get(SessionKey(kind="mcp-session", value="a")) is a
    assert a is not b
    assert len(store) == 2

    store.get(SessionKey(kind="mcp-session", value="c"))
    assert len(store) == 2
    # Re-reading 'a' above made it most recently used, so 'b' is the eviction
    # victim: 'a' survives and 'b' comes back as a fresh ledger.
    assert store.get(SessionKey(kind="mcp-session", value="a")) is a
    assert store.get(SessionKey(kind="connection", value="b")) is not b


def test_reset_is_the_only_way_a_session_forgets() -> None:
    store = LedgerStore()
    led = store.get(KEY)
    led.record("mail", "search", new_call_id(), "untrusted", TOP)
    assert store.get(KEY).session_label().is_untrusted
    store.reset(KEY)
    assert store.get(KEY).session_label() == IDENTITY


def test_session_key_records_which_assumption_was_used() -> None:
    assert str(SessionKey(kind="mcp-session", value="abc")) == "mcp-session:abc"
    assert str(SessionKey(kind="connection", value="pid-1")) == "connection:pid-1"
    assert SessionKey(kind="mcp-session", value="x") != SessionKey(kind="connection", value="x")
