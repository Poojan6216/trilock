"""Task 2.2 verification: trifecta accounting over every ordering, plus reset."""

from __future__ import annotations

import itertools

import pytest

from trilock.policy.decision import TrifectaState
from trilock.policy.model import Effect, Sensitivity, ToolClass, parse_policy
from trilock.policy.trifecta import SessionRegistry, is_external
from trilock.taint.labels import TrustLevel, new_call_id
from trilock.taint.store import LedgerStore, SessionKey

KEY = SessionKey(kind="stdio-process", value="pid-test")

UNTRUSTED_TOOL = ToolClass(reads=TrustLevel.UNTRUSTED)
SENSITIVE_TOOL = ToolClass(reads=TrustLevel.TRUSTED, sensitivity=Sensitivity.SENSITIVE)
EXTERNAL_TOOL = ToolClass(effect=Effect.EXTERNAL)
BOTH_TOOL = ToolClass(reads=TrustLevel.UNTRUSTED, sensitivity=Sensitivity.SENSITIVE)


def fresh() -> SessionRegistry:
    return SessionRegistry(LedgerStore())


def test_legs_and_completeness() -> None:
    assert TrifectaState().legs == 0
    assert TrifectaState(untrusted_input=True).legs == 1
    assert TrifectaState(untrusted_input=True, sensitive_access=True).legs == 2
    full = TrifectaState(untrusted_input=True, sensitive_access=True, external_action=True)
    assert full.legs == 3
    assert full.complete
    assert not TrifectaState(untrusted_input=True, sensitive_access=True).complete


EVENTS = ["untrusted", "sensitive", "external"]


@pytest.mark.parametrize("order", list(itertools.permutations(EVENTS)), ids=lambda o: "-".join(o))
def test_every_ordering_of_the_three_events_reaches_three_legs(order: tuple[str, ...]) -> None:
    """Order must not matter: the trifecta is a set, not a sequence."""
    state = fresh().get(KEY)
    external = False
    for event in order:
        if event == "untrusted":
            state.record_result("s", "t", new_call_id(), ["attacker text"], UNTRUSTED_TOOL)
        elif event == "sensitive":
            state.record_result("s", "t", new_call_id(), ["private thread"], SENSITIVE_TOOL)
        else:
            external = True
    assert state.trifecta(external=external).legs == 3


@pytest.mark.parametrize(
    "order", list(itertools.permutations(EVENTS, 2)), ids=lambda o: "-".join(o)
)
def test_any_two_events_stop_at_two_legs(order: tuple[str, ...]) -> None:
    state = fresh().get(KEY)
    external = False
    for event in order:
        if event == "untrusted":
            state.record_result("s", "t", new_call_id(), ["attacker text"], UNTRUSTED_TOOL)
        elif event == "sensitive":
            state.record_result("s", "t", new_call_id(), ["private thread"], SENSITIVE_TOOL)
        else:
            external = True
    assert state.trifecta(external=external).legs == 2


def test_the_ingress_legs_are_monotonic() -> None:
    """A session that has read attacker text has read it. Forever."""
    state = fresh().get(KEY)
    state.record_result("s", "t", new_call_id(), ["attacker text"], UNTRUSTED_TOOL)
    state.record_result("s", "t", new_call_id(), ["private"], SENSITIVE_TOOL)
    assert state.untrusted_input and state.sensitive_access
    for _ in range(10):
        state.record_result(
            "s", "t", new_call_id(), ["harmless"], ToolClass(reads=TrustLevel.TRUSTED)
        )
        assert state.untrusted_input, "an untrusted leg un-set itself"
        assert state.sensitive_access, "a sensitive leg un-set itself"


def test_external_is_per_call_not_per_session() -> None:
    """Sending one email must not bar the session from ever reading again."""
    state = fresh().get(KEY)
    state.record_result("s", "t", new_call_id(), ["attacker text"], UNTRUSTED_TOOL)
    assert state.trifecta(external=True).external_action
    assert not state.trifecta(external=False).external_action
    assert state.trifecta().legs == 1


def test_reset_is_the_only_way_a_leg_un_sets() -> None:
    registry = fresh()
    state = registry.get(KEY)
    state.record_result("s", "t", new_call_id(), ["attacker text"], BOTH_TOOL)
    assert state.trifecta().legs == 2

    registry.reset(KEY)
    reborn = registry.get(KEY)
    assert reborn is not state
    assert reborn.trifecta().legs == 0
    assert len(reborn.ledger) == 0


def test_one_result_can_set_two_legs_at_once() -> None:
    state = fresh().get(KEY)
    state.record_result("s", "mail.search", new_call_id(), ["private + attacker text"], BOTH_TOOL)
    assert state.trifecta().legs == 2


def test_unclassified_output_sets_the_untrusted_leg() -> None:
    state = fresh().get(KEY)
    state.record_result("s", "t", new_call_id(), ["who knows"], None)
    assert state.untrusted_input
    assert not state.sensitive_access


def test_is_external_does_not_assume_unclassified_is_safe() -> None:
    assert is_external(EXTERNAL_TOOL)
    assert not is_external(ToolClass())
    # An unclassified tool has no declared effect, so `is_external` is False —
    # but policy never *allows* an unclassified tool, so it is not a hole.
    assert not is_external(None)
    assert parse_policy({}).unclassified_verdict.value != "allow"


def test_sessions_are_independent() -> None:
    registry = fresh()
    a = registry.get(SessionKey(kind="mcp-session", value="a"))
    b = registry.get(SessionKey(kind="mcp-session", value="b"))
    a.record_result("s", "t", new_call_id(), ["attacker"], BOTH_TOOL)
    assert a.trifecta().legs == 2
    assert b.trifecta().legs == 0


def test_with_external_preserves_the_other_legs() -> None:
    base = TrifectaState(untrusted_input=True, sensitive_access=True)
    assert base.with_external(True) == TrifectaState(True, True, True)
    assert base.with_external(False) == base
    assert base.with_external(True).with_external(False) == base
