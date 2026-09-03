"""Task 4.1 verification: the detector budget is hard, and a hung detector is harmless.

Hard Rule 2 in executable form. A detector that never answers must not stretch
the request beyond the timeout, and its absence must not change a verdict —
because a missing score is neither "clean" nor "malicious", it is nothing.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

import anyio
import pytest

from tests.unit.test_engine import POLICIES
from trilock.detect.base import DetectorOutcome, merge_scores, run_detectors
from trilock.policy.decision import ToolCall, TrifectaState, Verdict
from trilock.policy.engine import SessionSnapshot, decide
from trilock.policy.model import Effect, ToolClass, load_policy


class Hanging:
    name = "hanging"

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        await anyio.sleep(3600)
        return [1.0] * len(texts)


class Crashing:
    name = "crashing"

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        raise RuntimeError("model failed to load")


class Constant:
    def __init__(self, name: str, value: float | None, delay: float = 0.0) -> None:
        self.name = name
        self.value = value
        self.delay = delay

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        if self.delay:
            await anyio.sleep(self.delay)
        return [self.value] * len(texts)


class WrongLength:
    name = "wrong_length"

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        return [0.5]  # one score for many texts: malformed


async def test_a_hanging_detector_costs_at_most_the_timeout() -> None:
    started = time.perf_counter()
    outcomes = await run_detectors([Hanging()], ["some text"], timeout_ms=100)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"a hung detector held the pipeline for {elapsed:.2f}s"
    (outcome,) = outcomes
    assert outcome.timed_out
    assert outcome.score is None
    assert not outcome.ok


async def test_a_crashing_detector_is_skipped_not_fatal() -> None:
    (outcome,) = await run_detectors([Crashing()], ["x"], timeout_ms=100)
    assert outcome.error is not None
    assert "model failed to load" in outcome.error
    assert outcome.score is None


async def test_detectors_run_concurrently_not_serially() -> None:
    """Three detectors that each take 80 ms must finish in ~80 ms, not ~240."""
    started = time.perf_counter()
    outcomes = await run_detectors(
        [Constant("a", 0.1, 0.08), Constant("b", 0.2, 0.08), Constant("c", 0.3, 0.08)],
        ["x"],
        timeout_ms=1000,
    )
    elapsed = time.perf_counter() - started
    assert elapsed < 0.2, f"detectors ran serially: {elapsed:.2f}s"
    assert [o.score for o in outcomes] == [0.1, 0.2, 0.3]


async def test_one_hung_detector_does_not_starve_the_others() -> None:
    outcomes = await run_detectors([Hanging(), Constant("fast", 0.42)], ["x"], timeout_ms=100)
    by_name = {o.name: o for o in outcomes}
    assert by_name["hanging"].timed_out
    assert by_name["fast"].ok and by_name["fast"].score == 0.42


async def test_malformed_output_is_treated_as_no_score() -> None:
    (outcome,) = await run_detectors([WrongLength()], ["a", "b", "c"], timeout_ms=100)
    assert outcome.scores == (None, None, None)
    assert outcome.score is None


async def test_scores_are_clamped_and_nan_is_nothing() -> None:
    outcomes = await run_detectors(
        [Constant("big", 7.0), Constant("neg", -3.0), Constant("nan", float("nan"))],
        ["x"],
        timeout_ms=100,
    )
    by_name = {o.name: o.score for o in outcomes}
    assert by_name == {"big": 1.0, "neg": 0.0, "nan": None}


def test_merge_scores_drops_absent_detectors() -> None:
    merged = merge_scores(
        [
            DetectorOutcome("a", (0.2, 0.9), 1.0),
            DetectorOutcome("b", (None, None), 1.0, timed_out=True),
            DetectorOutcome("c", (None,), 1.0, error="boom"),
        ]
    )
    assert merged == {"a": 0.9}


async def test_empty_inputs_are_a_no_op() -> None:
    assert await run_detectors([], ["x"]) == ()
    assert await run_detectors([Constant("a", 0.5)], []) == ()


# -- the point of all of it: a hung detector never changes a verdict ----------


@pytest.mark.parametrize("policy_name", ["default", "strict"])
async def test_a_hung_detector_never_changes_a_verdict(policy_name: str) -> None:
    policy = load_policy(POLICIES / f"{policy_name}.yaml")
    call = ToolCall(tool="mail.send", arguments={"to": "a@b.c"})
    base = SessionSnapshot(
        trifecta=TrifectaState(True, True, True),
        classification=ToolClass(effect=Effect.EXTERNAL),
    )
    # What policy decides with no detectors at all.
    without = decide(call, base, policy)

    # What it decides when the only detector hung: its score is absent.
    (outcome,) = await run_detectors([Hanging()], ["content"], timeout_ms=50)
    with_hung = decide(
        call,
        SessionSnapshot(
            trifecta=base.trifecta,
            classification=base.classification,
            detector_scores=merge_scores([outcome]),
        ),
        policy,
    )
    assert with_hung.verdict is without.verdict
    assert with_hung.rule_id == without.rule_id
    assert without.verdict is not Verdict.ALLOW  # three legs: the guarantee holds either way
