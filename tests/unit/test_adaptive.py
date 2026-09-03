"""The adaptive attacker is a test too (BUILD_SPEC 6.3).

If every attack scores zero the red team is broken, not the defence. And
strict must never lose a scenario that dataflow wins — that ordering is the
entire justification for having two modes.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bench.adaptive.attacker import run_scenario
from bench.adaptive.strategies import ALL_STRATEGIES, all_scenarios

from trilock.policy.model import Mode

SCENARIOS = all_scenarios()
HUMANS = ("none", "attentive", "tired")


@pytest.fixture(scope="module")
def results() -> dict[tuple[str, str, Mode, str], bool]:
    out: dict[tuple[str, str, Mode, str], bool] = {}
    for scenario in SCENARIOS:
        for mode in (Mode.DATAFLOW, Mode.STRICT):
            for human in HUMANS:
                out[(scenario.strategy, scenario.name, mode, human)] = run_scenario(
                    scenario, mode, human=human
                )["success"]
    return out


def test_every_strategy_produces_scenarios() -> None:
    names = {fn.__name__ for fn in ALL_STRATEGIES}
    assert {s.strategy for s in SCENARIOS} >= names - {"encodings"} | {"encoding"}
    assert len(SCENARIOS) >= 30


def test_the_red_team_is_not_too_weak(results: dict[tuple[str, str, Mode, str], bool]) -> None:
    """At least one attack must land.

    A defence that reports zero against its own red team is reporting a broken
    red team (BUILD_SPEC 6.3).
    """
    assert any(results.values()), "no adaptive attack succeeded anywhere; the attacker is too weak"


def test_strict_is_never_weaker_than_dataflow(
    results: dict[tuple[str, str, Mode, str], bool],
) -> None:
    """For every scenario and human, a strict win implies a dataflow win."""
    for scenario in SCENARIOS:
        for human in HUMANS:
            strict = results[(scenario.strategy, scenario.name, Mode.STRICT, human)]
            flow = results[(scenario.strategy, scenario.name, Mode.DATAFLOW, human)]
            assert not (strict and not flow), (
                f"{scenario.strategy}/{scenario.name} [{human}]: strict lost where dataflow held"
            )


def test_the_attribution_seam_is_real_and_strict_closes_it(
    results: dict[tuple[str, str, Mode, str], bool],
) -> None:
    """Paraphrase and encoding beat dataflow with an attentive human, and never beat strict."""
    for strategy in ("paraphrase", "encoding"):
        flow_wins = [
            k
            for k, v in results.items()
            if k[0] == strategy and k[2] is Mode.DATAFLOW and k[3] == "attentive" and v
        ]
        strict_wins = [
            k for k, v in results.items() if k[0] == strategy and k[2] is Mode.STRICT and v
        ]
        assert flow_wins, (
            f"{strategy}: expected dataflow to lose some scenarios to an attentive human"
        )
        assert not strict_wins, f"{strategy}: strict lost {strict_wins}"


def test_naming_the_destination_in_the_injection_is_always_denied(
    results: dict[tuple[str, str, Mode, str], bool],
) -> None:
    assert not any(v for k, v in results.items() if k[0] == "destination_leak")


def test_session_splitting_beats_both_modes_and_is_documented(
    results: dict[tuple[str, str, Mode, str], bool],
) -> None:
    """A structural loss. It must stay visible in the results, not be quietly fixed away."""
    wins = [k for k, v in results.items() if k[0] == "session_splitting" and v]
    assert wins, (
        "session splitting no longer succeeds; update docs/threat-model.md and "
        "RESULTS.md if that is deliberate"
    )
    text = (Path(__file__).resolve().parents[2] / "docs" / "threat-model.md").read_text(
        encoding="utf-8"
    )
    assert "session" in text.lower() and "weakest" in text.lower()


def test_asr_table_shape() -> None:
    tally: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for scenario in SCENARIOS[:6]:
        r = run_scenario(scenario, Mode.DATAFLOW, human="none")
        tally[(r["strategy"], r["mode"])].append(r["success"])
        assert r["trace"] and all("verdict" in t and "rule" in t for t in r["trace"])
    assert tally
