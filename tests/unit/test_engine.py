"""Task 2.3 verification: determinism, and 40+ hand-reasoned scenarios.

The expected verdicts below are written out by hand rather than blessed from a
run. A golden file that only records what the code already does proves the code
has not changed; it does not prove the code is right.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trilock.policy.decision import ToolCall, TrifectaState, Verdict
from trilock.policy.engine import DEFAULT_RULE_ID, SessionSnapshot, decide
from trilock.policy.model import Effect, Mode, Policy, ToolClass, load_policy, parse_policy
from trilock.taint.labels import IDENTITY, TOP, Sensitivity, SourceId, TaintLabel, TrustLevel
from trilock.taint.propagate import ArgumentMatch, Attribution

POLICIES = Path(__file__).resolve().parents[2] / "policies"
GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "engine_golden.json"

DEFAULT = load_policy(POLICIES / "default.yaml")
STRICT = load_policy(POLICIES / "strict.yaml")
MONITOR = load_policy(POLICIES / "monitor.yaml")

READS_UNTRUSTED = ToolClass(reads=TrustLevel.UNTRUSTED, sensitivity=Sensitivity.SENSITIVE)
EXTERNAL = ToolClass(effect=Effect.EXTERNAL)
INERT = ToolClass(reads=TrustLevel.TRUSTED)

SOURCE = SourceId(server="mail", tool="search", call_id="01JZ", seq=0)
TAINTED = Attribution(
    matches=(
        ArgumentMatch(path="$.body", sources=frozenset({SOURCE}), evidence="ngram", strength=0.9),
    ),
    label=TaintLabel(trust=TrustLevel.UNTRUSTED, sources=frozenset({SOURCE})),
    complete=True,
)
CLEAN = Attribution()
INCOMPLETE = Attribution(complete=False)


def snap(
    *,
    untrusted: bool = False,
    sensitive: bool = False,
    external: bool = False,
    classification: ToolClass | None = INERT,
    attribution: Attribution = CLEAN,
    scope_violation: bool = False,
    scores: dict[str, float] | None = None,
) -> SessionSnapshot:
    return SessionSnapshot(
        trifecta=TrifectaState(untrusted, sensitive, external),
        attribution=attribution,
        classification=classification,
        session_label=TOP if (untrusted and sensitive) else IDENTITY,
        detector_scores=scores or {},
        scope_violation=scope_violation,
    )


class Scenario(NamedTuple):
    name: str
    policy: Policy
    call: ToolCall
    session: SessionSnapshot
    verdict: Verdict
    rule_id: str


CALL = ToolCall(tool="mail.send", arguments={"to": "a@b.c", "body": "x"}, call_id="01J")
READ = ToolCall(tool="mail.search", arguments={"query": "x"}, call_id="01K")

SCENARIOS: list[Scenario] = [
    # -- the headline case: the demo attack ------------------------------
    Scenario(
        "demo attack: tainted egress from a sensitive session",
        DEFAULT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=TAINTED,
        ),
        Verdict.DENY,
        "tainted_egress",
    ),
    Scenario(
        "demo attack in strict: refused by rule of two, not attribution",
        STRICT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=TAINTED,
        ),
        Verdict.DENY,
        "rule_of_two",
    ),
    Scenario(
        "demo attack in monitor: allowed but recorded",
        MONITOR,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=TAINTED,
        ),
        Verdict.ALLOW,
        "monitor:tainted_egress",
    ),
    # -- three legs, clean arguments: dataflow's whole point --------------
    Scenario(
        "three legs but arguments provably clean: dataflow escalates, not denies",
        DEFAULT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=CLEAN,
        ),
        Verdict.ESCALATE,
        "rule_of_two",
    ),
    Scenario(
        "three legs, clean arguments, strict: still refused",
        STRICT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=CLEAN,
        ),
        Verdict.DENY,
        "rule_of_two",
    ),
    Scenario(
        "three legs, incomplete attribution: treated as tainted",
        DEFAULT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=INCOMPLETE,
        ),
        Verdict.DENY,
        "tainted_egress",
    ),
    # -- two legs is safe --------------------------------------------------
    Scenario(
        "untrusted + external, no sensitive data: two legs, allowed",
        DEFAULT,
        CALL,
        snap(untrusted=True, external=True, classification=EXTERNAL, attribution=TAINTED),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "sensitive + external, no untrusted input: two legs, allowed",
        DEFAULT,
        CALL,
        snap(sensitive=True, external=True, classification=EXTERNAL),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "untrusted + sensitive, no external action: two legs, allowed",
        DEFAULT,
        READ,
        snap(untrusted=True, sensitive=True, classification=READS_UNTRUSTED),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "two legs in strict is still allowed",
        STRICT,
        CALL,
        snap(untrusted=True, external=True, classification=EXTERNAL),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    # -- one leg and none ---------------------------------------------------
    Scenario(
        "one leg: external only",
        DEFAULT,
        CALL,
        snap(external=True, classification=EXTERNAL),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "one leg: untrusted only",
        DEFAULT,
        READ,
        snap(untrusted=True, classification=READS_UNTRUSTED),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "one leg: sensitive only",
        DEFAULT,
        READ,
        snap(sensitive=True, classification=INERT),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario("no legs at all", DEFAULT, READ, snap(), Verdict.ALLOW, "fewer_than_three_legs"),
    Scenario("no legs, strict", STRICT, READ, snap(), Verdict.ALLOW, "fewer_than_three_legs"),
    # -- scope violations come first ---------------------------------------
    Scenario(
        "scope violation outranks everything",
        DEFAULT,
        CALL,
        snap(external=True, classification=EXTERNAL, scope_violation=True),
        Verdict.DENY,
        "scope_violation",
    ),
    Scenario(
        "scope violation with zero other legs is still a deny",
        DEFAULT,
        CALL,
        snap(classification=EXTERNAL, scope_violation=True),
        Verdict.DENY,
        "scope_violation",
    ),
    Scenario(
        "scope violation in strict",
        STRICT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            scope_violation=True,
        ),
        Verdict.DENY,
        "scope_violation",
    ),
    Scenario(
        "scope violation in monitor is recorded, not enforced",
        MONITOR,
        CALL,
        snap(classification=EXTERNAL, scope_violation=True),
        Verdict.ALLOW,
        "monitor:scope_violation",
    ),
    # -- unclassified tools --------------------------------------------------
    Scenario(
        "unclassified tool escalates in dataflow",
        DEFAULT,
        ToolCall(tool="weird.thing"),
        snap(classification=None),
        Verdict.ESCALATE,
        "unclassified_tool",
    ),
    Scenario(
        "unclassified tool is denied in strict",
        STRICT,
        ToolCall(tool="weird.thing"),
        snap(classification=None),
        Verdict.DENY,
        "unclassified_tool",
    ),
    Scenario(
        "unclassified tool with three legs: rule of two fires first",
        DEFAULT,
        ToolCall(tool="weird.thing"),
        snap(untrusted=True, sensitive=True, external=True, classification=None),
        Verdict.ESCALATE,
        "rule_of_two",
    ),
    Scenario(
        "unclassified tool in monitor",
        MONITOR,
        ToolCall(tool="weird.thing"),
        snap(classification=None),
        Verdict.ALLOW,
        "monitor:unclassified_tool",
    ),
    # -- tainted egress needs all three conditions ---------------------------
    Scenario(
        "external + tainted args but session never touched sensitive data",
        DEFAULT,
        CALL,
        snap(untrusted=True, external=True, classification=EXTERNAL, attribution=TAINTED),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "sensitive session + tainted args but the call is not external",
        DEFAULT,
        READ,
        snap(untrusted=True, sensitive=True, classification=READS_UNTRUSTED, attribution=TAINTED),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    # -- an empty policy denies everything ------------------------------------
    Scenario(
        "empty policy: terminal deny", parse_policy({}), CALL, snap(), Verdict.DENY, DEFAULT_RULE_ID
    ),
    Scenario(
        "empty policy denies even a harmless read",
        parse_policy({}),
        READ,
        snap(),
        Verdict.DENY,
        DEFAULT_RULE_ID,
    ),
    Scenario(
        "empty monitor policy records the terminal deny",
        parse_policy({"mode": "monitor"}),
        CALL,
        snap(),
        Verdict.ALLOW,
        f"monitor:{DEFAULT_RULE_ID}",
    ),
    # -- tool-name globs in rules ----------------------------------------------
    Scenario(
        "a rule scoped to a tool glob fires only for that glob",
        parse_policy(
            {
                "rules": [
                    {"id": "no_mail", "when": {"tool": "mail.*"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        snap(),
        Verdict.DENY,
        "no_mail",
    ),
    Scenario(
        "the same policy allows a tool outside the glob",
        parse_policy(
            {
                "rules": [
                    {"id": "no_mail", "when": {"tool": "mail.*"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        ToolCall(tool="notes.write"),
        snap(),
        Verdict.ALLOW,
        "rest",
    ),
    # -- first match wins -------------------------------------------------------
    Scenario(
        "an earlier rule shadows a later one",
        parse_policy(
            {
                "rules": [
                    {"id": "first", "when": {"trifecta_legs": 0}, "then": "escalate"},
                    {"id": "second", "when": {"trifecta_legs": 0}, "then": "deny"},
                ]
            }
        ),
        CALL,
        snap(),
        Verdict.ESCALATE,
        "first",
    ),
    # -- detector scores may only tighten ---------------------------------------
    Scenario(
        "a high detector score raises an allow to an escalate",
        DEFAULT,
        CALL,
        snap(external=True, classification=EXTERNAL, scores={"promptguard": 0.97}),
        Verdict.ESCALATE,
        "fewer_than_three_legs",
    ),
    Scenario(
        "a low detector score changes nothing",
        DEFAULT,
        CALL,
        snap(external=True, classification=EXTERNAL, scores={"promptguard": 0.2}),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    Scenario(
        "a high detector score cannot soften a deny",
        DEFAULT,
        CALL,
        snap(
            untrusted=True,
            sensitive=True,
            external=True,
            classification=EXTERNAL,
            attribution=TAINTED,
            scores={"promptguard": 0.99},
        ),
        Verdict.DENY,
        "tainted_egress",
    ),
    Scenario(
        "detector scores are ignored entirely in monitor mode",
        MONITOR,
        CALL,
        snap(external=True, classification=EXTERNAL, scores={"promptguard": 0.99}),
        Verdict.ALLOW,
        "fewer_than_three_legs",
    ),
    # -- explicit detector rules ------------------------------------------------
    Scenario(
        "a rule keyed on a detector fires when it scores above the threshold",
        parse_policy(
            {
                "rules": [
                    {"id": "flagged", "when": {"detector_above": {"pg": 0.5}}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        snap(scores={"pg": 0.8}),
        Verdict.DENY,
        "flagged",
    ),
    Scenario(
        "a missing detector score never satisfies a threshold",
        parse_policy(
            {
                "rules": [
                    {"id": "flagged", "when": {"detector_above": {"pg": 0.5}}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        snap(scores={}),
        Verdict.ALLOW,
        "rest",
    ),
    Scenario(
        "a detector rule needs every named detector above threshold",
        parse_policy(
            {
                "rules": [
                    {
                        "id": "flagged",
                        "when": {"detector_above": {"pg": 0.5, "heur": 0.5}},
                        "then": "deny",
                    },
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        # 0.6 clears the rule's own threshold but not the global advisory floor,
        # so this isolates the "every named detector" semantics.
        snap(scores={"pg": 0.6}),
        Verdict.ALLOW,
        "rest",
    ),
    Scenario(
        "the advisory floor still applies when a detector rule does not fire",
        parse_policy(
            {
                "rules": [
                    {
                        "id": "flagged",
                        "when": {"detector_above": {"pg": 0.5, "heur": 0.5}},
                        "then": "deny",
                    },
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        snap(scores={"pg": 0.95}),
        Verdict.ESCALATE,
        "rest",
    ),
    # -- strict ignores attribution ----------------------------------------------
    Scenario(
        "strict treats clean arguments as tainted when the session is",
        parse_policy(
            {
                "mode": "strict",
                "rules": [
                    {"id": "taint", "when": {"args_tainted_by": "untrusted"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ],
            }
        ),
        CALL,
        snap(untrusted=True, attribution=CLEAN),
        Verdict.DENY,
        "taint",
    ),
    Scenario(
        "dataflow trusts clean attribution where strict does not",
        parse_policy(
            {
                "mode": "dataflow",
                "rules": [
                    {"id": "taint", "when": {"args_tainted_by": "untrusted"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ],
            }
        ),
        CALL,
        snap(untrusted=True, attribution=CLEAN),
        Verdict.ALLOW,
        "rest",
    ),
    Scenario(
        "dataflow falls back to session level once the ledger is incomplete",
        parse_policy(
            {
                "mode": "dataflow",
                "rules": [
                    {"id": "taint", "when": {"args_tainted_by": "untrusted"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ],
            }
        ),
        CALL,
        snap(untrusted=True, attribution=INCOMPLETE),
        Verdict.DENY,
        "taint",
    ),
    Scenario(
        "strict with no untrusted input still allows",
        parse_policy(
            {
                "mode": "strict",
                "rules": [
                    {"id": "taint", "when": {"args_tainted_by": "untrusted"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ],
            }
        ),
        CALL,
        snap(attribution=CLEAN),
        Verdict.ALLOW,
        "rest",
    ),
    # -- effect conditions --------------------------------------------------------
    Scenario(
        "an effect condition does not fire for an inert tool",
        parse_policy(
            {
                "rules": [
                    {"id": "ext", "when": {"effect": "external"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        READ,
        snap(classification=INERT),
        Verdict.ALLOW,
        "rest",
    ),
    Scenario(
        "an effect condition fires for an external tool",
        parse_policy(
            {
                "rules": [
                    {"id": "ext", "when": {"effect": "external"}, "then": "deny"},
                    {"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"},
                ]
            }
        ),
        CALL,
        snap(classification=EXTERNAL),
        Verdict.DENY,
        "ext",
    ),
]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_scenario(scenario: Scenario) -> None:
    decision = decide(scenario.call, scenario.session, scenario.policy)
    assert decision.verdict is scenario.verdict, (
        f"{scenario.name}: expected {scenario.verdict}, got {decision.verdict} "
        f"via rule {decision.rule_id!r}\nreasons: {decision.reasons}"
    )
    assert decision.rule_id == scenario.rule_id, (
        f"{scenario.name}: expected rule {scenario.rule_id!r}, got {decision.rule_id!r}"
    )
    assert decision.reasons, "every decision must be explainable"


def test_the_scenario_suite_is_large_enough() -> None:
    assert len(SCENARIOS) >= 40, f"the spec requires 40+ scenarios, got {len(SCENARIOS)}"
    assert len({s.name for s in SCENARIOS}) == len(SCENARIOS), "scenario names must be unique"


# -- determinism (Hard Rule 4) -----------------------------------------------

trust_levels = st.sampled_from(list(TrustLevel))
sensitivities = st.sampled_from(list(Sensitivity))
effects = st.sampled_from(list(Effect))

tool_classes = st.one_of(
    st.none(),
    st.builds(
        ToolClass,
        reads=st.one_of(st.none(), trust_levels),
        sensitivity=sensitivities,
        effect=effects,
    ),
)

source_ids = st.builds(
    SourceId,
    server=st.sampled_from(["mail", "web", "fs"]),
    tool=st.sampled_from(["search", "fetch", "read"]),
    call_id=st.sampled_from(["01A", "01B"]),
    seq=st.integers(0, 20),
)

attributions = st.builds(
    Attribution,
    matches=st.lists(
        st.builds(
            ArgumentMatch,
            path=st.sampled_from(["$.body", "$.to", "$.items[0]"]),
            sources=st.frozensets(source_ids, min_size=1, max_size=2),
            evidence=st.sampled_from(["ngram", "exact-token", "base64"]),
            strength=st.floats(0.0, 1.0, allow_nan=False),
        ),
        max_size=3,
    ).map(tuple),
    label=st.builds(
        TaintLabel,
        trust=trust_levels,
        sensitivity=sensitivities,
        sources=st.frozensets(source_ids, max_size=2),
    ),
    complete=st.booleans(),
)

snapshots = st.builds(
    SessionSnapshot,
    trifecta=st.builds(TrifectaState, st.booleans(), st.booleans(), st.booleans()),
    attribution=attributions,
    classification=tool_classes,
    session_label=st.builds(TaintLabel, trust=trust_levels, sensitivity=sensitivities),
    detector_scores=st.dictionaries(
        st.sampled_from(["heuristics", "promptguard"]),
        st.floats(0.0, 1.0, allow_nan=False),
        max_size=2,
    ),
    scope_violation=st.booleans(),
    normalisation_removed=st.integers(0, 500),
)

calls = st.builds(
    ToolCall,
    tool=st.sampled_from(
        ["mail.send", "mail.search", "notes.write_note", "weird.thing", "fs.write"]
    ),
    arguments=st.just({}),
    call_id=st.sampled_from(["01A", "01B"]),
)

policies = st.sampled_from(
    [DEFAULT, STRICT, MONITOR, load_policy(POLICIES / "dataflow.yaml"), parse_policy({})]
)


@settings(max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(call=calls, session=snapshots, policy=policies)
def test_decide_is_deterministic(call: ToolCall, session: SessionSnapshot, policy: Policy) -> None:
    """Same call, same session, same policy -> same decision. Always.

    This is what makes `trilock replay` able to re-derive history, and what
    makes the core an interlock rather than a classifier.
    """
    first = decide(call, session, policy)
    second = decide(call, session, policy)
    assert first == second


@settings(max_examples=800, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(call=calls, session=snapshots, policy=policies)
def test_every_decision_names_a_rule_and_explains_itself(
    call: ToolCall, session: SessionSnapshot, policy: Policy
) -> None:
    decision = decide(call, session, policy)
    assert decision.rule_id
    assert decision.reasons
    known = {r.id for r in policy.rules} | {DEFAULT_RULE_ID}
    bare = decision.rule_id.removeprefix("monitor:")
    assert bare in known, f"decision named an unknown rule {decision.rule_id!r}"


@settings(max_examples=800, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(call=calls, session=snapshots)
def test_monitor_mode_never_blocks(call: ToolCall, session: SessionSnapshot) -> None:
    assert decide(call, session, MONITOR).verdict is Verdict.ALLOW


@settings(max_examples=800, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(call=calls, session=snapshots)
def test_decide_does_not_mutate_its_inputs(call: ToolCall, session: SessionSnapshot) -> None:
    before = (repr(call), repr(session))
    decide(call, session, DEFAULT)
    assert (repr(call), repr(session)) == before


# -- golden file --------------------------------------------------------------


def _golden_payload() -> list[dict[str, Any]]:
    return [
        {
            "name": s.name,
            "policy": s.policy.mode.value + ":" + ",".join(r.id for r in s.policy.rules),
            "tool": s.call.tool,
            "decision": decide(s.call, s.session, s.policy).to_json(),
        }
        for s in SCENARIOS
    ]


def test_golden_decisions_are_unchanged() -> None:
    """Regression net over the *whole* Decision, not just verdict and rule id.

    Regenerate deliberately with:
        uv run python -c "from tests.unit.test_engine import _write_golden; _write_golden()"
    """
    current = _golden_payload()
    if not GOLDEN.is_file():  # pragma: no cover - first run only
        _write_golden()
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert len(current) == len(expected), "scenario count changed; regenerate the golden file"
    for got, want in zip(current, expected, strict=True):
        assert got == want, f"decision changed for {got['name']!r}"


def _write_golden() -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(
        json.dumps(_golden_payload(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


# -- the unclassified floor ---------------------------------------------------


def test_the_unclassified_floor_applies_even_when_no_rule_mentions_it() -> None:
    """Regression: `unclassified:` must be a control, not decoration.

    A policy that sets `unclassified: escalate` but whose rules end in a broad
    `allow` was letting unclassified tools straight through — the field that
    exists to prevent exactly that had no effect on the decision at all.
    """
    policy = parse_policy(
        {
            "unclassified": "escalate",
            "rules": [{"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"}],
        }
    )
    classified = decide(READ, snap(classification=INERT), policy)
    assert classified.verdict is Verdict.ALLOW

    unknown = decide(ToolCall(tool="weird.thing"), snap(classification=None), policy)
    assert unknown.verdict is Verdict.ESCALATE
    assert unknown.rule_id == "rest"
    assert any("nobody has reasoned about" in r for r in unknown.reasons)


def test_the_floor_only_tightens() -> None:
    """A rule may make an unclassified tool stricter than the floor."""
    policy = parse_policy(
        {
            "unclassified": "escalate",
            "rules": [{"id": "hard_no", "when": {"unclassified": True}, "then": "deny"}],
        }
    )
    assert decide(ToolCall(tool="x.y"), snap(classification=None), policy).verdict is Verdict.DENY


def test_the_floor_defaults_by_mode_when_unset() -> None:
    strict = parse_policy(
        {"mode": "strict", "rules": [{"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"}]}
    )
    assert decide(ToolCall(tool="x.y"), snap(classification=None), strict).verdict is Verdict.DENY

    flow = parse_policy(
        {
            "mode": "dataflow",
            "rules": [{"id": "rest", "when": {"trifecta_legs": 0}, "then": "allow"}],
        }
    )
    assert decide(ToolCall(tool="x.y"), snap(classification=None), flow).verdict is Verdict.ESCALATE


@settings(max_examples=1500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(call=calls, session=snapshots, policy=policies)
def test_an_unclassified_tool_is_never_allowed_outside_monitor(
    call: ToolCall, session: SessionSnapshot, policy: Policy
) -> None:
    """The invariant the floor exists to guarantee."""
    if session.classification is not None or policy.mode is Mode.MONITOR:
        return
    assert decide(call, session, policy).verdict is not Verdict.ALLOW
