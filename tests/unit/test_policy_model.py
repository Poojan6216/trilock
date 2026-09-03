"""Task 2.1 verification: policy validation, error quality, and round-tripping.

A security tool whose config fails open on a typo is not a security tool, so
every model forbids unknown keys and every rejection has to name the field and
say what to do about it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from trilock.policy.decision import Verdict
from trilock.policy.model import (
    UNCLASSIFIED_DEFAULTS,
    Effect,
    Mode,
    PolicyError,
    ToolClass,
    load_policy,
    parse_policy,
)
from trilock.taint.labels import Sensitivity, TrustLevel

POLICIES = Path(__file__).resolve().parents[2] / "policies"

MALFORMED: list[tuple[str, str, str]] = [
    (
        "unknown top-level key",
        "version: 1\nmodes: strict\n",
        "modes",
    ),
    (
        "unknown tool field",
        "version: 1\ntools:\n  a.b: {reeds: untrusted}\n",
        "reeds",
    ),
    (
        "unknown rule field",
        "version: 1\nrules:\n  - id: r\n    when: {effect: external}\n"
        "    then: deny\n    reason: x\n",
        "reason",
    ),
    (
        "unknown condition field",
        "version: 1\nrules:\n  - id: r\n    when: {legs: 3}\n    then: deny\n",
        "legs",
    ),
    ("bad mode", "version: 1\nmode: paranoid\n", "mode"),
    ("bad verdict", "version: 1\nunclassified: maybe\n", "unclassified"),
    ("unclassified allow", "version: 1\nunclassified: allow\n", "not permitted"),
    ("bad trust level", "version: 1\ntools:\n  a.b: {reads: sortof}\n", "reads"),
    ("bad sensitivity", "version: 1\ntools:\n  a.b: {sensitivity: quite}\n", "sensitivity"),
    ("bad effect", "version: 1\ntools:\n  a.b: {effect: sideways}\n", "effect"),
    ("bad version", "version: 2\n", "version"),
    (
        "empty rule condition",
        "version: 1\nrules:\n  - id: r\n    when: {}\n    then: deny\n",
        "must constrain something",
    ),
    (
        "duplicate rule id",
        "version: 1\nrules:\n"
        "  - id: r\n    when: {effect: external}\n    then: deny\n"
        "  - id: r\n    when: {effect: none}\n    then: allow\n",
        "duplicate rule id",
    ),
    (
        "rule id with bad characters",
        "version: 1\nrules:\n  - id: 'Rule One!'\n    when: {effect: external}\n    then: deny\n",
        "id",
    ),
    (
        "trifecta legs out of range",
        "version: 1\nrules:\n  - id: r\n    when: {trifecta_legs: 9}\n    then: deny\n",
        "trifecta_legs",
    ),
    (
        "negative trifecta legs",
        "version: 1\nrules:\n  - id: r\n    when: {trifecta_legs: -1}\n    then: deny\n",
        "trifecta_legs",
    ),
    ("rules not a list", "version: 1\nrules: {id: r}\n", "rules"),
    ("tools not a mapping", "version: 1\ntools: [a.b]\n", "tools"),
    ("missing rule id", "version: 1\nrules:\n  - when: {effect: external}\n    then: deny\n", "id"),
    ("missing rule then", "version: 1\nrules:\n  - id: r\n    when: {effect: external}\n", "then"),
    ("top level is a list", "- version: 1\n", "must be a mapping"),
]


@pytest.mark.parametrize(("label", "text", "expected"), MALFORMED, ids=[m[0] for m in MALFORMED])
def test_malformed_policies_produce_actionable_errors(label: str, text: str, expected: str) -> None:
    with pytest.raises(PolicyError) as caught:
        parse_policy(yaml.safe_load(text))
    message = str(caught.value)
    assert expected in message, f"{label}: error did not mention {expected!r}: {message}"


def test_the_malformed_table_is_large_enough() -> None:
    assert len(MALFORMED) >= 15


def test_errors_name_the_file() -> None:
    with pytest.raises(PolicyError, match=r"my\-policy\.yaml"):
        parse_policy({"mode": "nope"}, source=Path("my-policy.yaml"))


def test_invalid_yaml_is_reported_as_such(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("version: 1\n  bad: [indent\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(path)


def test_a_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="policy file not found"):
        load_policy(tmp_path / "absent.yaml")


# -- round-tripping -----------------------------------------------------------


@pytest.mark.parametrize("name", ["default", "strict", "dataflow", "monitor"])
def test_shipped_policies_round_trip(name: str) -> None:
    """load -> dump -> load must be stable, or a policy cannot be rewritten safely."""
    first = load_policy(POLICIES / f"{name}.yaml")
    dumped = yaml.safe_dump(first.model_dump(mode="json", exclude={"source_path"}))
    second = parse_policy(yaml.safe_load(dumped))
    assert first.model_dump(exclude={"source_path"}) == second.model_dump(exclude={"source_path"})


def test_empty_policy_is_valid_and_defaults_sensibly() -> None:
    policy = parse_policy({})
    assert policy.mode is Mode.DATAFLOW
    assert policy.tools == {}
    assert policy.rules == ()
    assert policy.unclassified_verdict is Verdict.ESCALATE


@pytest.mark.parametrize("mode", list(Mode))
def test_unclassified_never_defaults_to_allow(mode: Mode) -> None:
    assert UNCLASSIFIED_DEFAULTS[mode] is not Verdict.ALLOW
    assert parse_policy({"mode": mode.value}).unclassified_verdict is not Verdict.ALLOW


# -- classification lookup ----------------------------------------------------


def test_exact_match_beats_a_glob() -> None:
    policy = parse_policy(
        {"tools": {"mail.*": {"effect": "external"}, "mail.search": {"reads": "untrusted"}}}
    )
    assert policy.classify("mail.search") == ToolClass(reads=TrustLevel.UNTRUSTED)
    assert policy.classify("mail.send").effect is Effect.EXTERNAL


def test_the_most_specific_glob_wins_and_ties_break_deterministically() -> None:
    """Reproducibility (Hard Rule 4): the same policy must always resolve alike."""
    policy = parse_policy(
        {
            "tools": {
                "*": {"sensitivity": "public"},
                "mail.*": {"sensitivity": "sensitive"},
                "mail.se*": {"effect": "external"},
            }
        }
    )
    assert policy.classify("mail.send").effect is Effect.EXTERNAL  # longest pattern
    assert policy.classify("mail.drafts").sensitivity is Sensitivity.SENSITIVE
    assert policy.classify("web.fetch").sensitivity is Sensitivity.PUBLIC
    for _ in range(20):
        assert policy.classify("mail.send").effect is Effect.EXTERNAL


def test_an_unclassified_tool_resolves_to_none() -> None:
    assert parse_policy({"tools": {"mail.*": {}}}).classify("web.fetch") is None


def test_scope_accepts_a_string_or_a_list() -> None:
    one = parse_policy({"tools": {"fs.write": {"effect": "external", "scope": "./w/**"}}})
    assert one.classify("fs.write").scope == ("./w/**",)
    many = parse_policy({"tools": {"fs.write": {"effect": "external", "scope": ["a", "b"]}}})
    assert many.classify("fs.write").scope == ("a", "b")


def test_resolved_table_covers_every_tool_including_unclassified() -> None:
    policy = parse_policy({"tools": {"mail.send": {"effect": "external"}}})
    table = dict(policy.resolved_table(["mail.send", "web.fetch"]))
    assert table["mail.send"] is not None
    assert table["web.fetch"] is None


def test_policy_objects_are_frozen() -> None:
    policy = parse_policy({"mode": "strict"})
    with pytest.raises(ValidationError):
        policy.mode = Mode.MONITOR  # type: ignore[misc]


def test_shipped_policies_are_internally_consistent() -> None:
    """strict must actually be stricter, and none may allow the unclassified."""
    strict = load_policy(POLICIES / "strict.yaml")
    dataflow = load_policy(POLICIES / "dataflow.yaml")
    assert strict.mode is Mode.STRICT
    assert strict.unclassified_verdict is Verdict.DENY
    assert dataflow.unclassified_verdict is Verdict.ESCALATE
    # strict does not consult attribution, so it must carry no rule that does.
    assert all(r.when.args_tainted_by is None for r in strict.rules)
    for name in ("default", "strict", "dataflow", "monitor"):
        assert load_policy(POLICIES / f"{name}.yaml").unclassified_verdict is not Verdict.ALLOW


# -- shipped policies resolve by bare name ------------------------------------


def test_bare_names_resolve_to_the_packaged_policies() -> None:
    from trilock.policy.model import SHIPPED, resolve_policy_path

    for name in SHIPPED:
        resolved = resolve_policy_path(Path(name))
        assert resolved.is_file(), f"{name} did not resolve to a shipped policy"
        assert resolved.name == f"{name}.yaml"
        assert resolve_policy_path(Path(f"{name}.yaml")) == resolved
        assert load_policy(Path(name)).mode.value in ("strict", "dataflow", "monitor")


def test_paths_with_directories_are_left_alone(tmp_path: Path) -> None:
    from trilock.policy.model import resolve_policy_path

    custom = tmp_path / "mine.yaml"
    custom.write_text("version: 1\n", encoding="utf-8")
    assert resolve_policy_path(custom) == custom
    assert resolve_policy_path(Path("sub/dataflow")) == Path("sub/dataflow")


def test_an_unknown_bare_name_names_the_shipped_options() -> None:
    with pytest.raises(PolicyError, match="shipped policies: default, strict"):
        load_policy(Path("paranoid"))
