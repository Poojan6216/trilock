"""Task 1.1 verification: the lattice laws, property-tested.

`join` is the propagation rule for the entire system. If it is not
associative, commutative and idempotent, then the taint a call carries depends
on the order results happened to arrive in, and no decision built on it is
reproducible (Hard Rule 4).
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trilock.taint.labels import (
    IDENTITY,
    TOP,
    Sensitivity,
    SourceId,
    TaintLabel,
    TrustLevel,
    new_call_id,
)

source_ids = st.builds(
    SourceId,
    server=st.sampled_from(["mail", "notes", "docs", "web"]),
    tool=st.sampled_from(["search", "send", "read", "fetch"]),
    call_id=st.sampled_from([new_call_id() for _ in range(6)]),
    seq=st.integers(min_value=0, max_value=50),
)

labels = st.builds(
    TaintLabel,
    trust=st.sampled_from(list(TrustLevel)),
    sensitivity=st.sampled_from(list(Sensitivity)),
    sources=st.frozensets(source_ids, max_size=5),
    detector_scores=st.dictionaries(
        st.sampled_from(["heuristics", "promptguard", "perplexity"]),
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        max_size=3,
    ),
)

LAW_SETTINGS = settings(
    max_examples=1200, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)


@LAW_SETTINGS
@given(a=labels, b=labels, c=labels)
def test_join_is_associative(a: TaintLabel, b: TaintLabel, c: TaintLabel) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))


@LAW_SETTINGS
@given(a=labels, b=labels)
def test_join_is_commutative(a: TaintLabel, b: TaintLabel) -> None:
    assert a.join(b) == b.join(a)


@LAW_SETTINGS
@given(a=labels)
def test_join_is_idempotent(a: TaintLabel) -> None:
    assert a.join(a) == a


@LAW_SETTINGS
@given(a=labels)
def test_identity_is_the_unit(a: TaintLabel) -> None:
    assert a.join(IDENTITY) == a
    assert IDENTITY.join(a) == a


@LAW_SETTINGS
@given(a=labels, b=labels)
def test_join_only_moves_toward_danger(a: TaintLabel, b: TaintLabel) -> None:
    """The security property the laws exist to protect: joining never launders."""
    joined = a.join(b)
    assert joined.dominates(a)
    assert joined.dominates(b)
    assert joined.sources >= a.sources
    assert joined.sources >= b.sources


@LAW_SETTINGS
@given(a=labels, b=labels)
def test_detector_scores_join_by_maximum(a: TaintLabel, b: TaintLabel) -> None:
    joined = a.join(b)
    for key in set(a.detector_scores) | set(b.detector_scores):
        expected = max(
            a.detector_scores.get(key, float("-inf")), b.detector_scores.get(key, float("-inf"))
        )
        assert joined.detector_scores[key] == expected


@LAW_SETTINGS
@given(a=labels)
def test_top_absorbs(a: TaintLabel) -> None:
    joined = a.join(TOP)
    assert joined.trust is TrustLevel.UNTRUSTED
    assert joined.sensitivity is Sensitivity.SENSITIVE


@LAW_SETTINGS
@given(a=labels)
def test_widened_is_at_least_as_dangerous_and_keeps_sources(a: TaintLabel) -> None:
    widened = a.widened()
    assert widened.dominates(a)
    assert widened.sources == a.sources
    assert widened.join(a) == widened


def test_labels_are_immutable_through_an_alias() -> None:
    scores = {"heuristics": 0.2}
    label = TaintLabel(detector_scores=scores)
    scores["heuristics"] = 0.99  # mutating the caller's dict must not reach the label
    assert label.detector_scores["heuristics"] == 0.2
    import pytest

    with pytest.raises(TypeError):
        label.detector_scores["heuristics"] = 0.99  # type: ignore[index]


def test_labels_are_hashable_and_usable_in_sets() -> None:
    a = TaintLabel(trust=TrustLevel.UNTRUSTED, detector_scores={"x": 0.1})
    b = TaintLabel(trust=TrustLevel.UNTRUSTED, detector_scores={"x": 0.9})
    assert a != b  # advisory scores are part of equality
    assert hash(a) == hash(b)  # but not of identity
    assert len({a, b}) == 2
    assert len({IDENTITY, TaintLabel()}) == 1


def test_join_all_folds_and_defaults_to_identity() -> None:
    assert TaintLabel.join_all([]) == IDENTITY
    assert TaintLabel.join_all([TOP, IDENTITY]) == TOP
    assert (
        TaintLabel.join_all(
            [TaintLabel(trust=TrustLevel.UNTRUSTED), TaintLabel(sensitivity=Sensitivity.SENSITIVE)]
        )
        == TOP
    )


def test_predicates_and_json_carry_labels_not_content() -> None:
    src = SourceId(server="mail", tool="search", call_id=new_call_id(), seq=0)
    label = TaintLabel(
        trust=TrustLevel.UNTRUSTED, sources=frozenset({src}), detector_scores={"h": 0.5}
    )
    assert label.is_untrusted and not label.is_sensitive and not label.is_clean
    assert IDENTITY.is_clean
    rendered = label.to_json()
    assert rendered["trust"] == "untrusted"
    assert rendered["sources"] == ["mail.search#0"]
    assert rendered["detector_scores"] == {"h": 0.5}
