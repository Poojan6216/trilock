"""The decision function. This is the heart of the project.

`decide` is a **pure function**: same call, same session snapshot, same policy,
same decision, forever (Hard Rule 4). No I/O, no clock, no randomness, no
network, and above all no model. That is what makes `trilock replay` able to
re-derive every historical verdict and assert it still holds, and it is what
separates a deterministic interlock from a classifier with extra steps.

Everything the decision depends on is frozen into a `SessionSnapshot` before
this module is called. The engine cannot reach the ledger, so it cannot mutate
it, and it cannot see the content — only labels, shapes and paths.

Rules are ordered and first-match-wins, with an implicit terminal
`default_deny`. Every `Decision` names the rule that produced it, including
that one.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from trilock.policy.decision import Decision, ToolCall, TrifectaState, Verdict, stricter
from trilock.policy.model import Effect, Mode, Policy, Rule, RuleCondition, ToolClass
from trilock.taint.labels import IDENTITY, Sensitivity, TaintLabel, TrustLevel
from trilock.taint.propagate import Attribution

DEFAULT_RULE_ID = "default_deny"
MONITOR_RULE_PREFIX = "monitor:"


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Everything the engine may know, frozen at the moment of the call.

    Deliberately not the live `SessionState`: freezing it is what makes the
    decision reproducible from an audit record, and what stops the engine
    reaching content it has no business seeing.
    """

    trifecta: TrifectaState = TrifectaState()
    attribution: Attribution = field(default_factory=Attribution)
    classification: ToolClass | None = None
    session_label: TaintLabel = IDENTITY
    detector_scores: Mapping[str, float] = field(default_factory=lambda: MappingProxyType({}))
    """Advisory only (Hard Rule 1). May tighten a verdict; may never loosen one."""
    scope_violation: bool = False
    normalisation_removed: int = 0
    """Characters removed by inbound normalisation. A zero-model detector signal."""

    @property
    def unclassified(self) -> bool:
        return self.classification is None


def decide(call: ToolCall, session: SessionSnapshot, policy: Policy) -> Decision:
    """Return the verdict for `call`. Pure.

    Hard Rule 4: same (call, session, policy) MUST yield the same Decision,
    forever. This is what makes `trilock replay` possible.
    """
    base = _first_matching_rule(call, session, policy)
    adjusted = _apply_detectors(base, session, policy)
    if policy.mode is Mode.MONITOR:
        return _to_monitor(adjusted)
    return adjusted


# -- rule evaluation ---------------------------------------------------------


def _first_matching_rule(call: ToolCall, session: SessionSnapshot, policy: Policy) -> Decision:
    """Walk the rules in order; the first match wins, else the terminal deny."""
    for rule in policy.rules:
        if _matches(rule.when, call, session, policy):
            return _decision(rule.then, rule.id, _reasons(rule, call, session), session)
    return _decision(
        Verdict.DENY,
        DEFAULT_RULE_ID,
        (
            "no rule matched this call, and the terminal rule is deny. "
            "A policy that cannot decide refuses (Hard Rule 2).",
        ),
        session,
    )


def _matches(when: RuleCondition, call: ToolCall, session: SessionSnapshot, policy: Policy) -> bool:
    """Every field present on the condition must hold."""
    if when.tool is not None and not fnmatch.fnmatchcase(call.tool, when.tool):
        return False
    if when.effect is not None and _effect(session) is not when.effect:
        return False
    if when.trifecta_legs is not None and session.trifecta.legs < when.trifecta_legs:
        return False
    if when.unclassified is not None and session.unclassified is not when.unclassified:
        return False
    if when.scope_violation is not None and session.scope_violation is not when.scope_violation:
        return False
    if when.args_tainted_by is not None and not _args_tainted_by(
        when.args_tainted_by, session, policy.mode
    ):
        return False
    if when.session_touched is not None and not _session_touched(when.session_touched, session):
        return False
    if when.detector_above is not None and not _detector_above(when.detector_above, session):
        return False
    return True


def _effect(session: SessionSnapshot) -> Effect:
    return session.classification.effect if session.classification else Effect.NONE


def _args_tainted_by(level: TrustLevel, session: SessionSnapshot, mode: Mode) -> bool:
    """Whether this call's arguments carry taint at `level`.

    The two modes answer this differently, and that difference *is* the
    security/utility trade the project measures.

    In `strict`, attribution is not consulted at all. Paraphrase, re-encoding
    and laundering through a benign tool all defeat n-gram matching, so a mode
    that wants to be immune to them cannot ask "did the arguments match?" — it
    asks "has this session touched anything at that level?", and answers for
    the session.

    In `dataflow` the question is answered from attribution, with one
    conservative exception: once the ledger has evicted sources, a *negative*
    result proves nothing, so the session-level answer is used instead.
    """
    if level is TrustLevel.TRUSTED:
        return True  # everything is at least trusted; the condition is vacuous
    if mode is Mode.STRICT:
        return session.trifecta.untrusted_input
    if not session.attribution.complete:
        return session.trifecta.untrusted_input
    return session.attribution.label.is_untrusted


def _session_touched(level: Sensitivity, session: SessionSnapshot) -> bool:
    if level is Sensitivity.PUBLIC:
        return True
    return session.trifecta.sensitive_access


def _detector_above(thresholds: Mapping[str, float], session: SessionSnapshot) -> bool:
    """True when every named detector scored above its threshold.

    A detector that did not run, timed out or crashed has no score, and a
    missing score never satisfies a threshold (Hard Rule 2: a broken classifier
    is skipped, never treated as agreement).
    """
    for name, threshold in thresholds.items():
        score = session.detector_scores.get(name)
        if score is None or score < threshold:
            return False
    return True


# -- detector adjustment (Hard Rule 1) ---------------------------------------


def _apply_detectors(decision: Decision, session: SessionSnapshot, policy: Policy) -> Decision:
    """Let advisory scores tighten a verdict, never loosen one.

    This is the machine-checkable form of Hard Rule 1: a detector score may
    raise an ALLOW to an ESCALATE and may contribute to a DENY, but removing
    every score must never produce a *stricter* result, and adding one must
    never produce a looser one. Phase 4.4 property-tests exactly that.

    Rules that name a detector have already been evaluated above, where they
    can only select a rule. This step is the floor beneath them.
    """
    if not session.detector_scores or policy.mode is Mode.MONITOR:
        return decision
    if decision.verdict is not Verdict.ALLOW:
        return decision
    flagged = sorted(n for n, s in session.detector_scores.items() if s >= ADVISORY_ESCALATE_AT)
    if not flagged:
        return decision
    return Decision(
        verdict=stricter(decision.verdict, Verdict.ESCALATE),
        rule_id=decision.rule_id,
        reasons=(
            *decision.reasons,
            f"advisory detectors flagged this content ({', '.join(flagged)}), so an "
            "otherwise-allowed call is put to a human. A detector score can only "
            "tighten a decision, never permit one.",
        ),
        trifecta=decision.trifecta,
        tainted_args=decision.tainted_args,
        label=decision.label,
    )


ADVISORY_ESCALATE_AT = 0.9
"""Score at which an advisory detector raises an ALLOW to an ESCALATE.

High on purpose. Detection is a signal, never a control: *The Attacker Moves
Second* broke twelve published detectors with adaptive attacks, so a detector
that fires often would only add noise to the human's queue while adding no
security. It exists to catch the obvious, not to carry the guarantee.
"""


# -- monitor mode ------------------------------------------------------------


def _to_monitor(decision: Decision) -> Decision:
    """Record what would have happened; block nothing."""
    if decision.verdict is Verdict.ALLOW:
        return decision
    return Decision(
        verdict=Verdict.ALLOW,
        rule_id=f"{MONITOR_RULE_PREFIX}{decision.rule_id}",
        reasons=(
            f"monitor mode: this call would have been {decision.verdict.value.upper()} "
            f"by rule {decision.rule_id!r}, and was allowed because nothing is enforced "
            "in this mode.",
            *decision.reasons,
        ),
        trifecta=decision.trifecta,
        tainted_args=decision.tainted_args,
        label=decision.label,
    )


# -- assembly ----------------------------------------------------------------


def _decision(
    verdict: Verdict, rule_id: str, reasons: tuple[str, ...], session: SessionSnapshot
) -> Decision:
    return Decision(
        verdict=verdict,
        rule_id=rule_id,
        reasons=reasons,
        trifecta=session.trifecta,
        tainted_args=session.attribution.tainted_paths,
        label=session.session_label.join(session.attribution.label),
    )


def _reasons(rule: Rule, call: ToolCall, session: SessionSnapshot) -> tuple[str, ...]:
    """Human-readable justification, shown in the approval prompt.

    Every string here is written by Trilock from policy and session *labels*.
    No tool output reaches it, so nothing an attacker wrote can appear in the
    instruction part of a prompt (Hard Rule 3).
    """
    reasons = [f"rule {rule.id!r} matched {call.tool!r}"]
    if rule.because:
        reasons.append(rule.because.strip())
    legs = []
    if session.trifecta.untrusted_input:
        legs.append("untrusted input")
    if session.trifecta.sensitive_access:
        legs.append("sensitive data")
    if session.trifecta.external_action:
        legs.append("external action")
    if legs:
        reasons.append(f"session holds {len(legs)} of 3 trifecta legs: {', '.join(legs)}")
    if session.attribution.tainted_paths:
        reasons.append(
            "arguments derived from untrusted sources: "
            + ", ".join(session.attribution.tainted_paths)
        )
    if not session.attribution.complete:
        reasons.append(
            "the provenance ledger has evicted sources, so arguments are treated "
            "conservatively rather than assumed clean"
        )
    if session.scope_violation:
        reasons.append("the call falls outside the scope its policy declares")
    if session.normalisation_removed:
        reasons.append(
            f"{session.normalisation_removed} hidden or invisible characters were "
            "removed from content this session ingested"
        )
    return tuple(reasons)
