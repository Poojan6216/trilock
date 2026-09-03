"""Re-derive every recorded decision and assert it still holds.

`decide` is pure (Hard Rule 4), and every audit record holds the frozen inputs
it was given. So the log can be replayed: rebuild each snapshot, run `decide`
again against the same policy, and compare. A mismatch means one of three
things — the log was altered, the policy changed, or `decide` stopped being
deterministic — and every one of those is a build failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trilock.audit.log import ChainBreak, read_records, verify_chain
from trilock.policy.decision import Decision, ToolCall, TrifectaState, Verdict
from trilock.policy.engine import SessionSnapshot, decide
from trilock.policy.model import Policy, ToolClass
from trilock.taint.labels import Sensitivity, SourceId, TaintLabel, TrustLevel
from trilock.taint.propagate import ArgumentMatch, Attribution


@dataclass(frozen=True, slots=True)
class Mismatch:
    line: int
    call_id: str
    tool: str
    recorded: str
    replayed: str
    recorded_rule: str
    replayed_rule: str


@dataclass(frozen=True, slots=True)
class ReplayReport:
    records: int
    decisions: int
    mismatches: tuple[Mismatch, ...]
    chain_breaks: tuple[ChainBreak, ...]
    policy_hash_mismatches: int

    @property
    def ok(self) -> bool:
        return not self.mismatches and not self.chain_breaks and not self.policy_hash_mismatches


def _label(raw: dict[str, Any]) -> TaintLabel:
    return TaintLabel(
        trust=TrustLevel(raw["trust"]),
        sensitivity=Sensitivity(raw["sensitivity"]),
        sources=frozenset(_source(s) for s in raw.get("sources", [])),
        detector_scores=raw.get("detector_scores", {}),
    )


def _source(text: str) -> SourceId:
    # "server.tool#seq" — the call id is not recorded on the label, and the
    # engine never reads it, so a placeholder keeps replay exact.
    head, _, seq = text.rpartition("#")
    server, _, tool = head.partition(".")
    return SourceId(server=server, tool=tool, call_id="", seq=int(seq or 0))


def snapshot_from_json(raw: dict[str, Any]) -> SessionSnapshot:
    attribution_raw = raw["attribution"]
    matches = tuple(
        ArgumentMatch(
            path=m["path"],
            sources=frozenset(_source(s) for s in m["sources"]),
            evidence=m["evidence"],
            strength=float(m["strength"]),
        )
        for m in attribution_raw.get("matches", [])
    )
    trifecta = raw["trifecta"]
    return SessionSnapshot(
        trifecta=TrifectaState(
            untrusted_input=trifecta["untrusted_input"],
            sensitive_access=trifecta["sensitive_access"],
            external_action=trifecta["external_action"],
        ),
        attribution=Attribution(
            matches=matches,
            label=_label(attribution_raw["label"]),
            complete=attribution_raw["complete"],
        ),
        classification=ToolClass.model_validate(raw["classification"])
        if raw.get("classification")
        else None,
        session_label=_label(raw["session_label"]),
        detector_scores=raw.get("detector_scores", {}),
        scope_violation=bool(raw.get("scope_violation", False)),
        normalisation_removed=int(raw.get("normalisation_removed", 0)),
    )


def replay(path: Path, policy: Policy, *, policy_hash: str | None = None) -> ReplayReport:
    """Replay every decision record in `path` against `policy`."""
    chain_breaks = tuple(verify_chain(path))
    mismatches: list[Mismatch] = []
    records = decisions = hash_mismatches = 0
    for line, record in read_records(path):
        records += 1
        if record.get("kind") != "decision":
            continue
        decisions += 1
        if policy_hash is not None and record.get("policy_hash") != policy_hash:
            hash_mismatches += 1
        recorded = record["decision"]
        replayed: Decision = decide(
            ToolCall(tool=record["tool"], arguments={}, call_id=record["call_id"]),
            snapshot_from_json(record["snapshot"]),
            policy,
        )
        if (
            replayed.verdict is not Verdict(recorded["verdict"])
            or replayed.rule_id != recorded["rule_id"]
        ):
            mismatches.append(
                Mismatch(
                    line=line,
                    call_id=record["call_id"],
                    tool=record["tool"],
                    recorded=recorded["verdict"],
                    replayed=replayed.verdict.value,
                    recorded_rule=recorded["rule_id"],
                    replayed_rule=replayed.rule_id,
                )
            )
    return ReplayReport(
        records=records,
        decisions=decisions,
        mismatches=tuple(mismatches),
        chain_breaks=chain_breaks,
        policy_hash_mismatches=hash_mismatches,
    )
