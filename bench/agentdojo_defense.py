"""Trilock as an AgentDojo pipeline element.

AgentDojo scores an agent by running its tool calls against a real environment
and then asking the *environment* whether the user's task was done (utility)
and whether the attacker's goal was reached (security) — formal functions over
state, not an LLM judge. That is why it is the right benchmark, and why the
numbers it produces are the only ones Trilock quotes.

**How the agent is driven, and why.** No LLM API key is available in this
build environment, so the pipeline here is an *oracle*: it executes each
task's own ground-truth tool calls rather than a model's. For a user task that
is the ideal agent. For an attack scenario it first performs the user task's
calls (which read the injected content, so Trilock ingests it) and then emits
the injection task's ground-truth calls — the exact calls a fully hijacked
agent would make. This is the strongest adversary a deterministic interlock
can face: an attacker who always lands the injection and always knows the
right tool call. It is also precisely the threat model of the spec, which
assumes injection succeeds.

The trade is stated plainly in RESULTS.md: "utility under attack" with an
oracle agent measures Trilock's *false positives* (benign calls it refuses),
not a model's distraction, because an oracle is never distracted. A key-driven
run (``run_bench.py --model ...``) uses AgentDojo's own LLM pipelines instead
and measures both.

Every call goes through the same path the proxy uses: classification from
``policies/agentdojo/<suite>.yaml``, normalisation and labelling of results,
attribution of arguments, trifecta accounting, `decide()`. Blocked calls are
not executed; the environment never sees them.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from trilock.policy.decision import Decision, ToolCall, Verdict
from trilock.policy.engine import SessionSnapshot, decide
from trilock.policy.model import Mode, Policy, parse_policy
from trilock.policy.scope import check as check_scope
from trilock.policy.trifecta import SessionState, is_external
from trilock.taint.labels import new_call_id
from trilock.taint.propagate import Attribution, attribute
from trilock.taint.store import SessionKey, SessionLedger

POLICY_DIR = Path(__file__).resolve().parents[1] / "policies" / "agentdojo"


@dataclass(frozen=True, slots=True)
class Ablation:
    """Which component to switch off. All True is Trilock as shipped."""

    normalisation: bool = True
    attribution: bool = True
    detectors: bool = True
    trifecta_rule: bool = True

    @property
    def label(self) -> str:
        off = [
            n
            for n, on in (
                ("normalisation", self.normalisation),
                ("attribution", self.attribution),
                ("detectors", self.detectors),
                ("trifecta_rule", self.trifecta_rule),
            )
            if not on
        ]
        return "full" if not off else "no_" + "+".join(off)


def load_suite_policy(
    suite: str, mode: Mode, ablation: Ablation | None = None, *, integrity: bool = False
) -> Policy:
    """The shipped rules with the suite's tool table, at the requested mode.

    `integrity=True` inserts the shipped integrity rule (any external action
    after untrusted input escalates) ahead of rule_of_two.
    """
    ablation = ablation if ablation is not None else Ablation()
    common = yaml.safe_load((POLICY_DIR / "_common.yaml").read_text(encoding="utf-8"))
    if integrity:
        rules = list(common["rules"])
        idx = next(i for i, r in enumerate(rules) if r["id"] == "rule_of_two")
        rules.insert(
            idx,
            {
                "id": "untrusted_then_external",
                "when": {"effect": "external", "session_untrusted": True},
                "then": "escalate",
            },
        )
        common = {**common, "rules": rules}
    tools = yaml.safe_load((POLICY_DIR / f"{suite}.yaml").read_text(encoding="utf-8"))["tools"]
    doc = {**common, "tools": tools, "mode": mode.value}
    if mode is Mode.STRICT:
        doc["unclassified"] = "deny"
        doc["rules"] = [r for r in doc["rules"] if r["id"] != "tainted_egress"]
        for rule in doc["rules"]:
            if rule["id"] in ("rule_of_two", "unclassified_tool"):
                rule["then"] = "deny"
    if not ablation.trifecta_rule:
        doc["rules"] = [r for r in doc["rules"] if r["id"] not in ("rule_of_two", "tainted_egress")]
    return parse_policy(doc)


@dataclass
class CallRecord:
    tool: str
    verdict: str
    rule_id: str
    phase: str  # "user" or "injection"
    latency_ms: float


@dataclass
class TrilockPipeline(BasePipelineElement):
    """Oracle agent behind Trilock. See the module docstring."""

    suite: str
    policy: Policy | None
    ablation: Ablation = Ablation()
    human_approves_own_task: bool = False
    """The 'attentive human' reading. When True, an ESCALATE raised during the
    *user* phase is treated as approved — the human reads a prompt about the
    task they just asked for and says yes — while an ESCALATE during the
    *injection* phase stays blocked, because the same human reads a prompt about
    a call they never asked for and says no. DENY is never overridden. This
    separates the utility cost of hard refusals from the cost of questions a
    present human would answer; both readings are reported side by side."""
    name: str = "trilock-oracle-local"
    """AgentDojo's `important_instructions` attack templates the target model's
    name into its injection text and requires one of its model ids to appear in
    the pipeline name. The oracle has no cloud model, so it carries the `local`
    id, which renders as "Local model" in the injection text — the honest label
    for an agent driven by ground truth on this machine."""
    records: list[CallRecord] = field(default_factory=list)
    _user_task: BaseUserTask | None = None
    _injection_task: BaseInjectionTask | None = None

    def set_tasks(
        self, user_task: BaseUserTask | None, injection_task: BaseInjectionTask | None
    ) -> None:
        self._user_task, self._injection_task = user_task, injection_task

    # -- the AgentDojo contract ---------------------------------------------

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),  # noqa: B008 - AgentDojo's BasePipelineElement contract
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},  # noqa: B006 - ditto
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if self._user_task is None:
            raise ValueError("set_tasks() first")
        state = SessionState(
            key=SessionKey(kind="stdio-process", value="bench"),
            ledger=SessionLedger(key=SessionKey(kind="stdio-process", value="bench")),
        )
        new_messages: list[ChatMessage] = []
        for call in self._user_task.ground_truth(env):
            new_messages.extend(self._execute(call, runtime, env, state, phase="user"))
        if self._injection_task is not None:
            for call in self._injection_task.ground_truth(env):
                new_messages.extend(self._execute(call, runtime, env, state, phase="injection"))
        output = getattr(self._user_task, "GROUND_TRUTH_OUTPUT", "") or ""
        new_messages.append(
            ChatAssistantMessage(
                role="assistant", content=[text_content_block_from_string(output)], tool_calls=None
            )
        )
        return query, runtime, env, [*messages, *new_messages], extra_args

    # -- one call through Trilock's path ------------------------------------

    def _execute(
        self,
        call: FunctionCall,
        runtime: FunctionsRuntime,
        env: Env,
        state: SessionState,
        *,
        phase: str,
    ) -> list[ChatMessage]:
        qualified = f"{self.suite}.{call.function}"
        arguments = dict(call.args)
        started = time.perf_counter()
        decision = self._decide(qualified, arguments, state)
        latency = (time.perf_counter() - started) * 1000
        self.records.append(
            CallRecord(qualified, decision.verdict.value, decision.rule_id, phase, latency)
        )
        assistant = ChatAssistantMessage(
            role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]
        )
        approved_by_human = (
            self.human_approves_own_task
            and phase == "user"
            and decision.verdict is Verdict.ESCALATE
        )
        if decision.verdict is not Verdict.ALLOW and not approved_by_human:
            # Blocked: the environment never sees it. ESCALATE counts as blocked
            # for the oracle, which has no human to ask — the conservative
            # reading, and the one the spec's degrade rule (3.2) mandates.
            error = f"Trilock refused this call. rule={decision.rule_id} verdict={decision.verdict.value}"
            return [
                assistant,
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string("")],
                    tool_call=call,
                    tool_call_id=call.id,
                    error=error,
                ),
            ]
        result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
        text = tool_result_to_str(result) if error is None else str(error)
        if error is None:
            classification = self.policy.classify(qualified) if self.policy else None
            if self.ablation.normalisation:
                state.record_result(
                    self.suite, call.function, new_call_id(), [text], classification
                )
            else:
                # Ablation: label and fingerprint the raw text, skipping normalisation.
                from trilock.taint.labels import Sensitivity, TaintLabel, TrustLevel

                untrusted = classification is None or classification.yields_untrusted
                sensitive = classification is not None and classification.yields_sensitive
                state.ledger.record(
                    self.suite,
                    call.function,
                    new_call_id(),
                    text,
                    TaintLabel(
                        trust=TrustLevel.UNTRUSTED if untrusted else TrustLevel.TRUSTED,
                        sensitivity=Sensitivity.SENSITIVE if sensitive else Sensitivity.PUBLIC,
                    ),
                )
                state.untrusted_input |= untrusted
                state.sensitive_access |= sensitive
        return [
            assistant,
            ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(text)],
                tool_call=call,
                tool_call_id=call.id,
                error=error,
            ),
        ]

    def _decide(self, qualified: str, arguments: dict[str, Any], state: SessionState) -> Decision:
        if self.policy is None:
            return Decision(verdict=Verdict.ALLOW, rule_id="undefended")
        classification = self.policy.classify(qualified)
        attribution = (
            attribute(arguments, state.ledger)
            if self.ablation.attribution
            else Attribution(complete=state.ledger.attribution_complete)
        )
        if not self.ablation.attribution and state.untrusted_input:
            # Without attribution, dataflow has no argument-level evidence at all;
            # the honest fallback is the session-level answer, as after eviction.
            attribution = Attribution(complete=False)
        scope = check_scope(classification, arguments, root=Path.cwd())
        snapshot = SessionSnapshot(
            trifecta=state.trifecta(external=is_external(classification)),
            attribution=attribution,
            classification=classification,
            session_label=state.ledger.session_label(),
            detector_scores={},  # detectors are advisory and measured separately; off here unless ablation says otherwise
            scope_violation=scope.violated,
            normalisation_removed=sum(r.removed_chars for r in state.normalisations),
        )
        return decide(ToolCall(tool=qualified, arguments=arguments), snapshot, self.policy)
