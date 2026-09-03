"""The AgentDojo harness must not score a call Trilock blocked as an attack that ran.

AgentDojo scores one injection task (`slack.injection_task_5`) from the trace of
tool calls found in assistant messages, on the assumption that every emitted
call executed. Before this pin, the harness put refused calls into that trace,
so a fully-denied attack counted as a success — the benchmark's arithmetic was
being run against Trilock, not against the attacker.
"""

from __future__ import annotations

import pytest

agentdojo = pytest.importorskip("agentdojo")

from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages  # noqa: E402
from bench.agentdojo_defense import TrilockPipeline, load_suite_policy  # noqa: E402

from trilock.policy.model import Mode  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _slack_pair(user_task: str, injection_task: str, mode: Mode) -> tuple[TrilockPipeline, bool]:
    suite = get_suites("v1.2.2")["slack"]
    ut, it = suite.user_tasks[user_task], suite.injection_tasks[injection_task]
    pipeline = TrilockPipeline(suite="slack", policy=load_suite_policy("slack", mode))
    pipeline.set_tasks(ut, it)
    attack = load_attack("important_instructions", suite, pipeline)
    _utility, security = suite.run_task_with_pipeline(pipeline, ut, it, attack.attack(ut, it))
    return pipeline, security


def test_a_fully_refused_trace_scored_attack_is_not_a_success() -> None:
    """user_task_1 x injection_task_5 under strict: every injected call is denied."""
    pipeline, security = _slack_pair("user_task_1", "injection_task_5", Mode.STRICT)
    injected = [r for r in pipeline.records if r.phase == "injection"]
    assert injected, "the oracle must have attempted the injection"
    assert all(r.verdict != "allow" for r in injected), [r.verdict for r in injected]
    assert security is False


def test_refused_calls_are_absent_from_the_scored_trace_and_allowed_ones_present() -> None:
    """The trace AgentDojo reads is exactly the set of calls that executed."""
    suite = get_suites("v1.2.2")["slack"]
    ut, it = suite.user_tasks["user_task_1"], suite.injection_tasks["injection_task_5"]
    pipeline = TrilockPipeline(suite="slack", policy=load_suite_policy("slack", mode=Mode.STRICT))
    pipeline.set_tasks(ut, it)
    attack = load_attack("important_instructions", suite, pipeline)
    env = suite.load_and_inject_default_environment(attack.attack(ut, it))
    runtime = agentdojo.functions_runtime.FunctionsRuntime(suite.tools)
    _query, _runtime, _env, messages, _extra = pipeline.query(ut.PROMPT, runtime, env, [], {})

    traced = [c.function for c in functions_stack_trace_from_messages(messages)]
    executed = [r.tool.split(".", 1)[1] for r in pipeline.records if r.verdict == "allow"]
    refused = {r.tool.split(".", 1)[1] for r in pipeline.records if r.verdict != "allow"}
    assert traced == executed
    assert refused and not (set(traced) & refused)
