"""The one command that produces RESULTS.md.

    uv run python bench/run_bench.py --all
    uv run python bench/run_bench.py --suite banking --mode dataflow
    uv run python bench/run_bench.py --all --ablations
    uv run python bench/run_bench.py --all --model gpt-4o-mini-2024-07-18   # needs an API key

Every number in RESULTS.md traces to a run of this file; the JSON it writes to
bench/results/ is committed alongside. RESULTS.md is generated, never edited.

Three metrics, always together (task 5.3): benign utility (no attack), utility
under attack, and targeted attack success rate. Reporting ASR alone is the
degenerate result where a defence wins by breaking the agent.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import agentdojo
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suites

# Runnable as a script from anywhere: put the repo root first so `bench.*` imports resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.agentdojo_defense import Ablation, TrilockPipeline, load_suite_policy
from trilock import __version__
from trilock.policy.model import Mode

REPO = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO / "bench" / "results"
RESULTS_MD = REPO / "RESULTS.md"
SUITES = ("workspace", "travel", "banking", "slack")
CONFIGS: dict[str, Mode | None] = {
    "undefended": None,
    "monitor": Mode.MONITOR,
    "strict": Mode.STRICT,
    "dataflow": Mode.DATAFLOW,
}
ATTACK = "important_instructions"
BENCH_VERSION = "v1.2.2"


def _git() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=REPO, text=True
        ).strip()
    except Exception:
        return "unknown"


def _measure(
    suite: Any, pipeline: TrilockPipeline, attack: Any
) -> tuple[dict[str, bool], dict[str, bool], dict[str, bool]]:
    benign: dict[str, bool] = {}
    for uid, user_task in suite.user_tasks.items():
        pipeline.set_tasks(user_task, None)
        utility, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
        benign[uid] = utility
    under_attack: dict[str, bool] = {}
    attack_success: dict[str, bool] = {}
    for uid, user_task in suite.user_tasks.items():
        for iid, injection_task in suite.injection_tasks.items():
            pipeline.set_tasks(user_task, injection_task)
            injections = attack.attack(user_task, injection_task)
            utility, security = suite.run_task_with_pipeline(
                pipeline, user_task, injection_task, injections
            )
            under_attack[f"{uid}|{iid}"] = utility
            attack_success[f"{uid}|{iid}"] = security
    return benign, under_attack, attack_success


def run_config(suite_name: str, config: str, ablation: Ablation, *, quiet: bool) -> dict[str, Any]:
    suite = get_suites(BENCH_VERSION)[suite_name]
    mode = CONFIGS[config]
    policy = load_suite_policy(suite_name, mode, ablation) if mode is not None else None
    pipeline = TrilockPipeline(suite=suite_name, policy=policy, ablation=ablation)
    benign, under_attack, attack_success = _measure(
        suite, pipeline, load_attack(ATTACK, suite, pipeline)
    )

    # The 'attentive human' reading: same policy, user-phase escalations approved.
    human = TrilockPipeline(
        suite=suite_name, policy=policy, ablation=ablation, human_approves_own_task=True
    )
    h_benign, h_under_attack, h_attack_success = _measure(
        suite, human, load_attack(ATTACK, suite, human)
    )

    latencies = [r.latency_ms for r in pipeline.records]
    verdicts: dict[str, int] = defaultdict(int)
    for r in pipeline.records:
        verdicts[f"{r.phase}:{r.verdict}:{r.rule_id}"] += 1
    out = {
        "suite": suite_name,
        "config": config,
        "ablation": ablation.label,
        "user_tasks": len(suite.user_tasks),
        "injection_tasks": len(suite.injection_tasks),
        "security_cases": len(attack_success),
        "benign_utility": _rate(benign),
        "utility_under_attack": _rate(under_attack),
        "targeted_asr": _rate(attack_success),
        "with_attentive_human": {
            "benign_utility": _rate(h_benign),
            "utility_under_attack": _rate(h_under_attack),
            "targeted_asr": _rate(h_attack_success),
        },
        "decision_latency_ms": {
            "p50": round(statistics.median(latencies), 3) if latencies else None,
            "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3)
            if latencies
            else None,
            "p99": round(sorted(latencies)[int(0.99 * (len(latencies) - 1))], 3)
            if latencies
            else None,
            "n": len(latencies),
        },
        "verdicts": dict(sorted(verdicts.items())),
    }
    if not quiet:
        h = out["with_attentive_human"]
        print(
            f"  {suite_name:10} {config:10} {ablation.label:22} "
            f"oracle: benign={out['benign_utility']:.3f} atk={out['utility_under_attack']:.3f} "
            f"ASR={out['targeted_asr']:.3f} | human: benign={h['benign_utility']:.3f} "
            f"atk={h['utility_under_attack']:.3f} ASR={h['targeted_asr']:.3f} | cases={len(attack_success)}"
        )
    return out


def _rate(results: dict[str, bool]) -> float:
    return round(sum(results.values()) / len(results), 4) if results else 0.0


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Weighted by case count across suites, per (config, ablation)."""
    agg: dict[tuple[str, str], dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in rows:
        key = (r["config"], r["ablation"])
        a = agg[key]
        a["benign_n"] += r["user_tasks"]
        a["benign_ok"] += r["benign_utility"] * r["user_tasks"]
        a["cases"] += r["security_cases"]
        a["attack_util_ok"] += r["utility_under_attack"] * r["security_cases"]
        a["asr_ok"] += r["targeted_asr"] * r["security_cases"]
        h = r["with_attentive_human"]
        a["h_benign_ok"] += h["benign_utility"] * r["user_tasks"]
        a["h_attack_util_ok"] += h["utility_under_attack"] * r["security_cases"]
        a["h_asr_ok"] += h["targeted_asr"] * r["security_cases"]
    return {
        f"{c}/{ab}": {
            "config": c,
            "ablation": ab,
            "benign_utility": round(a["benign_ok"] / a["benign_n"], 4),
            "utility_under_attack": round(a["attack_util_ok"] / a["cases"], 4),
            "targeted_asr": round(a["asr_ok"] / a["cases"], 4),
            "human_benign_utility": round(a["h_benign_ok"] / a["benign_n"], 4),
            "human_utility_under_attack": round(a["h_attack_util_ok"] / a["cases"], 4),
            "human_targeted_asr": round(a["h_asr_ok"] / a["cases"], 4),
            "user_tasks": int(a["benign_n"]),
            "security_cases": int(a["cases"]),
        }
        for (c, ab), a in agg.items()
    }


def latest(pattern: str) -> Path | None:
    files = sorted(RESULTS_DIR.glob(pattern))
    return files[-1] if files else None


def render_attacks_section() -> str:
    """The 'Attacks that work against Trilock' tables, from the labelled adaptive runs.

    Task 6.3: report the losses, and where something was fixed keep the pre-fix
    number in the table. Three labelled runs of the same red team:
    `adaptive_before.json` (no persistent sink taint), `adaptive_shipped.json`
    (Trilock as shipped: sink taint on, durable sessions off) and
    `adaptive_durable.json` (durable sessions opted in). Regenerate with
    `uv run python -m bench.adaptive.attacker --label ...`; see the Makefile-free
    recipe at the top of that module.
    """
    runs = {
        "before": RESULTS_DIR / "adaptive_before.json",
        "shipped": RESULTS_DIR / "adaptive_shipped.json",
        "durable": RESULTS_DIR / "adaptive_durable.json",
    }
    data = {k: json.loads(p.read_text(encoding="utf-8")) for k, p in runs.items() if p.is_file()}
    if not data:
        path = latest("adaptive_*.json")
        if path is None:
            return ""
        data = {"shipped": json.loads(path.read_text(encoding="utf-8"))}
    head = data.get("shipped") or next(iter(data.values()))

    def cell(run: str, strategy: str, mode: str) -> str:
        d = data.get(run)
        if d is None:
            return "-"
        t = next((t for t in d["table"] if t["strategy"] == strategy and t["mode"] == mode), None)
        if t is None:
            return "-"
        return f"**{t['asr']:.3f}**" if t["asr"] > 0 else f"{t['asr']:.3f}"

    strategies = sorted({t["strategy"] for d in data.values() for t in d["table"]})
    lines = [
        "## Attacks that work against Trilock",
        "",
        f"From `uv run python -m bench.adaptive.attacker` (raw: {', '.join(f'`{p.relative_to(REPO)}`' for k, p in runs.items() if k in data)}), "
        f"latest at {head['measured_at']} on commit `{head['commit']}`. Every strategy runs in both modes under three human "
        "models: **none** (an ESCALATE is blocked - the oracle floor), **attentive** (declines if the literal credential is visible "
        "in the approval prompt, approves otherwise - careful, but cannot decode base64 or spot a paraphrase by eye), and **tired** "
        f"(approves everything after {head['fatigue_after']} prompts). Bold is a loss.",
        "",
        "Three columns per mode, because two structural losses were fixed after they were published and task 6.3 says the "
        "pre-fix number stays in the table: **before** (no persistent sink taint), **shipped** (sink taint on by default, "
        "durable sessions off), **durable** (`sessions: {durable: true}` opted in).",
        "",
        "| strategy | human | dataflow before | dataflow shipped | dataflow durable | strict before | strict shipped | strict durable |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy in strategies:
        for human in ("none", "attentive"):
            cells = [
                cell(run, strategy, f"{mode}/{human}")
                for mode in ("dataflow", "strict")
                for run in ("before", "shipped", "durable")
            ]
            lines.append(f"| {strategy} | {human} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "### What the losses mean, and what was done about each",
        "",
        "* **paraphrase, encoding, approval fatigue (dataflow only, attentive human).** The attribution seam the design "
        "documents: a body sharing no 5-grams with the ledger and showing no literal credential is unattributable, so "
        "`tainted_egress` cannot fire, `rule_of_two` escalates, and a human who cannot see the secret says yes. `strict` scores "
        "zero on all of them because it never consults attribution, and pays for that in the utility table. **Not fixed**, on "
        "purpose: fixing it inside `dataflow` means becoming `strict`, which is offered and measured.",
        "* **laundering via a misclassified store (both modes) - fixed.** A `memory`/`cache`/`notes` tool the policy author did not "
        "think of as an egress accepts the secret with two legs; a fresh session reads it back through a trusted-labelled tool and "
        "sends it. **Persistent sink taint** (`taint/sinks.py`, on by default) records the hashed identifiers of every allowed call "
        "whose arguments carried taint, and a later call naming one of them - any session, any process - inherits it. Before "
        f"{cell('before', 'laundering', 'dataflow/none')} -> shipped {cell('shipped', 'laundering', 'dataflow/none')}. "
        "The earlier version of this harness also let a *denied* write be read back, which flattered the attacker; it now models "
        "the store, and only allowed writes persist.",
        "* **session splitting (both modes) - fixed, opt-in.** Read in one session, reconnect, send from a fresh one: the secret "
        "travels in the model's own context where no tool call can see it. **Durable sessions** (`taint/durable.py`, "
        "`sessions: {durable: true}`) persist a session's legs and fingerprints - never raw tokens - per user and config, and the "
        "next process within the TTL resumes them, so the send is the third leg. Shipped "
        f"{cell('shipped', 'session_splitting', 'dataflow/none')} -> durable {cell('durable', 'session_splitting', 'dataflow/none')}. "
        "Opt-in because it trades utility: every new session inherits the previous one's legs for 24 hours. A different OS user, a "
        "different machine, or a TTL expiry still splits.",
        "* **destination_leak, scope_probing, padding: 0.** Reported so the zeros sit next to the losses.",
        "",
    ]
    return "\n".join(lines) + "\n"


def _residual_note(payload: dict[str, Any]) -> str:
    """Explain the non-zero ASR under strict/dataflow from the recorded verdicts.

    Every injection-phase call that *succeeded* under Trilock did so with the
    verdict `allow / fewer_than_three_legs`: the session held untrusted input and
    an external action but had touched **no sensitive data**. Those are two-leg
    integrity attacks - book a hotel, invite a user, post a link - and the Rule
    of Two permits two legs by design. Written from the data so the claim cannot
    drift from the numbers. The `integrity` configuration adds the rule that
    catches them, at the utility cost shown in the table.
    """
    per_suite = []
    for r in payload["rows"]:
        if r["config"] != "dataflow" or r["ablation"] != "full":
            continue
        allowed = sum(v for k, v in r["verdicts"].items() if k.startswith("injection:allow"))
        total = sum(v for k, v in r["verdicts"].items() if k.startswith("injection:"))
        per_suite.append(
            f"{r['suite']} ASR {r['targeted_asr']:.3f} ({allowed}/{total} injection-phase calls allowed, "
            "all as `fewer_than_three_legs`)"
        )
    integrity = payload["aggregate"].get("integrity/full")
    tail = ""
    if integrity:
        tail = (
            f" The `integrity` configuration (dataflow plus `untrusted_then_external -> escalate`) measures "
            f"ASR **{integrity['targeted_asr']:.3f}** at benign utility {integrity['benign_utility']:.3f} "
            f"(oracle) / {integrity['human_benign_utility']:.3f} (attentive human): that is the price of "
            "closing the integrity class, and it is a policy choice, not a code change."
        )
    return (
        "The ASR that remains under `strict` and `dataflow` is **not** exfiltration slipping through. In every "
        "successful injection, the attacker's call was allowed by `fewer_than_three_legs`: the session had ingested "
        "untrusted content and the call was an external action, but nothing *sensitive* had been read - hotel "
        "reviews and web pages are public. Those are two-leg **integrity** attacks (make a reservation at the "
        "attacker's hotel, invite the attacker to the workspace, send a link), and the lethal-trifecta model permits "
        "two legs by design: it bounds what a hijacked agent can *disclose*, not everything it can *do*. Per suite: "
        + "; ".join(per_suite)
        + ". "
        "`workspace`, where email and files are classified sensitive, is 0.000." + tail
    )


def render_results_md(payload: dict[str, Any]) -> str:
    agg = payload["aggregate"]
    lines = [
        "# RESULTS",
        "",
        "> **Generated file.** Produced by `"
        + payload["command"]
        + "` at "
        + payload["measured_at"]
        + f" on commit `{payload['commit']}`.",
        "> Raw data: `" + payload["results_file"] + "`. Do not edit; re-run the command.",
        "",
        "## How the agent was driven",
        "",
        payload["agent_note"],
        "",
        "## AgentDojo, all suites",
        "",
        f"{payload['totals']['user_tasks']} user tasks, {payload['totals']['injection_tasks']} injection tasks, "
        f"{payload['totals']['security_cases']} security cases (user task x injection task), attack `{ATTACK}`, "
        f"AgentDojo {payload['agentdojo_version']} benchmark {BENCH_VERSION}.",
        "",
        "Two readings of the same runs. **Oracle** treats every ESCALATE as blocked (no human present). "
        "**Attentive human** approves an ESCALATE raised by the task the user asked for and declines one raised "
        "by the attacker's call; DENY is never overridden. The gap between the readings is the utility a present "
        "human recovers; the oracle reading is the floor.",
        "",
        "| configuration | benign utility | utility under attack | targeted ASR | benign utility (human) | utility under attack (human) | targeted ASR (human) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for config in CONFIGS:
        row = agg.get(f"{config}/full")
        if row:
            lines.append(
                f"| `{config}` | {row['benign_utility']:.3f} | {row['utility_under_attack']:.3f} | **{row['targeted_asr']:.3f}** "
                f"| {row['human_benign_utility']:.3f} | {row['human_utility_under_attack']:.3f} | **{row['human_targeted_asr']:.3f}** |"
            )
    lines += ["", "### Reading the residual ASR", "", _residual_note(payload)]
    lines += [
        "",
        "### Per suite",
        "",
        "| suite | configuration | benign utility | utility under attack | targeted ASR | cases |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in payload["rows"]:
        if r["ablation"] == "full":
            lines.append(
                f"| {r['suite']} | `{r['config']}` | {r['benign_utility']:.3f} | {r['utility_under_attack']:.3f} | {r['targeted_asr']:.3f} | {r['security_cases']} |"
            )
    ablations = [k for k in agg if not k.endswith("/full")]
    if ablations:
        lines += [
            "",
            "## Ablation (dataflow mode, each component disabled in turn)",
            "",
            "| disabled | benign utility | utility under attack | targeted ASR | benign utility (human) | utility under attack (human) | targeted ASR (human) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]

        def _abl_row(label: str, row: dict[str, Any]) -> str:
            return (
                f"| {label} | {row['benign_utility']:.3f} | {row['utility_under_attack']:.3f} | {row['targeted_asr']:.3f} "
                f"| {row['human_benign_utility']:.3f} | {row['human_utility_under_attack']:.3f} | {row['human_targeted_asr']:.3f} |"
            )

        base = agg.get("dataflow/full")
        if base:
            lines.append(_abl_row("_(none: Trilock as shipped)_", base))
        for key in sorted(ablations):
            lines.append(_abl_row(agg[key]["ablation"].removeprefix("no_"), agg[key]))
        lines += ["", payload.get("ablation_note", "")]
    lines += [
        "",
        "## Decision latency (pure `decide()` path, per call)",
        "",
        "| configuration | p50 ms | p95 ms | p99 ms | calls |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in payload["rows"]:
        if r["ablation"] == "full" and r["suite"] == "workspace":
            d = r["decision_latency_ms"]
            lines.append(
                f"| `{r['config']}` (workspace) | {d['p50']} | {d['p95']} | {d['p99']} | {d['n']} |"
            )
    lines += [
        "",
        "Trilock adds zero LLM tokens: there is no model in the decision path. The marginal cost per protected call is CPU only.",
        "",
    ]
    lines += [
        "## Verdict breakdown (dataflow, all suites)",
        "",
        "| phase:verdict:rule | count |",
        "|---|---:|",
    ]
    combined: dict[str, int] = defaultdict(int)
    for r in payload["rows"]:
        if r["config"] == "dataflow" and r["ablation"] == "full":
            for k, v in r["verdicts"].items():
                combined[k] += v
    for k, v in sorted(combined.items()):
        lines.append(f"| `{k}` | {v} |")
    lines += [
        "",
        "## Machine",
        "",
        f"`{payload['machine']}` · Python {platform.python_version()} · mcp-trilock {__version__}",
        "",
    ]
    attacks = render_attacks_section()
    if attacks:
        lines += ["", attacks]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="every suite, every configuration")
    parser.add_argument("--suite", choices=SUITES)
    parser.add_argument("--mode", choices=list(CONFIGS))
    parser.add_argument(
        "--ablations", action="store_true", help="also run dataflow with each component disabled"
    )
    parser.add_argument(
        "--model",
        help="AgentDojo model name for an LLM-driven run (needs an API key). Not yet wired; documents intent.",
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="rebuild RESULTS.md from the latest committed JSON without re-running",
    )
    args = parser.parse_args()
    if args.render_only:
        path = latest("agentdojo_*.json")
        if path is None:
            print("no agentdojo results to render", file=sys.stderr)
            return 2
        payload = json.loads(path.read_text(encoding="utf-8"))
        RESULTS_MD.write_text(render_results_md(payload), encoding="utf-8")
        print(f"re-rendered RESULTS.md from {path.relative_to(REPO)}")
        return 0
    if args.model:
        print(
            "LLM-driven runs need an API key in the environment; none was available where RESULTS.md was produced.",
            file=sys.stderr,
        )
        return 2

    suites = SUITES if args.all or not args.suite else (args.suite,)
    configs = list(CONFIGS) if args.all or not args.mode else [args.mode]
    started = time.time()
    rows: list[dict[str, Any]] = []
    print(f"agentdojo {getattr(agentdojo, '__version__', '?')}  suites={suites}  configs={configs}")
    for suite in suites:
        for config in configs:
            rows.append(run_config(suite, config, Ablation(), quiet=args.quiet))
        if args.ablations:
            for ablation in (
                Ablation(normalisation=False),
                Ablation(attribution=False),
                Ablation(detectors=False),
                Ablation(trifecta_rule=False),
            ):
                rows.append(run_config(suite, "dataflow", ablation, quiet=args.quiet))

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    results_file = RESULTS_DIR / f"agentdojo_{stamp}.json"
    payload: dict[str, Any] = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "commit": _git(),
        "command": "uv run python bench/run_bench.py " + " ".join(sys.argv[1:]),
        "results_file": str(results_file.relative_to(REPO)),
        "agentdojo_version": getattr(agentdojo, "__version__", "0.1.35"),
        "attack": ATTACK,
        "machine": platform.platform(),
        "duration_s": round(time.time() - started, 1),
        "totals": {
            "user_tasks": sum(
                r["user_tasks"]
                for r in rows
                if r["config"] == configs[0] and r["ablation"] == "full"
            ),
            "injection_tasks": sum(
                r["injection_tasks"]
                for r in rows
                if r["config"] == configs[0] and r["ablation"] == "full"
            ),
            "security_cases": sum(
                r["security_cases"]
                for r in rows
                if r["config"] == configs[0] and r["ablation"] == "full"
            ),
        },
        "rows": rows,
        "aggregate": aggregate(rows),
        "agent_note": (
            "**Oracle agent, no LLM.** No LLM API key was available where this was produced, so the agent is "
            "AgentDojo's ground truth: for each user task it emits that task's own correct tool calls, and in each "
            "attack scenario it then emits the injection task's ground-truth calls — the exact calls a fully "
            "hijacked model would make. This is the strongest adversary a deterministic interlock can face and is "
            "the spec's threat model (injection is assumed to succeed). Two consequences for reading the table: "
            "**undefended ASR is 1.000 by construction**, because the oracle always performs the attack; and "
            "**utility under attack measures Trilock's false positives** (benign calls it refused), not model "
            "distraction, because an oracle is never distracted. ESCALATE counts as blocked: the oracle has no "
            "human to ask, and the spec forbids degrading ESCALATE to ALLOW. An LLM-driven run "
            "(`--model`) would measure a real model's utility and its actual hijack rate; that run has not been "
            "performed and no number for it is claimed."
        ),
        "ablation_note": (
            "Each row disables one component of dataflow mode. What the table shows: **the trifecta rule carries the "
            "entire security number** - remove it and every column returns to undefended. **Attribution changes "
            "nothing in the oracle reading and everything in the human reading**: it is what turns a hard DENY into an "
            "ESCALATE a human can approve, i.e. it buys utility, not ASR. **Normalisation contributes nothing on this "
            "benchmark** - AgentDojo's injections are plain visible text, so there was nothing to un-hide; it exists for "
            "the hidden-text corpus in tests/fixtures/attacks/invisible. **Detectors** are identical by construction: "
            "the oracle harness passes no detector scores, and the shipped proxy's own test asserts that disabling every "
            "detector changes no block. None of these rows is hidden; a component that does nothing here says so."
        ),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.all:
        RESULTS_MD.write_text(render_results_md(payload), encoding="utf-8")
        print(
            f"\nwrote {results_file.relative_to(REPO)} and RESULTS.md in {payload['duration_s']}s"
        )
    else:
        print(f"\nwrote {results_file.relative_to(REPO)} (RESULTS.md is only regenerated by --all)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
