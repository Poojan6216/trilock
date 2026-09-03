"""``trilock`` — the command line.

Subcommands:
    serve    run the proxy (stdio or streamable HTTP)
    check    validate config and policy; inspect and repin tool definitions
    replay   re-derive every decision in an audit log and assert it reproduces
    bench    run the AgentDojo harness
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer

from trilock import __version__, log
from trilock.approval import drop_approval
from trilock.config import ConfigError, TrilockConfig, find_config, load_config
from trilock.policy.model import Policy, PolicyError, load_policy

app = typer.Typer(
    name="trilock",
    help="An MCP proxy that makes the lethal trifecta structurally impossible.",
    no_args_is_help=True,
    add_completion=False,
)

ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to trilock.yaml.", show_default=False),
]
LogLevelOpt = Annotated[
    str, typer.Option("--log-level", help="Log verbosity.", envvar="TRILOCK_LOG_LEVEL")
]


def _load(path: Path | None) -> TrilockConfig:
    """Load config or exit 2 with a message on stderr."""
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.echo(f"trilock: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit.")] = False,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)


@app.command()
def serve(
    config: ConfigOpt = None,
    log_level: LogLevelOpt = "INFO",
    transport: Annotated[str, typer.Option("--transport", help="stdio or http.")] = "stdio",
) -> None:
    """Run the proxy.

    On stdio, stdout carries the JSON-RPC frames and nothing else: logs go to
    stderr, and stray library output is diverted there too.
    """
    log.configure(log_level)
    cfg = _load(config)
    if transport != "stdio":
        typer.echo(f"trilock: unsupported transport {transport!r}", err=True)
        raise typer.Exit(2)
    from trilock.proxy.server import serve_stdio

    asyncio.run(serve_stdio(cfg))


@app.command()
def check(
    config: ConfigOpt = None,
    log_level: LogLevelOpt = "WARNING",
    repin: Annotated[
        bool,
        typer.Option(
            "--repin",
            help="Connect to every upstream and accept the tool definitions as they are now.",
        ),
    ] = False,
    download_models: Annotated[
        bool,
        typer.Option(
            "--download-models",
            help="Fetch the Prompt Guard 2 ONNX model once, verifying its pinned digest.",
        ),
    ] = False,
) -> None:
    """Validate configuration and policy, and print the resolved tool table."""
    log.configure(log_level)
    cfg = _load(config)
    if download_models:
        from trilock.detect import promptguard

        typer.echo(f"downloading {promptguard.MODEL_REPO} into {cfg.detectors.model_dir} ...")
        try:
            for path in promptguard.download(cfg.detectors.model_dir):
                typer.echo(f"  {path.name:28} {path.stat().st_size:>12,} bytes")
        except Exception as exc:
            typer.echo(f"trilock: model download failed: {exc}", err=True)
            raise typer.Exit(6) from exc
        typer.echo("verified. Enable with `detectors: {promptguard: true}` in trilock.yaml.")
        typer.echo(
            "note: on the reference machine a 4 KB document exceeds the 150 ms budget "
            "and will time out (safely) - see bench/results/detector_latency.json."
        )
    source = cfg.source_path or find_config()
    typer.echo(f"config: {source or '<defaults, no file found>'}")
    typer.echo(f"upstream servers: {len(cfg.servers)}")
    for name, upstream in sorted(cfg.servers.items()):
        detail = (
            f"stdio: {upstream.command}"
            if upstream.transport == "stdio"
            else f"http: {upstream.url}"
        )
        typer.echo(f"  {name}  ({detail})")
    typer.echo(f"policy: {cfg.policy or '<none — proxy runs in passthrough>'}")
    typer.echo(f"pins: {cfg.pins.path if cfg.pins.enabled else '<disabled>'}")

    policy: Policy | None = None
    if cfg.policy is not None:
        try:
            policy = load_policy(cfg.policy)
        except PolicyError as exc:
            typer.echo(f"trilock: {exc}", err=True)
            raise typer.Exit(2) from exc
        typer.echo(f"mode: {policy.mode.value}")
        typer.echo(f"unclassified: {policy.unclassified_verdict.value}")
        typer.echo(f"rules: {len(policy.rules)} (first match wins, then default_deny)")
        for rule in policy.rules:
            typer.echo(f"  {rule.id:24} -> {rule.then.value}")
    if cfg.servers:
        raise typer.Exit(asyncio.run(_inspect_upstreams(cfg, policy, repin=repin)))
    if policy is not None:
        _print_tool_table(policy, sorted(policy.tools))


def _print_tool_table(policy: Policy, tools: list[str]) -> None:
    """The resolved classification for every tool, as policy actually sees it."""
    typer.echo("")
    typer.echo(f"{'tool':32} {'reads':10} {'sensitivity':12} {'effect':9} scope")
    typer.echo("-" * 84)
    for tool, cls in policy.resolved_table(tools):
        if cls is None:
            floor = policy.unclassified_verdict.value
            typer.echo(f"{tool:32} {'-':10} {'-':12} {'-':9} <unclassified -> {floor}>")
            continue
        reads = cls.reads.value if cls.reads else "-"
        scope = ", ".join(cls.scope) if cls.scope else "-"
        typer.echo(f"{tool:32} {reads:10} {cls.sensitivity.value:12} {cls.effect.value:9} {scope}")


async def _inspect_upstreams(cfg: TrilockConfig, policy: Policy | None, *, repin: bool) -> int:
    """List every upstream's tools, reporting pin violations. Returns an exit code."""
    from trilock.proxy.server import build_proxy

    async with build_proxy(cfg) as (_server, router, _guard):
        tools = await router.list_tools()
        down: list[str] = []
        for status in router.pool.statuses():
            state = status["state"]
            typer.echo(f"  {status['server']}: {state} ({status['protocol_version'] or '-'})")
            if state != "ready":
                down.append(status["server"])
                typer.echo(f"      reason: {status['last_error']}", err=True)
        typer.echo(f"tools: {len(tools.tools)}")
        if policy is not None:
            _print_tool_table(policy, [t.name for t in tools.tools])
        else:
            for tool in sorted(tools.tools, key=lambda t: t.name):
                typer.echo(f"  {tool.name}")
        pins = router.pins
        if pins is None:
            return 0
        if repin:
            for cleared in pins.repin():
                typer.echo(f"re-pinned {cleared.key}")
            pins.save()
            return 0
        if pins.violations:
            typer.echo("", err=True)
            for violation in pins.violations.values():
                typer.echo(f"PIN VIOLATION: {violation.describe()}", err=True)
            return 4
        if down:
            typer.echo(f"unavailable upstreams: {', '.join(down)}", err=True)
            return 5
        return 0


@app.command()
def approve(
    approval_id: Annotated[str, typer.Argument(help="The id printed in the tool error.")],
    config: ConfigOpt = None,
) -> None:
    """Approve, once, a call that Trilock held because the client could not ask you.

    Drops a token in the state directory. The running proxy consumes it on the
    next identical call and refuses the one after.
    """
    log.configure("WARNING")
    cfg = _load(config)
    try:
        token = drop_approval(cfg.state_dir, approval_id)
    except ValueError as exc:
        typer.echo(f"trilock: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"approved once: {approval_id}  ({token})")


@app.command()
def replay(
    log_path: Annotated[Path, typer.Argument(help="Path to an audit JSONL log.")],
    config: ConfigOpt = None,
) -> None:
    """Re-run the decision function over a recorded log and assert it reproduces.

    Exit 0 when every recorded verdict is reproduced and the hash chain is
    intact; 7 otherwise. A mismatch is a build failure.
    """
    log.configure("WARNING")
    cfg = _load(config)
    if cfg.policy is None:
        typer.echo(
            "trilock: replay needs the policy the log was recorded under (config.policy)", err=True
        )
        raise typer.Exit(2)
    from trilock.audit.replay import replay as run_replay
    from trilock.proxy.guard import policy_digest

    policy = load_policy(cfg.policy)
    report = run_replay(log_path, policy, policy_hash=policy_digest(policy))
    typer.echo(f"records: {report.records}  decisions: {report.decisions}")
    for brk in report.chain_breaks:
        typer.echo(f"CHAIN BREAK line {brk.line}: {brk.reason}", err=True)
    for miss in report.mismatches:
        typer.echo(
            f"MISMATCH line {miss.line} {miss.tool} {miss.call_id}: "
            f"recorded {miss.recorded}/{miss.recorded_rule}, "
            f"replayed {miss.replayed}/{miss.replayed_rule}",
            err=True,
        )
    if report.policy_hash_mismatches:
        typer.echo(
            f"note: {report.policy_hash_mismatches} record(s) were made under "
            "a different policy hash",
            err=True,
        )
    if report.ok:
        typer.echo("replay: every decision reproduced; chain intact")
        raise typer.Exit(0)
    raise typer.Exit(7)


@app.command()
def bench(
    config: ConfigOpt = None,
) -> None:
    """Run the AgentDojo benchmark harness."""
    log.configure("WARNING")
    _ = _load(config)
    typer.echo("trilock: bench is implemented in Phase 5; see bench/run_bench.py", err=True)
    raise typer.Exit(3)


def main() -> None:
    """Console-script entry point."""
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
