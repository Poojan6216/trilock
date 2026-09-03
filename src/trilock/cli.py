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
from trilock.config import ConfigError, TrilockConfig, find_config, load_config

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
) -> None:
    """Validate configuration and policy, and print the resolved tool table."""
    log.configure(log_level)
    cfg = _load(config)
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


@app.command()
def replay(
    log_path: Annotated[Path, typer.Argument(help="Path to an audit JSONL log.")],
    config: ConfigOpt = None,
) -> None:
    """Re-run the decision function over a recorded log and assert it reproduces."""
    log.configure("WARNING")
    _ = _load(config)
    typer.echo(f"trilock: replay is implemented in Phase 5 (would replay {log_path})", err=True)
    raise typer.Exit(3)


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
