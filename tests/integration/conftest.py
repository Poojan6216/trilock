"""Helpers for tests that drive a real Trilock proxy over real upstream servers.

These are async context managers rather than pytest fixtures on purpose.
pytest-asyncio runs an async generator fixture's setup and teardown in
different tasks, and anyio task groups — which the upstream supervisor and the
router's fan-out both use — must be exited in the task that entered them.
Opening the proxy inside the test body keeps one task across the whole
lifecycle.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import Client

from trilock.config import StdioUpstream, TrilockConfig
from trilock.proxy.router import Router
from trilock.proxy.server import build_proxy
from trilock.proxy.upstream import UpstreamPool, open_pool

FIXTURE_SERVERS = Path(__file__).resolve().parents[1] / "fixtures" / "servers"


def stdio_upstream(script: str, **env: str) -> StdioUpstream:
    """An upstream that launches one of the fixture servers."""
    return StdioUpstream(command=sys.executable, args=(str(FIXTURE_SERVERS / script),), env=env)


def two_server_config(**env: str) -> TrilockConfig:
    """mail + notes, the pair the demo scenario needs."""
    return TrilockConfig(
        servers={
            "mail": stdio_upstream("mail_server.py", **env),
            "notes": stdio_upstream("notes_server.py", **env),
        }
    )


@asynccontextmanager
async def proxied(config: TrilockConfig | None = None) -> AsyncIterator[tuple[Client, Router]]:
    """A client connected in-process to a Trilock proxy over the given upstreams."""
    async with (
        build_proxy(config if config is not None else two_server_config()) as (server, router),
        Client(server) as client,
    ):
        yield client, router


@asynccontextmanager
async def direct(config: TrilockConfig | None = None) -> AsyncIterator[UpstreamPool]:
    """Clients connected straight to each fixture server, bypassing Trilock."""
    async with open_pool(config if config is not None else two_server_config()) as pool:
        yield pool
