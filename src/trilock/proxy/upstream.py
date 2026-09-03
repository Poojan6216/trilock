"""Connections to the real MCP servers behind the proxy.

One `Upstream` per configured server, each supervised by its own task so that
connect, reconnect and teardown all happen in the task that owns the client's
cancel scope. A dead upstream is marked unavailable and retried with backoff;
it never takes the proxy down with it, because the whole point of Trilock is to
sit in the path of a working agent without becoming a new way for that agent to
break.
"""

from __future__ import annotations

import random
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters

from trilock import __version__, log
from trilock.config import HttpUpstream, StdioUpstream, TrilockConfig

if TYPE_CHECKING:
    from trilock.config import Upstream as UpstreamConfig

_log = log.get("proxy.upstream")

CLIENT_INFO: Final = types.Implementation(name="trilock", version=__version__)

INITIAL_BACKOFF: Final[float] = 0.5
MAX_BACKOFF: Final[float] = 30.0
HEALTH_INTERVAL: Final[float] = 30.0
CONNECT_TIMEOUT: Final[float] = 30.0


class UpstreamState(StrEnum):
    """Lifecycle of a single upstream connection."""

    PENDING = "pending"
    READY = "ready"
    UNAVAILABLE = "unavailable"
    CLOSED = "closed"


class UpstreamUnavailableError(RuntimeError):
    """A request was made against an upstream that is not currently connected."""

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"upstream {name!r} is unavailable: {reason}")
        self.name = name
        self.reason = reason


class Upstream:
    """A supervised connection to one upstream MCP server."""

    def __init__(
        self, name: str, config: UpstreamConfig, *, health_interval: float = HEALTH_INTERVAL
    ) -> None:
        self.name = name
        self.config = config
        self.state = UpstreamState.PENDING
        self.last_error: str | None = None
        self.generation = 0
        """Increments on every successful connect; lets callers detect a reconnect."""
        self.protocol_version: str | None = None
        self.server_info: types.Implementation | None = None
        self._client: Client | None = None
        self._health_interval = health_interval
        self._settled = anyio.Event()
        """Set once the first connect attempt has resolved, either way."""
        self._reconnect = anyio.Event()
        self._closing = anyio.Event()

    # -- accessors -------------------------------------------------------

    @property
    def available(self) -> bool:
        return self.state is UpstreamState.READY and self._client is not None

    def client(self) -> Client:
        """The live client, or raise `UpstreamUnavailableError`."""
        if self._client is None or self.state is not UpstreamState.READY:
            raise UpstreamUnavailableError(self.name, self.last_error or self.state.value)
        return self._client

    def status(self) -> dict[str, Any]:
        """A JSON-safe snapshot, for logs and ``trilock check``."""
        return {
            "server": self.name,
            "state": self.state.value,
            "transport": self.config.transport,
            "protocol_version": self.protocol_version,
            "server_info": self.server_info.name if self.server_info else None,
            "generation": self.generation,
            "last_error": self.last_error,
        }

    # -- supervision -----------------------------------------------------

    async def wait_settled(self) -> None:
        """Block until the first connect attempt has either succeeded or failed."""
        await self._settled.wait()

    def request_reconnect(self, reason: str) -> None:
        """Ask the supervisor to drop and rebuild the connection.

        Called by request paths that observe a transport-level failure; the
        supervisor owns the actual teardown so cancel scopes stay in one task.
        """
        if self._closing.is_set():
            return
        _log.warning("reconnect requested", extra={"server": self.name, "reason": reason})
        self._reconnect.set()

    def close(self) -> None:
        self._closing.set()
        self._reconnect.set()

    async def supervise(self) -> None:
        """Own this upstream's connection for the life of the pool.

        Connect, hold, health-check, and on any failure back off and try again.
        Every exception is contained here: this coroutine only exits when the
        pool is closing or its task is cancelled.
        """
        backoff = INITIAL_BACKOFF
        while not self._closing.is_set():
            self._reconnect = anyio.Event()
            try:
                async with await self._open() as client:
                    self._adopt(client)
                    backoff = INITIAL_BACKOFF
                    await self._hold(client)
            except anyio.get_cancelled_exc_class():
                raise
            except Exception as exc:
                self._fail(exc)
            else:
                self._fail(None)
            finally:
                self._client = None
                self._settled.set()
            if self._closing.is_set():
                break
            await anyio.sleep(backoff * (0.5 + random.random()))  # noqa: S311 - jitter, not crypto
            backoff = min(backoff * 2, MAX_BACKOFF)
        self.state = UpstreamState.CLOSED

    async def _open(self) -> Client:
        """Build the client for this upstream's transport."""
        if isinstance(self.config, StdioUpstream):
            params = StdioServerParameters(
                command=self.config.command,
                args=list(self.config.args),
                env=dict(self.config.env) or None,
                cwd=self.config.cwd,
            )
            server: Any = params
        else:
            assert isinstance(self.config, HttpUpstream)  # the union is exhaustive
            server = self.config.url
            if self.config.headers:
                from mcp.client.streamable_http import streamable_http_client
                from mcp.shared._httpx_utils import create_mcp_http_client

                server = streamable_http_client(
                    self.config.url,
                    http_client=create_mcp_http_client(headers=dict(self.config.headers)),
                )
        return Client(
            server,
            client_info=CLIENT_INFO,
            # 'auto' probes server/discover (2026-07-28) and falls back to the
            # initialize handshake (2025-11-25 and earlier), so one code path
            # serves both revisions the spec requires.
            mode="auto",
            # A proxy must not cache on the downstream client's behalf: a stale
            # tools/list would mask a definition change that tool pinning
            # (task 0.6) exists to catch.
            cache=None,
        )

    def _adopt(self, client: Client) -> None:
        self._client = client
        self.state = UpstreamState.READY
        self.last_error = None
        self.generation += 1
        self.protocol_version = client.protocol_version
        self.server_info = client.server_info
        self._settled.set()
        _log.info("upstream connected", extra=self.status())

    def _fail(self, exc: BaseException | None) -> None:
        self.state = UpstreamState.UNAVAILABLE
        self.last_error = f"{type(exc).__name__}: {exc}" if exc is not None else "connection closed"
        _log.warning("upstream unavailable", extra=self.status())

    async def _hold(self, client: Client) -> None:
        """Keep the connection open, pinging periodically, until it breaks."""
        while not self._closing.is_set():
            with anyio.move_on_after(self._health_interval) as scope:
                await self._reconnect.wait()
            if not scope.cancelled_caught:
                return  # a reconnect was requested
            await self._probe(client)  # raises on a broken transport

    @staticmethod
    async def _probe(client: Client) -> None:
        """Liveness probe that is valid on every protocol revision.

        Not `ping`: SEP-2577 removes it in 2026-07-28, so on a modern
        connection it fails against a perfectly healthy server and would drive
        an endless reconnect loop. `tools/list` is served by every revision we
        speak, and re-reading the listing is exactly what tool pinning wants.
        """
        await client.list_tools()


class UpstreamPool:
    """Every configured upstream, supervised together."""

    def __init__(self, config: TrilockConfig, *, health_interval: float = HEALTH_INTERVAL) -> None:
        self.upstreams: dict[str, Upstream] = {
            name: Upstream(name, cfg, health_interval=health_interval)
            for name, cfg in config.servers.items()
        }

    def __getitem__(self, name: str) -> Upstream:
        try:
            return self.upstreams[name]
        except KeyError:
            raise UpstreamUnavailableError(name, "no such upstream server is configured") from None

    def __contains__(self, name: str) -> bool:
        return name in self.upstreams

    @property
    def ready(self) -> Mapping[str, Upstream]:
        return {n: u for n, u in self.upstreams.items() if u.available}

    def statuses(self) -> list[dict[str, Any]]:
        return [u.status() for u in self.upstreams.values()]

    async def wait_settled(self, settle_budget: float = CONNECT_TIMEOUT) -> None:
        """Wait until every upstream's first connect attempt has resolved.

        Returns on timeout rather than raising: a slow or dead upstream must
        not stop the proxy from serving the others.
        """
        with anyio.move_on_after(settle_budget):
            async with anyio.create_task_group() as tg:
                for upstream in self.upstreams.values():
                    tg.start_soon(upstream.wait_settled)


@asynccontextmanager
async def open_pool(
    config: TrilockConfig, *, health_interval: float = HEALTH_INTERVAL, wait: bool = True
) -> AsyncIterator[UpstreamPool]:
    """Open every configured upstream and keep them supervised for the block."""
    pool = UpstreamPool(config, health_interval=health_interval)
    async with anyio.create_task_group() as tg:
        for upstream in pool.upstreams.values():
            tg.start_soon(upstream.supervise)
        try:
            if wait:
                await pool.wait_settled()
            yield pool
        finally:
            for upstream in pool.upstreams.values():
                upstream.close()
            tg.cancel_scope.cancel()
