"""Task 0.3 verification: connect to two real stdio MCP servers and list their tools."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from trilock.config import StdioUpstream, TrilockConfig
from trilock.proxy.upstream import UpstreamState, UpstreamUnavailableError, open_pool

FIXTURE_SERVERS = Path(__file__).resolve().parents[1] / "fixtures" / "servers"


def stdio(script: str) -> StdioUpstream:
    return StdioUpstream(command=sys.executable, args=(str(FIXTURE_SERVERS / script),))


@pytest.fixture
def two_servers() -> TrilockConfig:
    return TrilockConfig(
        servers={"mail": stdio("mail_server.py"), "notes": stdio("notes_server.py")}
    )


async def test_both_upstreams_connect_and_list_tools(two_servers: TrilockConfig) -> None:
    async with open_pool(two_servers) as pool:
        assert set(pool.ready) == {"mail", "notes"}

        mail_tools = await pool["mail"].client().list_tools()
        assert {t.name for t in mail_tools.tools} == {"search", "send", "drafts"}

        notes_tools = await pool["notes"].client().list_tools()
        assert {t.name for t in notes_tools.tools} == {"read_note", "write_note", "list_notes"}


async def test_upstreams_negotiate_a_protocol_version(two_servers: TrilockConfig) -> None:
    async with open_pool(two_servers) as pool:
        for name in ("mail", "notes"):
            upstream = pool[name]
            assert upstream.state is UpstreamState.READY
            # 'auto' mode probes server/discover first, so a modern SDK server
            # lands on 2026-07-28; older servers fall back to the handshake.
            assert upstream.protocol_version in {"2026-07-28", "2025-11-25", "2025-06-18"}
            assert upstream.server_info is not None
            assert upstream.generation == 1


async def test_a_call_reaches_the_upstream(two_servers: TrilockConfig) -> None:
    async with open_pool(two_servers) as pool:
        result = await pool["mail"].client().call_tool("search", {"query": "sprint"})
        assert not result.is_error
        text = "".join(c.text for c in result.content if c.type == "text")
        assert "Sprint planning notes" in text


async def test_one_dead_upstream_does_not_stop_the_others() -> None:
    """A broken upstream is marked unavailable; the healthy one keeps serving."""
    config = TrilockConfig(
        servers={
            "mail": stdio("mail_server.py"),
            "broken": StdioUpstream(command=sys.executable, args=("-c", "raise SystemExit(3)")),
        }
    )
    async with open_pool(config) as pool:
        assert pool["mail"].available
        assert not pool["broken"].available
        assert pool["broken"].state is UpstreamState.UNAVAILABLE
        assert pool["broken"].last_error
        with pytest.raises(UpstreamUnavailableError, match="broken"):
            pool["broken"].client()
        # The healthy upstream is unaffected.
        assert not (await pool["mail"].client().call_tool("search", {"query": ""})).is_error


async def test_unknown_upstream_is_a_clean_error(two_servers: TrilockConfig) -> None:
    async with open_pool(two_servers) as pool:
        with pytest.raises(UpstreamUnavailableError, match="no such upstream"):
            pool["nope"]
        assert "mail" in pool
        assert "nope" not in pool


async def test_status_snapshot_is_json_safe(two_servers: TrilockConfig) -> None:
    async with open_pool(two_servers) as pool:
        import json

        json.dumps(pool.statuses())  # raises if a value is not serialisable
        assert {s["server"] for s in pool.statuses()} == {"mail", "notes"}


async def test_reconnect_rebuilds_the_connection(two_servers: TrilockConfig) -> None:
    """A reconnect request drops the client and the supervisor rebuilds it."""
    import anyio

    async with open_pool(two_servers, health_interval=0.05) as pool:
        mail = pool["mail"]
        assert mail.generation == 1
        first_pid_result = await mail.client().call_tool("search", {"query": "sprint"})
        assert not first_pid_result.is_error

        mail.request_reconnect("test-initiated")
        with anyio.fail_after(20):
            while mail.generation < 2:
                await anyio.sleep(0.02)

        assert mail.available
        assert not (await mail.client().call_tool("search", {"query": "sprint"})).is_error


async def test_backoff_is_bounded_and_jittered() -> None:
    """A permanently broken upstream keeps retrying without spinning."""
    import anyio

    config = TrilockConfig(
        servers={
            "broken": StdioUpstream(command=sys.executable, args=("-c", "raise SystemExit(3)"))
        }
    )
    async with open_pool(config) as pool:
        broken = pool["broken"]
        attempts_at_start = broken.generation
        await anyio.sleep(1.5)
        # Backoff starts at 0.5s and doubles, so a 1.5s window admits a couple of
        # attempts, never a hot loop. generation only counts *successful*
        # connects, so it must not have moved at all.
        assert broken.generation == attempts_at_start == 0
        assert broken.state is UpstreamState.UNAVAILABLE


async def test_health_probe_does_not_churn_a_healthy_modern_connection(
    two_servers: TrilockConfig,
) -> None:
    """Regression: the liveness probe must be valid on the negotiated revision.

    `ping` is removed in 2026-07-28 (SEP-2577). Using it as the probe made a
    healthy modern upstream look dead every health interval, reconnecting in a
    loop. With a 50ms interval this window runs ~20 probes; generation must
    still be 1.
    """
    import anyio

    async with open_pool(two_servers, health_interval=0.05) as pool:
        mail = pool["mail"]
        assert mail.protocol_version is not None
        await anyio.sleep(1.0)
        assert mail.generation == 1, (
            f"health probe churned the connection on {mail.protocol_version}: "
            f"{mail.generation} connects, last error {mail.last_error}"
        )
        assert mail.available
