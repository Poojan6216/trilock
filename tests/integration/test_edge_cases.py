"""Task 7.2: nothing crashes the proxy; every failure is logged and returns a valid MCP error."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import mcp_types as types
from mcp import Client

from tests.fixtures.servers import journal
from tests.integration.conftest import guarded, proxied, stdio_upstream
from trilock.config import TrilockConfig
from trilock.proxy.server import build_proxy

POLICIES = Path(__file__).resolve().parents[2] / "policies"
REPO = Path(__file__).resolve().parents[2]


def chaos_config(tmp_path: Path, *, policy: str | None = None) -> TrilockConfig:
    return TrilockConfig(
        servers={
            "chaos": stdio_upstream(
                "chaos_server.py", **{journal.ENV_VAR: str(tmp_path / "j.jsonl")}
            ),
            "notes": stdio_upstream("notes_server.py", TRILOCK_FIXTURE_NOTES_DIR=str(tmp_path)),
        },
        policy=POLICIES / policy if policy else None,
        source_path=tmp_path / "trilock.yaml",
    )


def _text(result: types.CallToolResult) -> str:
    return "".join(c.text for c in result.content if isinstance(c, types.TextContent))


async def test_upstream_dying_mid_call_is_an_error_not_a_crash(tmp_path: Path) -> None:
    async with proxied(chaos_config(tmp_path)) as (client, router):
        result = await client.call_tool("chaos.die", {"code": 3})
        assert result.is_error, "a dead upstream must surface as a tool error"
        # The rest of the proxy is untouched.
        assert not (await client.call_tool("notes.list_notes", {})).is_error
        # And the supervisor brings the upstream back.
        with anyio.fail_after(30):
            while not router.pool["chaos"].available or router.pool["chaos"].generation < 2:
                await anyio.sleep(0.05)
        assert not (await client.call_tool("chaos.ok", {})).is_error


async def test_a_huge_result_is_forwarded_and_the_ledger_stays_bounded(tmp_path: Path) -> None:
    """8 MB through the whole path: normalise, fingerprint, label, return."""
    async with guarded(chaos_config(tmp_path, policy="monitor.yaml")) as (client, _, guard):
        result = await client.call_tool("chaos.huge", {"megabytes": 8}, read_timeout_seconds=120)
        assert not result.is_error
        assert len(_text(result)) >= 8 * 1024 * 1024
        state = next(iter(guard.sessions._states.values()))
        entry = next(iter(state.ledger))
        # The fingerprint is capped regardless of the content size.
        assert len(entry.ngrams) <= guard.config.ledger.max_ngrams_per_source


async def test_deeply_nested_arguments_and_results(tmp_path: Path) -> None:
    payload: dict = {"leaf": "x"}
    for i in range(60):
        payload = {f"level{i}": [payload, {"k": i}]}
    async with guarded(chaos_config(tmp_path, policy="monitor.yaml")) as (client, _, guard):
        result = await client.call_tool("chaos.echo_nested", {"payload": payload})
        assert not result.is_error
        assert result.structured_content is not None
        # Attribution walked the whole structure without recursion trouble.
        ctx = guard.prepare(None, "chaos.echo_nested", {"payload": payload})
        assert any(
            p.startswith("$.payload")
            for p, _ in __import__(
                "trilock.taint.propagate", fromlist=["walk_arguments"]
            ).walk_arguments({"payload": payload})
        )
        assert ctx.attribution is not None


async def test_binary_content_blocks_pass_through_untouched(tmp_path: Path) -> None:
    async with guarded(chaos_config(tmp_path, policy="monitor.yaml")) as (client, _, _guard):
        result = await client.call_tool("chaos.image", {})
        assert not result.is_error
        kinds = [c.type for c in result.content]
        assert "image" in kinds and "text" in kinds
        image = next(c for c in result.content if isinstance(c, types.ImageContent))
        assert image.mime_type == "image/png" and image.data.startswith("iVBOR")


async def test_concurrent_calls_in_one_session(tmp_path: Path) -> None:
    async with guarded(chaos_config(tmp_path, policy="monitor.yaml")) as (client, _, guard):
        results = []

        async def one(i: int) -> None:
            results.append(
                await client.call_tool("notes.write_note", {"name": f"n{i}.md", "content": f"c{i}"})
            )

        async with anyio.create_task_group() as tg:
            for i in range(20):
                tg.start_soon(one, i)
        assert len(results) == 20 and all(not r.is_error for r in results)
        state = next(iter(guard.sessions._states.values()))
        assert state.calls == 20
        assert [e.source.seq for e in state.ledger] == list(range(20))


async def test_two_clients_sharing_one_trilock(tmp_path: Path) -> None:
    """On stdio the process is the session, so two in-process clients share state by design."""
    async with build_proxy(chaos_config(tmp_path, policy="monitor.yaml")) as (
        server,
        _router,
        guard,
    ):
        async with Client(server) as a, Client(server) as b:
            assert not (await a.call_tool("chaos.ok", {})).is_error
            assert not (await b.call_tool("notes.list_notes", {})).is_error
        assert len(guard.sessions) == 1


async def test_unicode_tool_names_route(tmp_path: Path) -> None:
    async with proxied(chaos_config(tmp_path)) as (client, _):
        names = {t.name for t in (await client.list_tools()).tools}
        assert "chaos.résumé_lookup" in names
        result = await client.call_tool("chaos.résumé_lookup", {"name": "Ada"})
        assert not result.is_error and "résumé for Ada" in _text(result)


async def test_a_result_that_looks_like_a_tool_schema_is_just_data(tmp_path: Path) -> None:
    """Untrusted content must never reach the policy engine as instructions (Hard Rule 3).

    Run in monitor mode so the call goes through: under dataflow an unclassified
    tool is (correctly) escalated, and this test is about what the *result* can
    do to policy and the tool listing, which is nothing.
    """
    async with guarded(chaos_config(tmp_path, policy="monitor.yaml")) as (client, _, guard):
        before = set(guard.policy.tools) if guard.policy else set()
        result = await client.call_tool("chaos.schema_of_another_tool", {})
        assert not result.is_error
        assert (set(guard.policy.tools) if guard.policy else set()) == before, (
            "a tool result changed the policy"
        )
        listed = {t.name for t in (await client.list_tools()).tools}
        assert "mail.send" not in listed, "a tool result added a tool to the listing"
        state = next(iter(guard.sessions._states.values()))
        assert state.untrusted_input, "unclassified output was not labelled untrusted"


async def test_a_policy_naming_a_tool_no_upstream_provides_is_harmless(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\nmode: dataflow\ntools:\n  'ghost.tool': { effect: external }\n"
        "  'chaos.ok': { reads: trusted, sensitivity: public }\n"
        "rules:\n  - { id: rest, when: { trifecta_legs: 0 }, then: allow }\n",
        encoding="utf-8",
    )
    cfg = chaos_config(tmp_path).model_copy(update={"policy": policy})
    async with proxied(cfg) as (client, _):
        assert not (await client.call_tool("chaos.ok", {})).is_error
        ghost = await client.call_tool("ghost.tool", {})
        assert ghost.is_error and "no such upstream" in _text(ghost)


async def test_slow_upstream_call_can_be_cancelled_and_session_survives(tmp_path: Path) -> None:
    async with proxied(chaos_config(tmp_path)) as (client, _):
        with anyio.move_on_after(0.5) as scope:
            await client.call_tool("chaos.slow", {"seconds": 30})
        assert scope.cancelled_caught
        with anyio.fail_after(20):
            assert not (await client.call_tool("chaos.ok", {})).is_error


def test_malformed_jsonrpc_over_stdio_gets_an_error_frame_not_a_crash(tmp_path: Path) -> None:
    """Raw garbage on the wire: the process answers with JSON-RPC errors and keeps serving."""
    from tests.integration.test_stdout_hygiene import _INITIALIZE, _INITIALIZED, _drive

    config = tmp_path / "trilock.yaml"
    config.write_text("version: 1\nservers: {}\n", encoding="utf-8")
    lines, stderr, rc = _drive(
        _INITIALIZE,
        _INITIALIZED,
        "this is not json at all",  # a raw non-JSON line
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": 123}},
        {"jsonrpc": "2.0", "id": 3, "method": "no/such/method", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
        expect_ids=(1, 2, 3, 4),
        config=config,
    )
    frames = [json.loads(line) for line in lines]
    by_id = {m.get("id"): m for m in frames if "id" in m}
    assert "result" in by_id[1]
    assert "error" in by_id[2], "bad params must be a JSON-RPC error"
    assert "error" in by_id[3], "an unknown method must be a JSON-RPC error"
    assert "result" in by_id[4], f"the session did not survive the garbage\n{stderr}"
    assert rc == 0


async def test_stateless_identity_is_refused_not_faked() -> None:
    """With no stable session identity, Trilock reports rather than enforcing."""
    from trilock.policy.model import load_policy
    from trilock.proxy.guard import Guard

    guard = Guard(
        TrilockConfig(policy=POLICIES / "strict.yaml"),
        load_policy(POLICIES / "strict.yaml"),
        transport="http",
    )

    class Conn:
        session_id = None

    class Sess:
        _connection = Conn()

    ctx = guard.prepare(Sess(), "mail.send", {"to": "a@b.c"})
    decision = guard.decide(ctx)
    assert decision.rule_id == "identity_degraded"
    assert decision.verdict.value == "allow"
    assert "could not be established" in " ".join(decision.reasons)
