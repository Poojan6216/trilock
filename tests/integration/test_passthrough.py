"""Task 0.5 verification: the differential test behind Hard Rule 7.

A scripted sequence of MCP operations is run twice — once straight at the
fixture server, once through a real ``trilock serve`` subprocess — and the two
transcripts must be equal after `canonicalise` removes the only two differences
a proxy is allowed to introduce.

Both runs use real transports rather than the in-process dispatcher, because
that is the only way to exercise an actual protocol revision. The script runs
once for the handshake era (2025-11-25) and once for the modern era
(2026-07-28).
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml
from mcp import Client, StdioServerParameters

from trilock.config import TrilockConfig
from trilock.proxy.passthrough import canonicalise, is_passthrough

FIXTURE_SERVERS = Path(__file__).resolve().parents[1] / "fixtures" / "servers"
DOCS_SERVER = FIXTURE_SERVERS / "docs_server.py"
SERVER = "docs"

# 'legacy' forces the initialize handshake and lands on 2025-11-25.
# 'auto' probes server/discover and lands on 2026-07-28.
MODES = [("legacy", "2025-11-25"), ("auto", "2026-07-28")]

Op = tuple[str, Callable[[Client, str], Coroutine[Any, Any, Any]]]


def _script() -> list[Op]:
    """~30 MCP operations covering every method the proxy forwards."""

    def tools(_p: str) -> Op:
        return ("tools/list", lambda c, _: c.list_tools())

    ops: list[Op] = [
        ("tools/list", lambda c, _: c.list_tools()),
        ("prompts/list", lambda c, _: c.list_prompts()),
        ("resources/list", lambda c, _: c.list_resources()),
        ("resources/templates/list", lambda c, _: c.list_resource_templates()),
    ]
    for uri in (
        "docs://index",
        "docs://page/handbook",
        "docs://page/runbook",
        "docs://page/absent",
    ):
        ops.append((f"resources/read {uri}", lambda c, _, u=uri: c.read_resource(u)))
    for args in ({}, {"topic": "ingest"}, {"topic": "the nightly job"}):
        ops.append((f"prompts/get {args}", lambda c, ns, a=args: c.get_prompt(f"{ns}summarise", a)))
    for query in ("runbook", "handbook", "nightly", "", "no-such-content", "INGEST", "worker", "#"):
        ops.append(
            (
                f"tools/call search_docs {query!r}",
                lambda c, ns, q=query: c.call_tool(f"{ns}search_docs", {"query": q}),
            )
        )
    for steps in (0, 1, 3, 7):
        ops.append(
            (
                f"tools/call slow_index {steps}",
                lambda c, ns, s=steps: c.call_tool(f"{ns}slow_index", {"steps": s}),
            )
        )
    # Error paths must be forwarded faithfully too.
    ops += [
        ("tools/call missing argument", lambda c, ns: c.call_tool(f"{ns}search_docs", {})),
        ("tools/call wrong type", lambda c, ns: c.call_tool(f"{ns}slow_index", {"steps": "many"})),
        ("tools/call unknown tool", lambda c, ns: c.call_tool(f"{ns}no_such_tool", {})),
        ("tools/list (repeat)", lambda c, _: c.list_tools()),
        ("resources/list (repeat)", lambda c, _: c.list_resources()),
        ("prompts/list (repeat)", lambda c, _: c.list_prompts()),
        ("resources/read (repeat)", lambda c, _: c.read_resource("docs://index")),
        (
            "tools/call after errors",
            lambda c, ns: c.call_tool(f"{ns}search_docs", {"query": "run"}),
        ),
    ]
    del tools
    return ops


async def _run(client: Client, namespace: str) -> list[tuple[str, Any]]:
    """Execute the script, canonicalising each response."""
    transcript: list[tuple[str, Any]] = []
    for label, op in _script():
        try:
            result = await op(client, namespace)
            payload = canonicalise(result.model_dump(mode="json", by_alias=True), SERVER)
        except Exception as exc:  # protocol errors are part of the transcript
            payload = {"__exception__": type(exc).__name__, "detail": str(exc)}
        transcript.append((label, payload))
    return transcript


@asynccontextmanager
async def _direct(mode: str) -> AsyncIterator[Client]:
    params = StdioServerParameters(command=sys.executable, args=[str(DOCS_SERVER)])
    async with Client(params, mode=mode, cache=None) as client:
        yield client


@asynccontextmanager
async def _through_trilock(mode: str, tmp: Path) -> AsyncIterator[Client]:
    config = {
        "version": 1,
        "servers": {
            SERVER: {"transport": "stdio", "command": sys.executable, "args": [str(DOCS_SERVER)]}
        },
    }
    config_path = tmp / "trilock.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "trilock.cli", "serve", "--config", str(config_path), "--log-level", "ERROR"],
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    async with Client(params, mode=mode, cache=None) as client:
        yield client


def test_no_policy_means_passthrough() -> None:
    assert is_passthrough(TrilockConfig())
    assert not is_passthrough(TrilockConfig(policy=Path("policies/default.yaml")))


@pytest.mark.parametrize(("mode", "expected_version"), MODES)
async def test_proxied_transcript_matches_direct(
    mode: str, expected_version: str, tmp_path: Path
) -> None:
    async with _direct(mode) as client:
        assert client.protocol_version == expected_version
        baseline = await _run(client, "")

    async with _through_trilock(mode, tmp_path) as client:
        assert client.protocol_version == expected_version
        proxied = await _run(client, f"{SERVER}.")

    assert len(baseline) >= 30, f"the script must cover ~30 operations, got {len(baseline)}"
    assert [label for label, _ in baseline] == [label for label, _ in proxied]
    mismatches = [
        (label, want, got)
        for (label, want), (_, got) in zip(baseline, proxied, strict=True)
        if want != got
    ]
    assert not mismatches, "\n".join(
        f"{label}\n  direct:  {want}\n  proxied: {got}" for label, want, got in mismatches
    )


@pytest.mark.parametrize(("mode", "expected_version"), MODES)
async def test_the_proxy_names_itself_as_the_peer(
    mode: str, expected_version: str, tmp_path: Path
) -> None:
    """`canonicalise` normalises the peer stamp, so assert its real value here.

    Trilock must not impersonate the upstream: a client that decides anything
    on peer identity would be deciding on a lie. This is the assertion the
    differential test deliberately factors out.
    """
    async with _through_trilock(mode, tmp_path) as client:
        assert client.protocol_version == expected_version
        info = client.server_info
        assert info is not None
        assert info.name == "trilock"

        listed = (await client.list_tools()).model_dump(mode="json", by_alias=True)
        stamp = (listed.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")
        if stamp is not None:  # only stamped on 2026-07-28
            assert stamp["name"] == "trilock"


async def test_hop_meta_from_the_upstream_is_not_forwarded() -> None:
    """Unit-level guard for the leak the differential test found."""
    import mcp_types as types

    from trilock.proxy.router import strip_hop_meta

    stamped = types.CallToolResult(
        content=[types.TextContent(type="text", text="x")],
        _meta={"io.modelcontextprotocol/serverInfo": {"name": "docs"}, "app/trace": "keep-me"},
    )
    scrubbed = strip_hop_meta(stamped)
    assert scrubbed.meta == {"app/trace": "keep-me"}

    only_hop = types.CallToolResult(
        content=[], _meta={"io.modelcontextprotocol/serverInfo": {"name": "docs"}}
    )
    assert strip_hop_meta(only_hop).meta is None

    untouched = types.CallToolResult(content=[], _meta={"app/trace": "t"})
    assert strip_hop_meta(untouched) is untouched
    assert strip_hop_meta(types.CallToolResult(content=[])).meta is None
