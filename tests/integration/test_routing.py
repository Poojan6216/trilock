"""Task 0.4 verification: aggregation, namespacing and routing."""

from __future__ import annotations

import json

import pytest

from tests.integration.conftest import direct, proxied, stdio_upstream, two_server_config
from trilock.proxy.router import Route, RouteError, qualify, split_qualified


def test_split_qualified_uses_the_first_separator() -> None:
    # SEP-986 permits dots inside a tool name; server names may not contain one,
    # so the first dot is always the namespace boundary.
    assert split_qualified("mail.send") == Route(server="mail", name="send")
    assert split_qualified("mail.send.now") == Route(server="mail", name="send.now")
    assert qualify("mail", "send.now") == "mail.send.now"
    for bad in ("send", "", ".send", "mail."):
        with pytest.raises(RouteError):
            split_qualified(bad)


async def test_client_sees_the_union_of_both_servers_namespaced() -> None:
    async with proxied() as (client, _):
        tools = await client.list_tools()
    assert {t.name for t in tools.tools} == {
        "mail.search",
        "mail.send",
        "mail.drafts",
        "notes.read_note",
        "notes.write_note",
        "notes.list_notes",
    }


async def test_namespacing_preserves_every_other_tool_field() -> None:
    async with proxied() as (client, _):
        through = {t.name: t for t in (await client.list_tools()).tools}
    async with direct() as pool:
        straight = {t.name: t for t in (await pool["mail"].client().list_tools()).tools}
    for name, original in straight.items():
        seen = through[f"mail.{name}"]
        assert seen.description == original.description
        assert seen.input_schema == original.input_schema
        assert seen.output_schema == original.output_schema
        assert seen.title == original.title
        assert seen.annotations == original.annotations


async def test_a_call_reaches_the_right_upstream(tmp_path: object) -> None:
    async with proxied(two_server_config(TRILOCK_FIXTURE_NOTES_DIR=str(tmp_path))) as (client, _):
        result = await client.call_tool("mail.search", {"query": "sprint"})
        assert not result.is_error
        text = "".join(c.text for c in result.content if c.type == "text")
        assert "Sprint planning notes" in text

        written = await client.call_tool("notes.write_note", {"name": "n.txt", "content": "hello"})
        assert not written.is_error
        listed = await client.call_tool("notes.list_notes", {})
        assert "n.txt" in json.loads("".join(c.text for c in listed.content if c.type == "text"))


async def test_unrouted_names_are_clean_tool_errors_not_crashes() -> None:
    async with proxied() as (client, _):
        for name in ("bogus.tool", "unnamespaced"):
            result = await client.call_tool(name, {})
            assert result.is_error
            text = "".join(c.text for c in result.content if c.type == "text")
            assert "not a namespaced name" in text or "no such upstream" in text
        # The session survives a bad route and keeps serving.
        assert not (await client.call_tool("mail.search", {"query": ""})).is_error


async def test_listings_survive_a_dead_upstream() -> None:
    """An upstream that is down is skipped, not fatal to the whole listing."""
    import sys

    from trilock.config import StdioUpstream, TrilockConfig

    config = TrilockConfig(
        servers={
            "mail": stdio_upstream("mail_server.py"),
            "broken": StdioUpstream(command=sys.executable, args=("-c", "raise SystemExit(3)")),
        }
    )
    async with proxied(config) as (client, _):
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == {"mail.search", "mail.send", "mail.drafts"}
        assert (await client.call_tool("broken.anything", {})).is_error
