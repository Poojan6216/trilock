"""Task 0.4: resources/* and prompts/* are forwarded, not just tools/*."""

from __future__ import annotations

import pytest

from tests.integration.conftest import proxied, stdio_upstream
from trilock.config import TrilockConfig
from trilock.proxy.router import RouteError

DOCS = TrilockConfig(servers={"docs": stdio_upstream("docs_server.py")})
BOTH = TrilockConfig(
    servers={"docs": stdio_upstream("docs_server.py"), "mail": stdio_upstream("mail_server.py")}
)


async def test_prompts_are_listed_and_namespaced() -> None:
    async with proxied(DOCS) as (client, _):
        prompts = await client.list_prompts()
        assert {p.name for p in prompts.prompts} == {"docs.summarise"}

        got = await client.get_prompt("docs.summarise", {"topic": "ingest"})
        rendered = " ".join(
            m.content.text for m in got.messages if getattr(m.content, "type", None) == "text"
        )
        assert "ingest" in rendered


async def test_resources_are_listed_and_read_by_uri() -> None:
    async with proxied(DOCS) as (client, _):
        listed = await client.list_resources()
        uris = {str(r.uri) for r in listed.resources}
        assert "docs://index" in uris

        read = await client.read_resource("docs://index")
        text = "".join(c.text for c in read.contents if hasattr(c, "text"))
        assert "handbook" in text and "runbook" in text


async def test_resource_templates_are_forwarded() -> None:
    async with proxied(DOCS) as (client, _):
        templates = await client.list_resource_templates()
        assert any("docs://page/" in t.uri_template for t in templates.resource_templates)
        read = await client.read_resource("docs://page/runbook")
        assert "ingest worker" in "".join(c.text for c in read.contents if hasattr(c, "text"))


async def test_resource_routing_learns_the_owner_and_survives_a_second_server() -> None:
    """With two upstreams, a URI still lands on the one that owns it."""
    async with proxied(BOTH) as (client, router):
        await client.list_resources()
        assert router._resource_owner["docs://index"] == "docs"
        read = await client.read_resource("docs://index")
        assert "handbook" in "".join(c.text for c in read.contents if hasattr(c, "text"))


async def test_an_unknown_resource_uri_is_an_error_not_a_hang() -> None:
    async with proxied(DOCS) as (_client, router):
        with pytest.raises(RouteError, match="no upstream served"):
            await router.read_resource("docs://page/../../etc/passwd/nope")


async def test_progress_notifications_reach_the_downstream_client() -> None:
    """Progress raised upstream is re-labelled with the downstream client's token."""
    seen: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append((progress, total, message))

    async with proxied(DOCS) as (client, _):
        result = await client.call_tool(
            "docs.slow_index", {"steps": 3}, progress_callback=on_progress
        )
        assert not result.is_error
    assert [p for p, _, _ in seen] == [1.0, 2.0, 3.0]
    assert all(total == 3.0 for _, total, _ in seen)
    assert [m for _, _, m in seen] == ["step 1", "step 2", "step 3"]


async def test_cancellation_propagates_upstream() -> None:
    """Cancelling downstream must not leave the upstream call running."""
    import anyio

    async with proxied(DOCS) as (client, _):
        with anyio.move_on_after(1.0) as scope:
            await client.call_tool("docs.hang", {"seconds": 30})
        assert scope.cancelled_caught, "the hanging call should have been cancelled"
        # The session is still usable after a cancellation.
        with anyio.fail_after(20):
            assert not (await client.call_tool("docs.search_docs", {"query": "runbook"})).is_error


async def test_application_meta_is_forwarded_and_reserved_keys_are_not() -> None:
    from trilock.proxy.router import strip_reserved_meta

    assert strip_reserved_meta(None) is None
    assert strip_reserved_meta({}) is None
    assert strip_reserved_meta({"progress_token": "t"}) is None
    assert strip_reserved_meta({"io.modelcontextprotocol/logLevel": "debug"}) is None
    assert strip_reserved_meta({"app/trace": "abc"}) == {"app/trace": "abc"}
    assert strip_reserved_meta({"app/trace": "abc", "progress_token": 1}) == {"app/trace": "abc"}
