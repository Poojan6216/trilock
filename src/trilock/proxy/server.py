"""The MCP server Trilock exposes downstream, to the agent.

Trilock is a proxy: this server owns no tools. Everything it lists and
everything it executes comes from an upstream via the router. What it adds is
the decision point in the middle — which, until Phase 2, is a no-op.

Handlers are registered on the low-level `Server` rather than the decorator
API because a proxy must forward whatever it is handed, including shapes it
does not itself model.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

import mcp_types as types
from mcp.server import InitializationOptions, NotificationOptions, ServerRequestContext
from mcp.server.lowlevel import Server

from trilock import __version__, log
from trilock.config import TrilockConfig
from trilock.proxy.router import RouteError, Router
from trilock.proxy.upstream import UpstreamUnavailableError, open_pool

SERVER_NAME: Final[str] = "trilock"

_log = log.get("proxy.server")

Ctx = ServerRequestContext[None, Any]


def _error_result(message: str) -> types.CallToolResult:
    """A tool error the *agent* reads.

    Deliberately terse and non-directive: this text goes back into a model's
    context, so it must not read as an instruction (Hard Rule 3 in the other
    direction). It states what happened and nothing more.
    """
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


def _progress_bridge(ctx: Ctx) -> Any:
    """Forward upstream progress to whoever asked for it downstream.

    `session.report_progress` is scoped to the inbound request and is a no-op
    when the caller did not ask for progress, which makes it the only correct
    bridge here. The obvious alternative — reading `progress_token` out of the
    downstream `_meta` and calling `send_progress_notification` — works only
    over JSON-RPC: an in-process client (and every 2026-07-28 caller, where
    client-to-server progress is deprecated) passes a callback with no token on
    the wire, so the token lookup finds nothing and every notification is
    silently dropped.

    The bridge is therefore installed unconditionally. The cost is that an
    upstream may produce progress no one consumes; the alternative is a proxy
    that swallows progress, which is worse.
    """

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        await ctx.session.report_progress(progress, total, message)

    return on_progress


def build_server(router: Router) -> Server[None]:
    """Construct the downstream-facing MCP server over `router`."""
    server: Server[None] = Server(SERVER_NAME, version=__version__)

    async def on_list_tools(_ctx: Ctx, _p: types.PaginatedRequestParams) -> types.ListToolsResult:
        return await router.list_tools()

    async def on_call_tool(ctx: Ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        try:
            return await router.call_tool(
                params.name,
                params.arguments,
                meta=ctx.meta,
                progress_callback=_progress_bridge(ctx),
            )
        except (RouteError, UpstreamUnavailableError) as exc:
            _log.warning("tools/call not routed", extra={"tool": params.name, "error": str(exc)})
            return _error_result(str(exc))

    async def on_list_prompts(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListPromptsResult:
        return await router.list_prompts()

    async def on_get_prompt(
        ctx: Ctx, params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        return await router.get_prompt(params.name, params.arguments, meta=ctx.meta)

    async def on_list_resources(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListResourcesResult:
        return await router.list_resources()

    async def on_list_resource_templates(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListResourceTemplatesResult:
        return await router.list_resource_templates()

    async def on_read_resource(
        ctx: Ctx, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        return await router.read_resource(str(params.uri), meta=ctx.meta)

    server.add_request_handler("tools/list", types.PaginatedRequestParams, on_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, on_call_tool)
    server.add_request_handler("prompts/list", types.PaginatedRequestParams, on_list_prompts)
    server.add_request_handler("prompts/get", types.GetPromptRequestParams, on_get_prompt)
    server.add_request_handler("resources/list", types.PaginatedRequestParams, on_list_resources)
    server.add_request_handler(
        "resources/templates/list", types.PaginatedRequestParams, on_list_resource_templates
    )
    server.add_request_handler("resources/read", types.ReadResourceRequestParams, on_read_resource)
    return server


def initialization_options(server: Server[None]) -> InitializationOptions:
    """Capabilities Trilock advertises downstream.

    The union of what the upstreams can do is not known until they connect, and
    a client that learns of a capability late cannot use it. Trilock therefore
    advertises the full set it is willing to forward, and answers with an empty
    listing when no upstream provides one.
    """
    return server.create_initialization_options(
        NotificationOptions(prompts_changed=True, resources_changed=True, tools_changed=True)
    )


@asynccontextmanager
async def build_proxy(config: TrilockConfig) -> AsyncIterator[tuple[Server[None], Router]]:
    """Open the upstream pool and build the downstream server over it."""
    async with open_pool(config) as pool:
        router = Router(pool)
        _log.info("proxy ready", extra={"upstreams": pool.statuses()})
        yield build_server(router), router


async def serve_stdio(config: TrilockConfig) -> None:
    """Serve the proxy over stdio until the client closes the connection."""
    from mcp.server.stdio import stdio_server

    async with build_proxy(config) as (server, _router):
        _log.info("serving over stdio", extra={"upstreams": sorted(config.servers)})
        # stdio_server() claims fd 1 and points it at stderr, so stray *native*
        # writes miss the wire. The guard goes inside that claim, not around it:
        # it adds a log record for stray Python-level writes, and installing it
        # first would hide the real stdout the SDK needs to take over.
        async with stdio_server() as (read_stream, write_stream):
            with log.guard_stdout():
                await server.run(read_stream, write_stream, initialization_options(server))
