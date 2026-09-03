"""The MCP server Trilock exposes downstream, to the agent.

Trilock is a proxy: this server has no tools of its own. Everything it lists
and everything it executes comes from an upstream server via the router. What
it adds is the decision point in the middle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import mcp_types as types
from mcp.server import InitializationOptions, NotificationOptions
from mcp.server.lowlevel import Server

from trilock import __version__, log

if TYPE_CHECKING:
    from trilock.config import TrilockConfig

SERVER_NAME: Final[str] = "trilock"

_log = log.get("proxy.server")


def build_server(config: TrilockConfig) -> Server[None]:
    """Construct the downstream-facing MCP server.

    Handlers are registered against the low-level `Server` rather than the
    `MCPServer` decorator API: a proxy needs to forward whatever it is given,
    including methods it does not itself understand, so it must own dispatch.
    """
    server: Server[None] = Server(SERVER_NAME, version=__version__)

    async def on_list_tools(
        _ctx: Any, _params: types.PaginatedRequestParams
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[])

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"unknown tool: {params.name}")],
            is_error=True,
        )

    server.add_request_handler("tools/list", types.PaginatedRequestParams, on_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, on_call_tool)
    _log.debug("built downstream server", extra={"upstreams": sorted(config.servers)})
    return server


def initialization_options(server: Server[None]) -> InitializationOptions:
    """Capabilities Trilock advertises downstream."""
    return server.create_initialization_options(
        NotificationOptions(prompts_changed=True, resources_changed=True, tools_changed=True)
    )


async def serve_stdio(config: TrilockConfig) -> None:
    """Serve the proxy over stdio until the client closes the connection."""
    from mcp.server.stdio import stdio_server

    server = build_server(config)
    _log.info("serving over stdio", extra={"upstreams": sorted(config.servers)})
    # stdio_server() claims fd 1 and points it at stderr, so stray *native*
    # writes miss the wire. The guard goes inside that claim, not around it: it
    # adds a log record for stray Python-level writes, and installing it first
    # would hide the real stdout the SDK needs to take over.
    async with stdio_server() as (read_stream, write_stream):
        with log.guard_stdout():
            await server.run(read_stream, write_stream, initialization_options(server))
