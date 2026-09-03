"""A fixture docs MCP server exposing resources and prompts, not just tools.

Trilock forwards resources/* and prompts/* as well as tools/*. Without a
server that serves them, that forwarding would ship untested.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import journal
from mcp.server.mcpserver import Context, MCPServer

SERVER_NAME = "docs"
server = MCPServer(SERVER_NAME)

_PAGES = {
    "handbook": "# Handbook\n\nThe project doc the agent is asked to update.",
    "runbook": "# Runbook\n\nRestart the ingest worker before the nightly job.",
}


@server.resource("docs://page/{name}")
def page(name: str) -> str:
    """A documentation page."""
    journal.record(SERVER_NAME, "resource:page", {"name": name})
    return _PAGES.get(name, f"(no such page: {name})")


@server.resource("docs://index")
def index() -> str:
    """The list of pages."""
    journal.record(SERVER_NAME, "resource:index", {})
    return "\n".join(sorted(_PAGES))


@server.prompt()
def summarise(topic: str = "everything") -> str:
    """A prompt template for summarising a topic."""
    journal.record(SERVER_NAME, "prompt:summarise", {"topic": topic})
    return f"Summarise what the docs say about {topic}."


@server.tool()
def search_docs(query: str) -> str:
    """Search the documentation."""
    journal.record(SERVER_NAME, "search_docs", {"query": query})
    return "\n".join(f"{k}: {v}" for k, v in _PAGES.items() if query.lower() in v.lower())


@server.tool()
async def slow_index(steps: int, ctx: Context) -> str:
    """Rebuild the index, reporting progress. Exercises progress forwarding."""
    journal.record(SERVER_NAME, "slow_index", {"steps": steps})
    for step in range(1, steps + 1):
        await ctx.report_progress(step, steps, f"step {step}")
    return f"indexed {steps}"


@server.tool()
async def hang(seconds: float = 30.0) -> str:
    """Block. Exercises cancellation forwarding."""
    import anyio

    journal.record(SERVER_NAME, "hang", {"seconds": seconds})
    await anyio.sleep(seconds)
    return "finished"


if __name__ == "__main__":
    server.run("stdio")
