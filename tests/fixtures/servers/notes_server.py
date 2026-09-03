"""A fixture notes MCP server: trusted local reads and scoped local writes."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import journal
from mcp.server.mcpserver import MCPServer

SERVER_NAME = "notes"
server = MCPServer(SERVER_NAME)


def _root() -> Path:
    root = Path(os.environ.get("TRILOCK_FIXTURE_NOTES_DIR", "."))
    root.mkdir(parents=True, exist_ok=True)
    return root


@server.tool()
def read_note(name: str) -> str:
    """Read a note by name."""
    journal.record(SERVER_NAME, "read_note", {"name": name})
    path = _root() / name
    if not path.exists():
        return f"(no such note: {name})"
    return path.read_text(encoding="utf-8")


@server.tool()
def write_note(name: str, content: str) -> str:
    """Write a note. An external action under policy: it changes state on disk."""
    journal.record(SERVER_NAME, "write_note", {"name": name, "content": content})
    path = _root() / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return json.dumps({"status": "written", "name": name, "bytes": len(content)})


@server.tool()
def list_notes() -> str:
    """List every note."""
    journal.record(SERVER_NAME, "list_notes", {})
    return json.dumps(sorted(p.name for p in _root().glob("*") if p.is_file()))


if __name__ == "__main__":
    server.run("stdio")
