"""Emit a client configuration for any stdio MCP client.

For clients without a known config file, `trilock init --print` writes the
server entry a user pastes in. The shape is the common `mcpServers` object;
every client that speaks MCP over stdio accepts it or a trivial variant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trilock.integrations.claude_code import _trilock_args, trilock_server_entry


def client_snippet(
    trilock_config_path: Path, *, server_name: str = "trilock", flavour: str = "mcpServers"
) -> str:
    """A JSON snippet pointing a stdio client at Trilock."""
    entry = trilock_server_entry(trilock_config_path, servers_key=flavour)
    entry["args"] = _trilock_args(entry)
    document: dict[str, Any] = {flavour: {server_name: entry}}
    return json.dumps(document, indent=2) + "\n"
