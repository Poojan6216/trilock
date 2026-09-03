"""Invocation journal shared by the fixture MCP servers.

Several tests assert a *negative*: that a denied call never reached the real
server. That is only checkable if the server itself records what it was asked
to do, out of band of the proxy. Each fixture server appends one JSON line per
invocation to ``$TRILOCK_FIXTURE_JOURNAL`` when that variable is set.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

ENV_VAR = "TRILOCK_FIXTURE_JOURNAL"


def record(server: str, tool: str, arguments: dict[str, Any]) -> None:
    """Append one invocation record, if journalling is enabled."""
    path = os.environ.get(ENV_VAR)
    if not path:
        return
    entry = {"ts": time.time(), "server": server, "tool": tool, "arguments": arguments}
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")


def read(path: str | Path) -> list[dict[str, Any]]:
    """Read back every recorded invocation."""
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def calls_to(path: str | Path, tool: str) -> list[dict[str, Any]]:
    """Every recorded invocation of `tool`."""
    return [e for e in read(path) if e["tool"] == tool]
