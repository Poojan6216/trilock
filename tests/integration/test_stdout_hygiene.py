"""Task 0.2 verification: ``trilock serve`` must not pollute stdout.

Under the stdio transport stdout *is* the JSON-RPC channel. A single stray
byte — a progress bar, a warning banner, a debug print — desynchronises the
framing and takes the session down. This test drives a real subprocess and
asserts every stdout line parses as a JSON-RPC message, while the structured
logs land on stderr.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "hygiene-test", "version": "1.0"},
    },
}
_INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
_LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def _drive(*messages: dict[str, object]) -> tuple[list[str], str, int]:
    """Run ``trilock serve``, feed it `messages`, return (stdout lines, stderr, rc)."""
    stdin = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(
        [sys.executable, "-m", "trilock.cli", "serve", "--log-level", "DEBUG"],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
    )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return lines, proc.stderr, proc.returncode


def test_stdout_carries_only_jsonrpc_frames() -> None:
    lines, stderr, rc = _drive(_INITIALIZE, _INITIALIZED, _LIST_TOOLS)
    assert rc == 0, f"serve exited {rc}\nstderr:\n{stderr}"
    assert lines, f"no JSON-RPC frames on stdout\nstderr:\n{stderr}"
    for line in lines:
        message = json.loads(line)  # raises if a non-JSON byte leaked in
        assert message.get("jsonrpc") == "2.0", f"non-JSON-RPC object on stdout: {line!r}"
        assert "method" in message or "result" in message or "error" in message, (
            f"malformed JSON-RPC frame on stdout: {line!r}"
        )


def test_responses_are_correlated_and_tools_list_is_empty() -> None:
    lines, stderr, _ = _drive(_INITIALIZE, _INITIALIZED, _LIST_TOOLS)
    by_id = {m["id"]: m for m in map(json.loads, lines) if "id" in m}
    assert 1 in by_id, f"no initialize response\nstderr:\n{stderr}"
    assert by_id[1]["result"]["protocolVersion"] == "2025-11-25"
    assert 2 in by_id, "no tools/list response"
    # No upstreams are configured, so the aggregate listing is empty rather than absent.
    assert by_id[2]["result"]["tools"] == []


def test_structured_logs_go_to_stderr_as_json() -> None:
    _, stderr, _ = _drive(_INITIALIZE, _INITIALIZED)
    records = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
    assert records, f"expected structured logs on stderr, got:\n{stderr}"
    assert any(r["logger"].startswith("trilock") for r in records)
    assert all({"ts", "level", "logger", "msg"} <= r.keys() for r in records)
