"""Task 0.2 verification: ``trilock serve`` must not pollute stdout.

Under the stdio transport stdout *is* the JSON-RPC channel. A single stray
byte — a progress bar, a warning banner, a debug print — desynchronises the
framing and takes the session down. This test drives a real subprocess and
asserts every stdout line parses as a JSON-RPC message, while the structured
logs land on stderr.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue

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


def _drive(
    *messages: dict[str, object] | str,
    expect_ids: tuple[int, ...] = (),
    config: Path | None = None,
) -> tuple[list[str], str, int]:
    """Run ``trilock serve``, feed it `messages`, return (stdout lines, stderr, rc).

    Reads responses until every id in `expect_ids` has been answered *before*
    closing stdin. Writing everything and closing immediately races the server's
    EOF shutdown against its handling of the last frame, which made this test
    flaky rather than wrong.
    """
    argv = [sys.executable, "-m", "trilock.cli", "serve", "--log-level", "DEBUG"]
    if config is not None:
        argv += ["--config", str(config)]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout
    lines: list[str] = []
    collected: Queue[str | None] = Queue()

    def pump() -> None:
        assert proc.stdout
        for line in proc.stdout:
            collected.put(line)
        collected.put(None)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    try:
        for message in messages:
            proc.stdin.write((message if isinstance(message, str) else json.dumps(message)) + "\n")
            proc.stdin.flush()
        outstanding = set(expect_ids)
        deadline = time.monotonic() + 30
        while outstanding and time.monotonic() < deadline:
            try:
                line = collected.get(timeout=deadline - time.monotonic())
            except Empty:
                break
            if line is None:
                break
            lines.append(line)
            with contextlib.suppress(json.JSONDecodeError):
                outstanding.discard(json.loads(line).get("id"))
        assert not outstanding, f"no response for ids {sorted(outstanding)}; got {lines!r}"
    finally:
        proc.stdin.close()
        stderr = proc.stderr.read() if proc.stderr else ""
        rc = proc.wait(timeout=30)
        reader.join(timeout=5)
    while True:  # drain anything the pump captured after the last expected id
        try:
            tail = collected.get_nowait()
        except Empty:
            break
        if tail is None:
            break
        lines.append(tail)
    return [line for line in lines if line.strip()], stderr, rc


def test_stdout_carries_only_jsonrpc_frames() -> None:
    lines, stderr, rc = _drive(_INITIALIZE, _INITIALIZED, _LIST_TOOLS, expect_ids=(1, 2))
    assert rc == 0, f"serve exited {rc}\nstderr:\n{stderr}"
    assert lines, f"no JSON-RPC frames on stdout\nstderr:\n{stderr}"
    for line in lines:
        message = json.loads(line)  # raises if a non-JSON byte leaked in
        assert message.get("jsonrpc") == "2.0", f"non-JSON-RPC object on stdout: {line!r}"
        assert "method" in message or "result" in message or "error" in message, (
            f"malformed JSON-RPC frame on stdout: {line!r}"
        )


def test_responses_are_correlated_and_tools_list_is_empty() -> None:
    lines, stderr, _ = _drive(_INITIALIZE, _INITIALIZED, _LIST_TOOLS, expect_ids=(1, 2))
    by_id = {m["id"]: m for m in map(json.loads, lines) if "id" in m}
    assert 1 in by_id, f"no initialize response\nstderr:\n{stderr}"
    assert by_id[1]["result"]["protocolVersion"] == "2025-11-25"
    assert 2 in by_id, "no tools/list response"
    # No upstreams are configured, so the aggregate listing is empty rather than absent.
    assert by_id[2]["result"]["tools"] == []


def test_structured_logs_go_to_stderr_as_json() -> None:
    _, stderr, _ = _drive(_INITIALIZE, _INITIALIZED, expect_ids=(1,))
    records = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
    assert records, f"expected structured logs on stderr, got:\n{stderr}"
    assert any(r["logger"].startswith("trilock") for r in records)
    assert all({"ts", "level", "logger", "msg"} <= r.keys() for r in records)
