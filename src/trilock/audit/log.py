"""Append-only, hash-chained decision log.

Every record carries the SHA-256 of the previous record's canonical bytes, so
the file is a chain: flip one byte anywhere and every later record's link no
longer matches. `verify_chain` walks it. The first record chains to a fixed
genesis value, so an emptied-and-restarted log is distinguishable from a
continued one.

What is recorded, and what is not, is the whole point (Hard Rule 6). A record
carries taint *labels*, tool names, argument *shapes* (JSON paths and types)
and content *hashes* — never argument values, never tool output, never the
content of anything the session ingested. `tests/integration/test_no_secret_leak.py`
seeds fifteen secret formats through a session and asserts none appear in the
log, and that test is mandatory.

Records are what `trilock replay` re-derives decisions from, so a record holds
exactly the frozen inputs `decide` saw — the snapshot — alongside the verdict it
produced.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from trilock import log
from trilock.policy.decision import Decision, ToolCall
from trilock.policy.engine import SessionSnapshot
from trilock.taint.propagate import walk_arguments

_log = log.get("audit")

GENESIS: Final[str] = hashlib.sha256(b"trilock-audit-genesis-v1").hexdigest()
SCHEMA_VERSION: Final[int] = 1


def canonical(record: dict[str, Any]) -> bytes:
    """The bytes that are hashed: sorted keys, no whitespace, UTF-8."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def argument_shapes(arguments: object) -> list[dict[str, object]]:
    """JSON paths, types and lengths of every leaf. Never the values."""
    shapes: list[dict[str, object]] = []
    for path, text in walk_arguments(arguments):
        shapes.append(
            {
                "path": path,
                "type": "string",
                "length": len(text),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
    # Non-string leaves are shape-only.
    _walk_non_strings(arguments, "$", shapes)
    return sorted(shapes, key=lambda s: str(s["path"]))


def _walk_non_strings(value: object, path: str, out: list[dict[str, object]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _walk_non_strings(item, f"{path}.{key}", out)
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _walk_non_strings(item, f"{path}[{index}]", out)
    elif not isinstance(value, str):
        out.append({"path": path, "type": type(value).__name__})


def snapshot_to_json(snapshot: SessionSnapshot) -> dict[str, Any]:
    """The frozen engine inputs, for replay. Labels and flags only."""
    return {
        "trifecta": snapshot.trifecta.to_json(),
        "attribution": snapshot.attribution.to_json(),
        "classification": (
            snapshot.classification.model_dump(mode="json") if snapshot.classification else None
        ),
        "session_label": snapshot.session_label.to_json(),
        "detector_scores": dict(sorted(snapshot.detector_scores.items())),
        "scope_violation": snapshot.scope_violation,
        "normalisation_removed": snapshot.normalisation_removed,
    }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One decision, as written."""

    seq: int
    prev_hash: str
    body: dict[str, Any]

    @property
    def hash(self) -> str:
        return record_hash(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {"v": SCHEMA_VERSION, "seq": self.seq, "prev": self.prev_hash, **self.body}


class AuditLog:
    """Writer for one hash-chained JSONL file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seq, self._last = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Continue an existing chain rather than restarting it."""
        if not self.path.is_file():
            return 0, GENESIS
        last_line = ""
        seq = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
                    seq += 1
        if not last_line:
            return 0, GENESIS
        try:
            return seq, record_hash(json.loads(last_line))
        except ValueError:
            _log.error(
                "audit log tail is unreadable; continuing the chain from genesis",
                extra={"path": str(self.path)},
            )
            return seq, GENESIS

    def append(self, body: dict[str, Any]) -> AuditRecord:
        record = AuditRecord(seq=self._seq, prev_hash=self._last, body=body)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical(record.as_dict()).decode("utf-8") + "\n")
        self._seq += 1
        self._last = record.hash
        return record

    def record_decision(
        self,
        *,
        session: str,
        call: ToolCall,
        snapshot: SessionSnapshot,
        decision: Decision,
        policy_mode: str,
        policy_hash: str,
        latency_ms: float,
    ) -> AuditRecord:
        """Write one decision record. Shapes and hashes, never values."""
        return self.append(
            {
                "kind": "decision",
                "ts": time.time(),
                "session": session,
                "call_id": call.call_id,
                "tool": call.tool,
                "argument_shapes": argument_shapes(call.arguments),
                "policy_mode": policy_mode,
                "policy_hash": policy_hash,
                "snapshot": snapshot_to_json(snapshot),
                "decision": decision.to_json(),
                "latency_ms": round(latency_ms, 3),
            }
        )


def read_records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (line number, record) for every non-empty line."""
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                yield number, json.loads(line)


@dataclass(frozen=True, slots=True)
class ChainBreak:
    line: int
    reason: str


def verify_chain(path: Path) -> list[ChainBreak]:
    """Every record's `prev` must equal the hash of the record before it."""
    breaks: list[ChainBreak] = []
    expected_prev = GENESIS
    expected_seq = 0
    try:
        for line, record in read_records(path):
            if record.get("prev") != expected_prev:
                breaks.append(ChainBreak(line, "prev hash does not match the previous record"))
            if record.get("seq") != expected_seq:
                breaks.append(
                    ChainBreak(
                        line, f"sequence gap: expected {expected_seq}, got {record.get('seq')}"
                    )
                )
            expected_prev = record_hash(record)
            expected_seq = int(record.get("seq", expected_seq)) + 1
    except ValueError as exc:
        breaks.append(ChainBreak(-1, f"unparseable record: {exc}"))
    return breaks
