"""Tool definition pinning: detect a server that changes what its tools claim to be.

A server can serve a benign tool description at review time and a malicious one
later — the "rug pull" or tool-poisoning class, where the description is itself
the injection. Pinning hashes each tool's definition on first sight and shouts
when it changes.

**This is table stakes, not a contribution.** `airlock-agent` ships tool
pinning with a HELD/approve flow already; Trilock builds it because a proxy in
this position is incomplete without it, and credits the prior art in the README.
Trilock's actual contribution is the ingress provenance in Phase 1.

What is hashed is a superset of the obvious three fields. `description` is the
injection vector and `inputSchema` shapes the call, but `outputSchema`,
`title` and `annotations` also change what a tool claims to be — and
`annotations` carries hints (`readOnlyHint`, `destructiveHint`) that a reader
may act on. A benign server upgrade trips the pin either way; the answer to a
false positive is `trilock check --repin`, not a narrower hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Self

import mcp_types as types

from trilock import log

_log = log.get("proxy.pins")

PINS_BASENAME: Final[str] = "pins.json"
SCHEMA_VERSION: Final[int] = 1


def digest_tool(tool: types.Tool) -> str:
    """A stable SHA-256 over everything the tool claims about itself."""
    payload: dict[str, Any] = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations.model_dump(mode="json") if tool.annotations else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Pin:
    """The recorded definition digest for one upstream tool."""

    server: str
    tool: str
    digest: str
    first_seen: str

    @property
    def key(self) -> str:
        return f"{self.server}/{self.tool}"

    def to_json(self) -> dict[str, str]:
        return {
            "server": self.server,
            "tool": self.tool,
            "digest": self.digest,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_json(cls, raw: dict[str, str]) -> Self:
        return cls(
            server=raw["server"],
            tool=raw["tool"],
            digest=raw["digest"],
            first_seen=raw.get("first_seen", ""),
        )


@dataclass(frozen=True, slots=True)
class PinViolation:
    """A tool whose definition no longer matches its pin."""

    server: str
    tool: str
    pinned: str
    observed: str

    @property
    def key(self) -> str:
        return f"{self.server}/{self.tool}"

    def describe(self) -> str:
        return (
            f"tool {self.tool!r} on upstream {self.server!r} changed its definition since it was "
            f"pinned (pinned {self.pinned[:12]}, now {self.observed[:12]}). Review the change, "
            f"then re-pin with 'trilock check --repin'."
        )


class PinStore:
    """The on-disk pin ledger, ``.trilock/pins.json``."""

    def __init__(self, path: Path, *, strict: bool = False) -> None:
        self.path = path
        self.strict = strict
        """In strict mode a violating tool is withheld from the listing, not just logged."""
        self._pins: dict[str, Pin] = {}
        self._dirty = False
        self.violations: dict[str, PinViolation] = {}

    # -- persistence -----------------------------------------------------

    @classmethod
    def load(cls, path: Path, *, strict: bool = False) -> PinStore:
        """Read the ledger, tolerating absence and refusing corruption silently."""
        store = cls(path, strict=strict)
        if not path.is_file():
            return store
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            entries = raw["pins"] if isinstance(raw, dict) else raw
            store._pins = {p.key: p for p in (Pin.from_json(e) for e in entries)}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # A pin file we cannot read is not a reason to run unpinned, but it is
            # also not a reason to refuse to start: every tool simply looks new,
            # which re-pins on this run and is logged loudly.
            _log.error(
                "pin file unreadable; treating every tool as newly seen",
                extra={"path": str(path), "error": f"{type(exc).__name__}: {exc}"},
            )
        return store

    def save(self) -> None:
        """Write the ledger if it changed. Atomic, so a crash cannot truncate it."""
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": SCHEMA_VERSION,
            "pins": [p.to_json() for p in sorted(self._pins.values(), key=lambda p: p.key)],
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False

    # -- checking --------------------------------------------------------

    def check(self, server: str, tools: list[types.Tool]) -> list[PinViolation]:
        """Compare `tools` against the ledger, pinning anything new.

        Returns the violations found for this server. A tool that disappears is
        not a violation — servers legitimately stop offering tools — but its pin
        is kept, so that the same tool returning with a different definition is
        still caught.
        """
        found: list[PinViolation] = []
        now = datetime.now(UTC).isoformat(timespec="seconds")
        for tool in tools:
            observed = digest_tool(tool)
            key = f"{server}/{tool.name}"
            pin = self._pins.get(key)
            if pin is None:
                self._pins[key] = Pin(
                    server=server, tool=tool.name, digest=observed, first_seen=now
                )
                self._dirty = True
                _log.info(
                    "tool pinned",
                    extra={"server": server, "tool": tool.name, "digest": observed[:12]},
                )
                self.violations.pop(key, None)
                continue
            if pin.digest == observed:
                self.violations.pop(key, None)
                continue
            violation = PinViolation(
                server=server, tool=tool.name, pinned=pin.digest, observed=observed
            )
            self.violations[key] = violation
            found.append(violation)
            _log.error(
                "TOOL DEFINITION CHANGED SINCE IT WAS PINNED",
                extra={
                    "server": server,
                    "tool": tool.name,
                    "pinned_digest": pin.digest,
                    "observed_digest": observed,
                    "strict": self.strict,
                    "action": "withheld" if self.strict else "exposed with a warning",
                },
            )
        return found

    def filter(self, server: str, tools: list[types.Tool]) -> list[types.Tool]:
        """Check `tools` and, in strict mode, withhold the ones that violate."""
        violations = {v.tool for v in self.check(server, tools)}
        if not violations or not self.strict:
            return tools
        return [t for t in tools if t.name not in violations]

    # -- repinning -------------------------------------------------------

    def repin(self, server: str | None = None, tool: str | None = None) -> list[PinViolation]:
        """Accept the observed definitions, clearing the matching violations."""
        cleared: list[PinViolation] = []
        now = datetime.now(UTC).isoformat(timespec="seconds")
        for key, violation in list(self.violations.items()):
            if server is not None and violation.server != server:
                continue
            if tool is not None and violation.tool != tool:
                continue
            self._pins[key] = Pin(
                server=violation.server,
                tool=violation.tool,
                digest=violation.observed,
                first_seen=now,
            )
            self._dirty = True
            cleared.append(self.violations.pop(key))
        return cleared

    def forget(self, server: str) -> None:
        """Drop every pin for one upstream. Used when a server is removed."""
        for key in [k for k, p in self._pins.items() if p.server == server]:
            del self._pins[key]
            self.violations.pop(key, None)
            self._dirty = True

    @property
    def pins(self) -> dict[str, Pin]:
        return dict(self._pins)

    def __len__(self) -> int:
        return len(self._pins)
