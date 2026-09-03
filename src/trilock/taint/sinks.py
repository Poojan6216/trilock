"""Taint that outlives the session: what an agent writes stays tainted when read back.

The session ledger answers "where did this content come from?" for content that
arrived *during* this session. It cannot answer for content the agent parked
somewhere — a note, a cache key, a scratch file — and read back later, possibly
from a fresh session with no legs at all. The red team's realistic laundering
attack is exactly that: a `memory.store` the policy author never thought of as
an egress accepts the secret with two legs, and a new session recalls it clean.

A **sink** is any string argument of an allowed call whose arguments carried
taint. Its identifier — hashed, never stored (Hard Rule 6) — is recorded with
the taint it carried. When any later call's arguments name that identifier, the
result of that call inherits the sink's taint. So `memory.recall(key="k1")`
returns content labelled untrusted+sensitive because `memory.store(key="k1",
value=<tainted>)` was allowed earlier — in this session, or in another one, or
after a restart, because the store is file-backed.

This deliberately over-approximates: recording *every* string argument of a
tainted write (not just the one that "is the key") means a later
`notes.delete_note(name="plan.md")` also inherits taint on its result. That
costs a leg, not a decision — and guessing which argument is the address is how
a defence gets bypassed. Bounded by count and TTL so it cannot grow forever.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Final

from trilock import log
from trilock.taint.labels import IDENTITY, Sensitivity, TaintLabel, TrustLevel
from trilock.taint.propagate import walk_arguments

_log = log.get("taint.sinks")

DEFAULT_MAX_ENTRIES: Final[int] = 5000
DEFAULT_TTL_S: Final[float] = 7 * 24 * 3600
MIN_IDENTIFIER_CHARS: Final[int] = 2
"""An attacker chooses the key; `k1` must count. Single characters are too collision-prone."""
SCHEMA_VERSION: Final[int] = 1


def _sink_id(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


class SinkStore:
    """Hashed sink identifiers → the taint they carry. File-backed, bounded, TTL."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        ttl_s: float = DEFAULT_TTL_S,
    ) -> None:
        self.path = path
        self.max_entries = max_entries
        self.ttl_s = ttl_s
        self._entries: OrderedDict[str, tuple[str, str, float, str]] = OrderedDict()
        """sink id -> (trust, sensitivity, recorded_at, tool)."""
        self.recorded = 0
        self.hits = 0
        if path is not None:
            self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        assert self.path is not None
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            now = time.time()
            for entry in raw.get("sinks", []):
                if now - float(entry["at"]) <= self.ttl_s:
                    self._entries[entry["id"]] = (
                        entry["trust"],
                        entry["sensitivity"],
                        float(entry["at"]),
                        entry["tool"],
                    )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            _log.error(
                "sink store unreadable; starting empty",
                extra={"path": str(self.path), "error": str(exc)},
            )

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": SCHEMA_VERSION,
            "sinks": [
                {"id": sid, "trust": t, "sensitivity": s, "at": at, "tool": tool}
                for sid, (t, s, at, tool) in self._entries.items()
            ],
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    # -- recording -------------------------------------------------------

    def record(self, tool: str, arguments: object, label: TaintLabel) -> int:
        """Record every string argument of an allowed, tainted call as a sink.

        Returns how many identifiers were recorded. A clean label records nothing:
        there is no taint to carry.
        """
        if not label.is_untrusted and not label.is_sensitive:
            return 0
        now = time.time()
        count = 0
        for _path, text in walk_arguments(arguments):
            value = text.strip()
            if len(value) < MIN_IDENTIFIER_CHARS:
                continue
            sid = _sink_id(value)
            previous = self._entries.get(sid)
            trust = label.trust
            sensitivity = label.sensitivity
            if previous is not None:
                # Join toward danger with whatever was already recorded.
                if previous[0] == TrustLevel.UNTRUSTED.value:
                    trust = TrustLevel.UNTRUSTED
                if previous[1] == Sensitivity.SENSITIVE.value:
                    sensitivity = Sensitivity.SENSITIVE
            self._entries[sid] = (trust.value, sensitivity.value, now, tool)
            self._entries.move_to_end(sid)
            count += 1
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        if count:
            self.recorded += count
            _log.info(
                "tainted sinks recorded",
                extra={"tool": tool, "count": count, "label": label.to_json()},
            )
        return count

    # -- lookup ----------------------------------------------------------

    def lookup(self, arguments: object) -> TaintLabel:
        """The join of every recorded sink named by `arguments`. IDENTITY when none."""
        now = time.time()
        found = IDENTITY
        for _path, text in walk_arguments(arguments):
            value = text.strip()
            if len(value) < MIN_IDENTIFIER_CHARS:
                continue
            entry = self._entries.get(_sink_id(value))
            if entry is None:
                continue
            if now - entry[2] > self.ttl_s:
                del self._entries[_sink_id(value)]
                continue
            found = found.join(
                TaintLabel(trust=TrustLevel(entry[0]), sensitivity=Sensitivity(entry[1]))
            )
        if not found.is_clean:
            self.hits += 1
        return found

    def __len__(self) -> int:
        return len(self._entries)

    def to_json(self) -> dict[str, Any]:
        return {
            "entries": len(self._entries),
            "recorded": self.recorded,
            "hits": self.hits,
            "path": str(self.path) if self.path else None,
        }
