"""Session state that survives a client reconnect.

Trilock's unit of accounting is the session, and on stdio the session is the
process. That is exact - and it is exactly what the red team's session-splitting
attack exploits: read the secret in one session, reconnect (a new process,
Claude Code's `/mcp` reload, a restart), and send it from a fresh session that
holds no legs. The secret travels in the model's own context, where no tool call
can see it.

Durable sessions close this for the common case: the *same user*, on the *same
Trilock configuration*, within a time window. The session's legs, its evicted
floor, and its ledger fingerprints are written to `.trilock/sessions/<key>.json`
and reloaded by the next process for that key while the entry is younger than
the TTL. A new session therefore starts where the last one left off, and the
send in the fresh session is the third leg.

What is persisted: trust/sensitivity legs, the evicted floor, the sequence
counter, and per-source (source id, content hash, label, n-gram hashes). What is
**not** persisted: the exact-token set, because those tokens are emails, URLs and
secret-shaped strings - the very values Hard Rule 6 keeps out of every file
Trilock writes. Restored sources therefore attribute by n-gram only; the legs,
which are what session splitting needs, restore fully.

Opt-in (`sessions: {durable: true}`) because it trades utility for security:
every new session inherits the previous one's legs for the TTL, so a morning of
reading untrusted web pages makes the afternoon's first external action an
escalation. The default TTL is 24 hours.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Final

from trilock import log
from trilock.taint.labels import Sensitivity, SourceId, TaintLabel, TrustLevel
from trilock.taint.store import LedgerEntry, SessionLedger

_log = log.get("taint.durable")

SCHEMA_VERSION: Final[int] = 1
DEFAULT_TTL_S: Final[float] = 24 * 3600


def durable_key(config_path: Path | None, user: str | None = None) -> str:
    """The identity a stdio session keeps across processes: this user, this config."""
    who = user if user is not None else _current_user()
    where = str(config_path.resolve()) if config_path is not None else "<no-config>"
    return hashlib.sha256(f"{who}\n{where}".encode()).hexdigest()[:24]


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - no passwd entry
        return "unknown"


def _label_to_json(label: TaintLabel) -> dict[str, str]:
    return {"trust": label.trust.value, "sensitivity": label.sensitivity.value}


def _label_from_json(raw: dict[str, Any]) -> TaintLabel:
    return TaintLabel(trust=TrustLevel(raw["trust"]), sensitivity=Sensitivity(raw["sensitivity"]))


def snapshot(
    ledger: SessionLedger, *, untrusted_input: bool, sensitive_access: bool
) -> dict[str, Any]:
    """The persistable form of a session. Labels, hashes and n-gram hashes only."""
    return {
        "version": SCHEMA_VERSION,
        "saved_at": time.time(),
        "untrusted_input": untrusted_input,
        "sensitive_access": sensitive_access,
        "seq": ledger.seq,
        "evicted_count": ledger.evicted_count,
        "attribution_complete": ledger.attribution_complete,
        "evicted_floor": _label_to_json(ledger.evicted_floor),
        "entries": [
            {
                "server": e.source.server,
                "tool": e.source.tool,
                "call_id": e.source.call_id,
                "seq": e.source.seq,
                "content_hash": e.content_hash,
                "label": _label_to_json(e.label),
                "ngrams": sorted(e.ngrams),
                "length": e.length,
            }
            for e in ledger.entries.values()
        ],
    }


def restore(ledger: SessionLedger, raw: dict[str, Any]) -> tuple[bool, bool]:
    """Load a snapshot into an empty ledger. Returns (untrusted_input, sensitive_access)."""
    ledger.seq = int(raw.get("seq", 0))
    ledger.evicted_count = int(raw.get("evicted_count", 0))
    # A restored session has lost its exact tokens, so a negative attribution
    # proves less than it did; the conservative flag is the honest one.
    ledger.attribution_complete = bool(raw.get("attribution_complete", True)) and not raw.get(
        "entries"
    )
    ledger.evicted_floor = _label_from_json(raw["evicted_floor"])
    ledger.entries = OrderedDict()
    for e in raw.get("entries", []):
        source = SourceId(
            server=e["server"], tool=e["tool"], call_id=e["call_id"], seq=int(e["seq"])
        )
        ledger.entries[source] = LedgerEntry(
            source=source,
            content_hash=e["content_hash"],
            label=_label_from_json(e["label"]),
            ngrams=frozenset(int(n) for n in e["ngrams"]),
            exact_tokens=frozenset(),  # never persisted (Hard Rule 6)
            length=int(e.get("length", 0)),
        )
    return bool(raw.get("untrusted_input")), bool(raw.get("sensitive_access"))


class DurableSessions:
    """Reads and writes session snapshots under the state directory."""

    def __init__(self, directory: Path, *, ttl_s: float = DEFAULT_TTL_S) -> None:
        self.directory = directory
        self.ttl_s = ttl_s

    def path_for(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def load(self, key: str) -> dict[str, Any] | None:
        path = self.path_for(key)
        if not path.is_file():
            return None
        try:
            raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _log.error(
                "durable session unreadable; starting clean",
                extra={"path": str(path), "error": str(exc)},
            )
            return None
        if time.time() - float(raw.get("saved_at", 0)) > self.ttl_s:
            _log.info("durable session expired; starting clean", extra={"key": key})
            path.unlink(missing_ok=True)
            return None
        return raw

    def save(self, key: str, data: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.path_for(key).with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data) + "\n", encoding="utf-8")
        tmp.replace(self.path_for(key))

    def forget(self, key: str) -> None:
        self.path_for(key).unlink(missing_ok=True)
