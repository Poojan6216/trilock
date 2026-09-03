"""The per-session provenance ledger: every byte that entered, and from where.

The ledger is append-only within a session and bounded in memory. The bound is
the interesting part.

**Eviction must widen taint, never narrow it.** A ledger that forgets a source
loses the ability to *prove* that an outbound argument derives from it — and if
"unproven" silently meant "clean", then an attacker could exfiltrate simply by
being patient: fill the ledger with 500 benign results, push the poisoned one
out, and the same call that was denied a moment ago is allowed. Forgetting must
never be a laundering channel.

So eviction keeps two things. The evicted entry's *label* is joined into a
permanent `evicted_floor`, which keeps contributing to session-level accounting
forever. And `attribution_complete` latches false, which tells the policy
engine that a negative attribution result is no longer evidence of anything, so
arguments it cannot attribute must be treated as carrying the floor.

Session identity is the other subtle part, and it is the weakest structural
link in the design — see `docs/threat-model.md`. Where the protocol has a
session id (the 2025-11-25 handshake era, and 2026-07-28 connections that carry
one) the ledger is keyed by it. In stateless 2026-07-28 mode there is no
session id, and the ledger falls back to the identity of the client connection.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Final, Literal

from trilock import log
from trilock.taint.labels import IDENTITY, SourceId, TaintLabel, TrustLevel
from trilock.taint.propagate import (
    DEFAULT_NGRAM_SIZE,
    content_hash,
    extract_ngrams,
    high_entropy_tokens,
)

_log = log.get("taint.store")

DEFAULT_MAX_SOURCES: Final[int] = 500
DEFAULT_MAX_NGRAMS: Final[int] = 4096

SessionKind = Literal["mcp-session", "connection"]


@dataclass(frozen=True, slots=True)
class SessionKey:
    """How a session was identified, and by what value.

    `kind` is recorded rather than discarded because the two are not equally
    trustworthy, and a reader of the audit log must be able to tell which
    assumption a decision rested on.
    """

    kind: SessionKind
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One piece of content that entered the session."""

    source: SourceId
    content_hash: str
    label: TaintLabel
    ngrams: frozenset[int]
    exact_tokens: frozenset[str]
    length: int

    def to_json(self) -> dict[str, object]:
        """Labels, hashes and shapes. Never content (Hard Rule 6)."""
        return {
            "source": str(self.source),
            "content_hash": self.content_hash,
            "label": self.label.to_json(),
            "ngrams": len(self.ngrams),
            "exact_tokens": len(self.exact_tokens),
            "length": self.length,
        }


@dataclass
class SessionLedger:
    """The provenance ledger for one session."""

    key: SessionKey
    max_sources: int = DEFAULT_MAX_SOURCES
    ngram_size: int = DEFAULT_NGRAM_SIZE
    max_ngrams_per_source: int = DEFAULT_MAX_NGRAMS

    entries: OrderedDict[SourceId, LedgerEntry] = field(default_factory=OrderedDict)
    evicted_floor: TaintLabel = IDENTITY
    """The join of every evicted entry's label. Contributes forever."""
    evicted_count: int = 0
    attribution_complete: bool = True
    """False once anything has been evicted: a negative attribution proves nothing."""
    seq: int = 0

    # -- writing ---------------------------------------------------------

    def record(
        self, server: str, tool: str, call_id: str, content: str, label: TaintLabel
    ) -> LedgerEntry:
        """Record one tool result and return its ledger entry."""
        source = SourceId(server=server, tool=tool, call_id=call_id, seq=self.seq)
        self.seq += 1
        entry = LedgerEntry(
            source=source,
            content_hash=content_hash(content),
            label=label,
            ngrams=extract_ngrams(content, self.ngram_size, self.max_ngrams_per_source),
            exact_tokens=high_entropy_tokens(content),
            length=len(content),
        )
        self.entries[source] = entry
        self.entries.move_to_end(source)
        self._evict()
        return entry

    def _evict(self) -> None:
        """Drop least-recently-used entries, folding their labels into the floor."""
        while len(self.entries) > self.max_sources:
            _, evicted = self.entries.popitem(last=False)
            self.evicted_floor = self.evicted_floor.join(evicted.label)
            self.evicted_count += 1
            self.attribution_complete = False
            _log.info(
                "ledger source evicted; taint widened to session level",
                extra={
                    "session": str(self.key),
                    "source": str(evicted.source),
                    "evicted_total": self.evicted_count,
                    "floor": self.evicted_floor.to_json(),
                },
            )

    # -- reading ---------------------------------------------------------

    def session_label(self) -> TaintLabel:
        """The join of everything this session has ingested, evicted included.

        This is what `strict` mode decides on, and it is exactly the quantity
        eviction must not be able to reduce.
        """
        return TaintLabel.join_all(
            [self.evicted_floor, *(entry.label for entry in self.entries.values())]
        )

    def untrusted_sources(self) -> frozenset[SourceId]:
        return frozenset(
            e.source for e in self.entries.values() if e.label.trust is TrustLevel.UNTRUSTED
        )

    def touch(self, source: SourceId) -> None:
        """Mark a source recently used, so matching keeps it alive."""
        if source in self.entries:
            self.entries.move_to_end(source)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self.entries.values())

    def to_json(self) -> dict[str, object]:
        return {
            "session": str(self.key),
            "sources": len(self.entries),
            "evicted": self.evicted_count,
            "attribution_complete": self.attribution_complete,
            "session_label": self.session_label().to_json(),
        }


class LedgerStore:
    """Every live session's ledger, keyed by session identity."""

    def __init__(
        self,
        *,
        max_sources: int = DEFAULT_MAX_SOURCES,
        ngram_size: int = DEFAULT_NGRAM_SIZE,
        max_ngrams_per_source: int = DEFAULT_MAX_NGRAMS,
        max_sessions: int = 256,
    ) -> None:
        self.max_sources = max_sources
        self.ngram_size = ngram_size
        self.max_ngrams_per_source = max_ngrams_per_source
        self.max_sessions = max_sessions
        self._sessions: OrderedDict[SessionKey, SessionLedger] = OrderedDict()

    def get(self, key: SessionKey) -> SessionLedger:
        """The ledger for `key`, created on first use."""
        ledger = self._sessions.get(key)
        if ledger is None:
            ledger = SessionLedger(
                key=key,
                max_sources=self.max_sources,
                ngram_size=self.ngram_size,
                max_ngrams_per_source=self.max_ngrams_per_source,
            )
            self._sessions[key] = ledger
        self._sessions.move_to_end(key)
        self._evict_sessions()
        return ledger

    def _evict_sessions(self) -> None:
        """Drop the least-recently-used whole session when over the cap.

        Dropping a *session* is not a laundering risk the way dropping a source
        within one is: a new session legitimately starts with no trifecta legs
        held. It does mean a very long-idle session resumes clean, which is
        recorded in the threat model as an accepted limit.
        """
        while len(self._sessions) > self.max_sessions:
            key, dropped = self._sessions.popitem(last=False)
            _log.warning(
                "session ledger dropped (session cap reached)",
                extra={"session": str(key), "sources": len(dropped)},
            )

    def reset(self, key: SessionKey) -> None:
        """Explicitly forget a session. The only way a trifecta leg un-sets."""
        if self._sessions.pop(key, None) is not None:
            _log.info("session ledger reset", extra={"session": str(key)})

    def keys(self) -> Iterable[SessionKey]:
        return tuple(self._sessions)

    def __len__(self) -> int:
        return len(self._sessions)
