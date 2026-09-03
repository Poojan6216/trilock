"""The taint lattice: what a piece of content is, and where it came from.

Two independent axes, each a two-element lattice ordered toward danger:

    trust:        TRUSTED  <  UNTRUSTED      (anything a tool returned is untrusted)
    sensitivity:  PUBLIC   <  SENSITIVE      (private data, credentials, PII)

`join` is the least upper bound — the *meet toward danger*. Joining two labels
can only ever produce something at least as dangerous as either input, which is
what makes it safe to use as the propagation rule: combining content never
launders it.

`detector_scores` rides along but is **advisory only** (Hard Rule 1). It is
carried here so a decision can be explained and logged, never so it can permit
anything. `join` takes the per-detector maximum, keeping it monotone with the
rest of the lattice.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Self

from ulid import ULID


class TrustLevel(StrEnum):
    """Where the content's *instructions* may be trusted to come from."""

    TRUSTED = "trusted"
    """The user's own instruction, or content a policy declares authoritative."""

    UNTRUSTED = "untrusted"
    """Anything a tool returned. Assume an attacker wrote every byte of it."""


class Sensitivity(StrEnum):
    """How much damage disclosing the content would do."""

    PUBLIC = "public"
    SENSITIVE = "sensitive"


_TRUST_ORDER: Final[dict[TrustLevel, int]] = {TrustLevel.TRUSTED: 0, TrustLevel.UNTRUSTED: 1}
_SENSITIVITY_ORDER: Final[dict[Sensitivity, int]] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.SENSITIVE: 1,
}


def new_call_id() -> str:
    """A fresh, sortable identifier for one tool call."""
    return str(ULID())


@dataclass(frozen=True, slots=True, order=True)
class SourceId:
    """Where one piece of content entered the session."""

    server: str
    """Upstream MCP server name."""
    tool: str
    """The tool that produced it."""
    call_id: str
    """ULID of the originating call."""
    seq: int
    """Ordinal within the session, so provenance can be replayed in order."""

    def __str__(self) -> str:
        return f"{self.server}.{self.tool}#{self.seq}"


@dataclass(frozen=True, slots=True)
class TaintLabel:
    """The provenance of a piece of content."""

    trust: TrustLevel = TrustLevel.TRUSTED
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    sources: frozenset[SourceId] = frozenset()
    detector_scores: Mapping[str, float] = field(
        default_factory=lambda: MappingProxyType({}), hash=False
    )
    """Advisory detector output. Never a reason to allow (Hard Rule 1).

    Excluded from `__hash__` — two labels that differ only in advisory scores
    are not equal, but may share a hash bucket, which is legal and keeps the
    security-relevant axes as the identity of the label.
    """

    def __post_init__(self) -> None:
        # Freeze the mapping so a caller cannot mutate a label through an alias
        # it still holds. Frozen dataclasses forbid normal assignment.
        if not isinstance(self.detector_scores, MappingProxyType):
            object.__setattr__(
                self, "detector_scores", MappingProxyType(dict(self.detector_scores))
            )

    # -- lattice ---------------------------------------------------------

    def join(self, other: TaintLabel) -> TaintLabel:
        """Least upper bound: associative, commutative, idempotent.

        `IDENTITY` (TRUSTED, PUBLIC, no sources, no scores) is the unit.
        """
        return TaintLabel(
            trust=max(self.trust, other.trust, key=_TRUST_ORDER.__getitem__),
            sensitivity=max(
                self.sensitivity, other.sensitivity, key=_SENSITIVITY_ORDER.__getitem__
            ),
            sources=self.sources | other.sources,
            detector_scores=_join_scores(self.detector_scores, other.detector_scores),
        )

    def __or__(self, other: TaintLabel) -> TaintLabel:
        return self.join(other)

    def dominates(self, other: TaintLabel) -> bool:
        """True when `self` is at least as dangerous as `other` on both axes."""
        return (
            _TRUST_ORDER[self.trust] >= _TRUST_ORDER[other.trust]
            and _SENSITIVITY_ORDER[self.sensitivity] >= _SENSITIVITY_ORDER[other.sensitivity]
        )

    # -- predicates ------------------------------------------------------

    @property
    def is_untrusted(self) -> bool:
        return self.trust is TrustLevel.UNTRUSTED

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity is Sensitivity.SENSITIVE

    @property
    def is_clean(self) -> bool:
        """True for the identity label: nothing dangerous is known about it."""
        return not self.is_untrusted and not self.is_sensitive and not self.sources

    # -- construction ----------------------------------------------------

    def with_scores(self, scores: Mapping[str, float]) -> TaintLabel:
        """A copy carrying `scores`, joined with any already present."""
        return TaintLabel(
            trust=self.trust,
            sensitivity=self.sensitivity,
            sources=self.sources,
            detector_scores=_join_scores(self.detector_scores, scores),
        )

    def widened(self) -> TaintLabel:
        """The most conservative label at or above this one.

        Used where precision has been lost — a ledger eviction, an
        unclassifiable argument — so that losing information can only ever
        widen taint, never narrow it.
        """
        return TaintLabel(
            trust=TrustLevel.UNTRUSTED,
            sensitivity=Sensitivity.SENSITIVE,
            sources=self.sources,
            detector_scores=self.detector_scores,
        )

    def to_json(self) -> dict[str, object]:
        """A JSON-safe rendering for the audit log. Carries labels, never content."""
        return {
            "trust": self.trust.value,
            "sensitivity": self.sensitivity.value,
            "sources": sorted(str(s) for s in self.sources),
            "detector_scores": dict(sorted(self.detector_scores.items())),
        }

    @classmethod
    def join_all(cls, labels: Iterable[TaintLabel]) -> Self:
        """Fold `join` over `labels`, returning IDENTITY for an empty iterable."""
        result = IDENTITY
        for label in labels:
            result = result.join(label)
        return cls(
            trust=result.trust,
            sensitivity=result.sensitivity,
            sources=result.sources,
            detector_scores=result.detector_scores,
        )


def _join_scores(a: Mapping[str, float], b: Mapping[str, float]) -> Mapping[str, float]:
    """Per-detector maximum over the union of keys."""
    if not a:
        return b
    if not b:
        return a
    merged = dict(a)
    for key, value in b.items():
        merged[key] = max(merged.get(key, value), value)
    return MappingProxyType(merged)


IDENTITY: Final[TaintLabel] = TaintLabel()
"""The join identity, and the bottom of the lattice: trusted, public, no sources."""

UNTRUSTED_PUBLIC: Final[TaintLabel] = TaintLabel(trust=TrustLevel.UNTRUSTED)
TRUSTED_SENSITIVE: Final[TaintLabel] = TaintLabel(sensitivity=Sensitivity.SENSITIVE)
TOP: Final[TaintLabel] = TaintLabel(trust=TrustLevel.UNTRUSTED, sensitivity=Sensitivity.SENSITIVE)
"""The most dangerous label: untrusted *and* sensitive."""
