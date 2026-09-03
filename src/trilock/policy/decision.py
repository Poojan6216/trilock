"""The types a decision is made of.

Kept separate from the engine so that the audit log, the approval prompt and
the replay checker all depend on the *shape* of a decision without depending on
how one is reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from trilock.taint.labels import IDENTITY, TaintLabel


class Verdict(StrEnum):
    """What Trilock does with a call."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    """Ask the human, over MCP's own multi-round-trip mechanism."""


_STRICTNESS: Final[dict[Verdict, int]] = {Verdict.ALLOW: 0, Verdict.ESCALATE: 1, Verdict.DENY: 2}


def stricter(a: Verdict, b: Verdict) -> Verdict:
    """The more restrictive of two verdicts. ALLOW < ESCALATE < DENY."""
    return a if _STRICTNESS[a] >= _STRICTNESS[b] else b


def is_stricter_or_equal(a: Verdict, b: Verdict) -> bool:
    return _STRICTNESS[a] >= _STRICTNESS[b]


@dataclass(frozen=True, slots=True)
class TrifectaState:
    """Which legs of the lethal trifecta this session is standing on.

    Any one leg is safe. Any two are safe. All three in one session let
    attacker-controlled text move private data out under the user's own
    privileges.
    """

    untrusted_input: bool = False
    """The session has ingested content a tool returned."""
    sensitive_access: bool = False
    """The session has touched private data."""
    external_action: bool = False
    """*This call* would change state or communicate outside."""

    @property
    def legs(self) -> int:
        return sum((self.untrusted_input, self.sensitive_access, self.external_action))

    @property
    def complete(self) -> bool:
        return self.legs == 3

    def with_external(self, external: bool) -> TrifectaState:
        """The same session state, evaluated for a call with this effect.

        `external_action` is per-call, not per-session: reading mail is not an
        egress, and a session that once sent an email is not permanently barred
        from reading another one.
        """
        return TrifectaState(
            untrusted_input=self.untrusted_input,
            sensitive_access=self.sensitive_access,
            external_action=external,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "untrusted_input": self.untrusted_input,
            "sensitive_access": self.sensitive_access,
            "external_action": self.external_action,
            "legs": self.legs,
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One outbound tool call, as the policy engine sees it."""

    tool: str
    """The namespaced downstream name, ``<server>.<tool>``."""
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""

    @property
    def server(self) -> str:
        return self.tool.partition(".")[0]


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome, and everything needed to explain or reproduce it."""

    verdict: Verdict
    rule_id: str
    """Which rule fired. ``default_deny`` when none did."""
    reasons: tuple[str, ...] = ()
    """Human-readable, shown in the approval prompt."""
    trifecta: TrifectaState = TrifectaState()
    tainted_args: tuple[str, ...] = ()
    """JSON paths of arguments carrying taint."""
    label: TaintLabel = IDENTITY

    @property
    def blocked(self) -> bool:
        return self.verdict is not Verdict.ALLOW

    def to_json(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "rule_id": self.rule_id,
            "reasons": list(self.reasons),
            "trifecta": self.trifecta.to_json(),
            "tainted_args": list(self.tainted_args),
            "label": self.label.to_json(),
        }
