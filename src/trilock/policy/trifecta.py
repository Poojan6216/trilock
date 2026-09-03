"""Per-session accounting: which legs of the trifecta this session stands on.

`SessionState` is what the decision function reads. It owns the provenance
ledger for one session and the two *monotonic* legs derived from it.

Monotonic is the important word. `untrusted_input` and `sensitive_access` are
set when a classified tool returns and are never cleared except by an explicit
session reset. A session that has read attacker-controlled text has read it;
"the agent has probably moved on" is not a security property. Only
`external_action` is evaluated per call, because it describes the call rather
than the session.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from trilock import log
from trilock.policy.decision import TrifectaState
from trilock.policy.model import Effect, Mode, Policy, ToolClass
from trilock.taint.labels import Sensitivity, TaintLabel, TrustLevel
from trilock.taint.normalize import Normalized, normalize
from trilock.taint.propagate import Attribution, attribute
from trilock.taint.store import LedgerStore, SessionKey, SessionLedger

_log = log.get("policy.trifecta")


@dataclass
class SessionState:
    """Everything the decision function knows about one session."""

    key: SessionKey
    ledger: SessionLedger
    untrusted_input: bool = False
    sensitive_access: bool = False
    calls: int = 0
    normalisations: list[Normalized] = field(default_factory=list)
    """Every inbound normalisation report, newest last. Feeds the audit log and
    the approval prompt; bounded by the ledger's own source cap."""

    # -- ingress ---------------------------------------------------------

    def record_result(
        self,
        server: str,
        tool: str,
        call_id: str,
        contents: Sequence[str],
        classification: ToolClass | None,
    ) -> tuple[list[str], list[Normalized]]:
        """Label one inbound tool result and fold it into the session.

        `contents` is every text the result carries — its content blocks and,
        if present, its structured payload. They are normalised individually,
        because each is substituted back into its own block, but recorded as a
        **single** ledger source: one call produced them, and splitting them
        would double-count a result whose structured payload merely restates
        its text, inflating the ledger and evicting real sources sooner.

        Returns the normalised texts, in order, with their reports.

        An *unclassified* tool's output is treated as untrusted. That is the
        only safe default: content whose provenance nobody declared is content
        whose provenance nobody knows.
        """
        reports = [normalize(text) for text in contents]
        combined = "\n".join(r.text for r in reports)
        untrusted = classification is None or classification.yields_untrusted
        sensitive = classification is not None and classification.yields_sensitive
        label = TaintLabel(
            trust=TrustLevel.UNTRUSTED if untrusted else TrustLevel.TRUSTED,
            sensitivity=Sensitivity.SENSITIVE if sensitive else Sensitivity.PUBLIC,
        )
        entry = self.ledger.record(server, tool, call_id, combined, label)
        label = label.join(TaintLabel(sources=frozenset({entry.source})))
        # Re-record with the source attached so the ledger's own label names it.
        self.ledger.entries[entry.source] = type(entry)(
            source=entry.source,
            content_hash=entry.content_hash,
            label=label,
            ngrams=entry.ngrams,
            exact_tokens=entry.exact_tokens,
            length=entry.length,
        )
        if untrusted:
            self.untrusted_input = True
        if sensitive:
            self.sensitive_access = True
        for item in reports:
            if item.modifications:
                self.normalisations.append(item)
        del self.normalisations[: -self.ledger.max_sources]
        _log.info(
            "inbound result labelled",
            extra={
                "session": str(self.key),
                "source": str(entry.source),
                "label": label.to_json(),
                "normalised": [r.to_json() for r in reports if r.modifications],
                "trifecta": self.trifecta().to_json(),
            },
        )
        return [r.text for r in reports], reports

    # -- egress ----------------------------------------------------------

    def trifecta(self, *, external: bool = False) -> TrifectaState:
        """This session's legs, evaluated for a call with the given effect."""
        return TrifectaState(
            untrusted_input=self.untrusted_input,
            sensitive_access=self.sensitive_access,
            external_action=external,
        )

    def attribute_call(self, arguments: object, mode: Mode) -> Attribution:
        """Attribute an outbound call's arguments to their sources.

        In `strict` mode this is deliberately *not* consulted for the decision —
        the mode exists precisely because attribution can be defeated by
        paraphrase — but it is still computed, because the audit log and the
        approval prompt are more useful with it than without, and computing it
        cannot weaken a decision that ignores it.
        """
        return attribute(arguments, self.ledger)

    def to_json(self) -> dict[str, object]:
        return {
            "session": str(self.key),
            "calls": self.calls,
            "trifecta": self.trifecta().to_json(),
            "ledger": self.ledger.to_json(),
            "normalisations": len(self.normalisations),
        }


class SessionRegistry:
    """Every live session's state, keyed by session identity."""

    def __init__(self, ledgers: LedgerStore) -> None:
        self._ledgers = ledgers
        self._states: dict[SessionKey, SessionState] = {}

    def get(self, key: SessionKey) -> SessionState:
        ledger = self._ledgers.get(key)
        state = self._states.get(key)
        if state is None or state.ledger is not ledger:
            # A ledger the store has replaced means the session was evicted;
            # its accounting must restart with it rather than outlive it.
            state = SessionState(key=key, ledger=ledger)
            self._states[key] = state
        return state

    def reset(self, key: SessionKey) -> None:
        """Explicitly forget a session. The only way a trifecta leg un-sets."""
        self._ledgers.reset(key)
        self._states.pop(key, None)
        _log.info("session reset", extra={"session": str(key)})

    def __len__(self) -> int:
        return len(self._states)


def classify(policy: Policy | None, tool: str) -> ToolClass | None:
    """Look up a tool's classification, or None when there is no policy at all."""
    return policy.classify(tool) if policy is not None else None


def is_external(classification: ToolClass | None) -> bool:
    """Whether calling this tool acts on the world. Unclassified is not assumed safe."""
    return classification is not None and classification.effect is Effect.EXTERNAL
