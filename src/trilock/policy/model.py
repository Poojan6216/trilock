"""The policy schema: what tools are, and what to do about combinations of them.

Policy is the *only* source of authority in Trilock. Nothing a tool returns can
name a rule, add a classification or change a verdict (Hard Rule 3) — tool
output is data, and this module never reads any.

The document has four parts:

* ``mode`` — how much evidence a decision needs. See `Mode`.
* ``tools`` — what each tool does: whether its output is trustworthy, whether
  it touches sensitive data, and whether calling it acts on the outside world.
* ``unclassified`` — what to do about a tool nobody classified. Never ALLOW.
* ``rules`` — ordered, first-match-wins, with an implicit terminal deny.
"""

from __future__ import annotations

import fnmatch
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from trilock.policy.decision import Verdict
from trilock.taint.labels import Sensitivity, TrustLevel


class PolicyError(ValueError):
    """A policy document is missing, unparseable, or internally inconsistent."""


class Mode(StrEnum):
    """How much evidence a decision requires."""

    STRICT = "strict"
    """Session-level Rule of Two. Ignores argument attribution entirely, so
    paraphrase cannot launder anything. Maximum security, lowest utility."""

    DATAFLOW = "dataflow"
    """Argument-level attribution. A call whose arguments provably carry no
    untrusted content is allowed even when the session holds all three legs.
    Better utility, and exactly as strong as attribution is — which is why the
    misses are documented and measured rather than assumed away."""

    MONITOR = "monitor"
    """Decide and log, never block. For onboarding onto a live deployment."""


class Effect(StrEnum):
    """What calling a tool does to the world."""

    NONE = "none"
    EXTERNAL = "external"
    """Changes state or communicates outside the session."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolClass(_Strict):
    """What one tool is, for policy purposes."""

    reads: TrustLevel | None = None
    """Trust level of the content this tool returns. ``None`` means it returns
    nothing worth labelling."""
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    """Sensitivity of the content this tool returns or touches."""
    effect: Effect = Effect.NONE
    scope: tuple[str, ...] = ()
    """Where an external action may act: path globs, host names, or recipient
    domains, depending on the tool. Empty means unscoped."""
    describe: str = ""
    """Optional human note, carried into the approval prompt."""

    @model_validator(mode="before")
    @classmethod
    def _coerce_scope(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("scope"), str):
            data = {**data, "scope": (data["scope"],)}
        return data

    @property
    def is_external(self) -> bool:
        return self.effect is Effect.EXTERNAL

    @property
    def yields_untrusted(self) -> bool:
        return self.reads is TrustLevel.UNTRUSTED

    @property
    def yields_sensitive(self) -> bool:
        return self.sensitivity is Sensitivity.SENSITIVE


UNCLASSIFIED_DEFAULTS: dict[Mode, Verdict] = {
    Mode.STRICT: Verdict.DENY,
    Mode.DATAFLOW: Verdict.ESCALATE,
    Mode.MONITOR: Verdict.ESCALATE,
}
"""What an unclassified tool gets when the policy does not say.

Never ALLOW, in any mode. A tool nobody has classified is a tool nobody has
reasoned about, and the whole design rests on knowing what a call does.
"""


class RuleCondition(_Strict):
    """What must hold for a rule to fire. All present fields must match."""

    tool: str | None = None
    """Glob over the namespaced tool name, e.g. ``mail.*``."""
    effect: Effect | None = None
    trifecta_legs: int | None = Field(default=None, ge=0, le=3)
    """Fires when the call stands on at least this many legs."""
    args_tainted_by: TrustLevel | None = None
    """Fires when the call's arguments are attributed to a source at this trust level."""
    session_touched: Sensitivity | None = None
    """Fires when the session has ingested content at this sensitivity."""
    unclassified: bool | None = None
    scope_violation: bool | None = None
    """Fires when an external action's arguments fall outside its declared scope."""
    detector_above: dict[str, float] | None = None
    """Advisory only. May contribute to a DENY or raise an ALLOW to ESCALATE;
    may never be the reason a call is permitted (Hard Rule 1)."""

    @model_validator(mode="after")
    def _reject_empty(self) -> Self:
        if not any(
            v is not None
            for v in (
                self.tool,
                self.effect,
                self.trifecta_legs,
                self.args_tainted_by,
                self.session_touched,
                self.unclassified,
                self.scope_violation,
                self.detector_above,
            )
        ):
            raise ValueError(
                "a rule condition must constrain something; an empty 'when' would "
                "match every call and shadow every rule after it"
            )
        return self


class Rule(_Strict):
    """One ordered, first-match-wins rule."""

    id: str = Field(min_length=1, pattern=r"^[a-z0-9_]+$")
    when: RuleCondition
    then: Verdict
    because: str = ""
    """Optional explanation, shown to the human on an escalation."""


class Policy(_Strict):
    """A whole policy document."""

    version: Literal[1] = 1
    mode: Mode = Mode.DATAFLOW
    tools: dict[str, ToolClass] = Field(default_factory=dict)
    unclassified: Verdict | None = None
    rules: tuple[Rule, ...] = ()
    source_path: Path | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.unclassified is Verdict.ALLOW:
            raise ValueError(
                "unclassified: allow is not permitted. A tool nobody classified is a "
                "tool nobody has reasoned about; use 'escalate' or 'deny'."
            )
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}: rule ids must be unique")
            seen.add(rule.id)
        return self

    # -- lookups ---------------------------------------------------------

    @property
    def unclassified_verdict(self) -> Verdict:
        """What an unclassified tool gets, defaulting by mode."""
        return (
            self.unclassified if self.unclassified is not None else UNCLASSIFIED_DEFAULTS[self.mode]
        )

    def classify(self, tool: str) -> ToolClass | None:
        """The classification for `tool`, exact match first, then most specific glob.

        Ordering matters for reproducibility (Hard Rule 4): with two matching
        globs the longer pattern wins, and ties break lexicographically, so the
        same policy always resolves the same way.
        """
        exact = self.tools.get(tool)
        if exact is not None:
            return exact
        candidates = [p for p in self.tools if _is_glob(p) and fnmatch.fnmatchcase(tool, p)]
        if not candidates:
            return None
        best = min(candidates, key=lambda p: (-len(p), p))
        return self.tools[best]

    def resolved_table(self, tools: list[str]) -> list[tuple[str, ToolClass | None]]:
        """Every tool with the classification it resolves to. Used by `trilock check`."""
        return [(tool, self.classify(tool)) for tool in sorted(tools)]


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


PolicySource = Annotated[Path | str, "a path to a policy document, or its YAML text"]


def load_policy(path: Path) -> Policy:
    """Load and validate a policy document, with the file named in every error."""
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    return parse_policy(raw, source=path)


def parse_policy(raw: object, *, source: Path | None = None) -> Policy:
    """Validate an already-parsed policy document."""
    where = f"{source}: " if source is not None else ""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}top level must be a mapping, got {type(raw).__name__}")
    payload = dict(raw)
    payload.pop("source_path", None)
    try:
        policy = Policy.model_validate(payload)
    except Exception as exc:
        raise PolicyError(f"{where}{_explain(exc)}") from exc
    return policy.model_copy(update={"source_path": source})


def _explain(exc: Exception) -> str:
    """Render a pydantic error as one actionable line per problem."""
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    lines = []
    for error in errors():
        location = ".".join(str(p) for p in error.get("loc", ())) or "<root>"
        lines.append(f"{location}: {error.get('msg', 'invalid')}")
    return "; ".join(lines) or str(exc)
