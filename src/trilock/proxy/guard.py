"""The decision point: everything that happens around a proxied tool call.

Ingress and egress are both here so the ordering is visible in one place:

    egress   resolve session -> classify tool -> attribute arguments
             -> account trifecta -> decide -> (execute or refuse)
    ingress  normalise result -> label it -> fold into the ledger

Normalisation happens on the way *in*, before the ledger fingerprints the
content and before the agent sees it, so that attribution matches on defused
text and a smuggled instruction cannot hide from both.

Until Phase 2 lands the rule engine, `decide` is not called: this module
computes and logs the full record, and blocks nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from weakref import WeakKeyDictionary

import mcp_types as types

from trilock import log
from trilock.approval import ApprovalScope, ApprovalStore, mailbox_path
from trilock.audit.log import AuditLog
from trilock.config import TrilockConfig
from trilock.detect.base import Detector, merge_scores, run_detectors
from trilock.detect.heuristics import HeuristicDetector
from trilock.detect.promptguard import PromptGuardDetector, is_available
from trilock.policy.decision import Decision, ToolCall, TrifectaState, Verdict
from trilock.policy.engine import SessionSnapshot, decide
from trilock.policy.model import Mode, Policy, ToolClass
from trilock.policy.scope import ScopeResult
from trilock.policy.scope import check as check_scope
from trilock.policy.trifecta import SessionRegistry, SessionState, is_external
from trilock.taint.labels import new_call_id
from trilock.taint.propagate import Attribution, walk_arguments
from trilock.taint.store import LedgerStore, SessionKey

_log = log.get("proxy.guard")

Executor = Callable[[], Awaitable[types.CallToolResult]]


@dataclass(frozen=True, slots=True)
class CallContext:
    """Everything known about one outbound call before it is decided."""

    call: ToolCall
    session: SessionState
    classification: ToolClass | None
    attribution: Attribution
    trifecta: TrifectaState
    scope: ScopeResult = field(default_factory=ScopeResult)

    @property
    def unclassified(self) -> bool:
        return self.classification is None

    def to_json(self) -> dict[str, object]:
        return {
            "session": str(self.session.key),
            "tool": self.call.tool,
            "call_id": self.call.call_id,
            "unclassified": self.unclassified,
            "effect": self.classification.effect.value if self.classification else None,
            "trifecta": self.trifecta.to_json(),
            "attribution": self.attribution.to_json(),
            "scope": self.scope.to_json(),
        }


class SessionResolver:
    """Decides which session a request belongs to, and how much that is worth.

    This is the trickiest part of the design and the weakest structural link,
    exactly as the spec warns. The SDK builds a fresh `ServerSession` *and*
    `Connection` for every request on a 2026-07-28 connection, and
    `session_id` is `None` there — so the obvious "identify a session by its
    connection object" produces one session per call, taint never accumulates,
    and Trilock silently protects nothing.

    The resolution order below is therefore explicit about what each source of
    identity is worth, and `degraded` is true when the best available answer
    cannot support session accounting. `Guard` refuses to enforce while
    degraded rather than pretending: a defence that quietly does nothing is
    worse than one that says it cannot run.
    """

    def __init__(self, transport: str = "stdio") -> None:
        self.transport = transport
        self._process_token = f"pid-{os.getpid()}"
        self._degraded_warned = False
        # Not id(): CPython reuses the address of a collected object, so two
        # unrelated connections could be handed the same identity and share a
        # ledger. A weak-keyed token is unique per live object and disappears
        # with it, so an address reused later gets a fresh token.
        self._tokens: WeakKeyDictionary[object, str] = WeakKeyDictionary()

    def key_for(self, session_obj: object) -> SessionKey:
        connection = getattr(session_obj, "_connection", None)
        transport_session_id = getattr(connection, "session_id", None)
        if transport_session_id:
            return SessionKey(kind="mcp-session", value=str(transport_session_id))

        if self.transport in ("stdio", "inproc"):
            # One process, one client, for the whole life of the connection.
            # The process is the session, and that is exact rather than a guess.
            return SessionKey(kind="stdio-process", value=self._process_token)

        principal = _principal(connection)
        if principal:
            return SessionKey(kind="principal", value=principal)

        if not self._degraded_warned:
            self._degraded_warned = True
            _log.error(
                "no stable session identity available; session accounting is degraded",
                extra={
                    "transport": self.transport,
                    "consequence": "taint cannot accumulate across calls; enforcement is disabled",
                    "fix": "run a session-ful transport, or provide an authenticated principal",
                },
            )
        return SessionKey(kind="connection", value=self._token_for(connection or session_obj))

    def _token_for(self, obj: object) -> str:
        try:
            token = self._tokens.get(obj)
            if token is None:
                token = f"obj-{uuid.uuid4().hex[:16]}"
                self._tokens[obj] = token
            return token
        except TypeError:
            # Not weak-referenceable; fall back to the address and accept it.
            return f"addr-{id(obj):x}"

    def is_degraded(self, key: SessionKey) -> bool:
        """Whether `key` is too weak to carry session-level accounting."""
        return key.kind == "connection"


def _principal(connection: object) -> str | None:
    """An authenticated identity from the transport, if the deployment has one."""
    for attribute in ("user", "auth_info", "principal"):
        holder = getattr(connection, attribute, None)
        for field_name in ("subject", "sub", "client_id", "username"):
            value = getattr(holder, field_name, None)
            if value:
                return f"{attribute}:{value}"
    state = getattr(connection, "state", None)
    if isinstance(state, dict):
        value = state.get("trilock.principal")
        if value:
            return f"state:{value}"
    return None


def result_text(result: types.CallToolResult) -> str:
    """Every piece of text an agent would read from a tool result.

    Non-text blocks are not decoded: an image or an audio payload is content
    Trilock cannot fingerprint, so it is labelled by its *tool's*
    classification and never treated as clean because it happened to be
    unreadable.
    """
    parts: list[str] = [
        block.text for block in result.content if isinstance(block, types.TextContent)
    ]
    if result.structured_content is not None:
        import json

        parts.append(json.dumps(result.structured_content, sort_keys=True, default=str))
    return "\n".join(parts)


def replace_text(result: types.CallToolResult, replacements: list[str]) -> types.CallToolResult:
    """Return `result` with its text blocks replaced by normalised text, in order."""
    if not replacements:
        return result
    remaining = list(replacements)
    blocks: list[types.ContentBlock] = []
    for block in result.content:
        if isinstance(block, types.TextContent) and remaining:
            blocks.append(block.model_copy(update={"text": remaining.pop(0)}))
        else:
            blocks.append(block)
    return result.model_copy(update={"content": blocks})


def _structured_text(result: types.CallToolResult) -> str | None:
    """The result's structured payload as canonical JSON, if it has one."""
    if result.structured_content is None:
        return None
    return json.dumps(result.structured_content, sort_keys=True, default=str)


def policy_digest(policy: Policy | None) -> str:
    """A stable digest of the policy a decision was made under."""
    if policy is None:
        return "none"
    dumped = policy.model_dump(mode="json", exclude={"source_path"})
    return hashlib.sha256(
        json.dumps(dumped, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


class Guard:
    """Owns policy and session state for the life of one proxy process."""

    def __init__(
        self, config: TrilockConfig, policy: Policy | None, *, transport: str = "stdio"
    ) -> None:
        self.config = config
        self.policy = policy
        self.resolver = SessionResolver(transport)
        self.ledgers = LedgerStore(
            max_sources=config.ledger.max_sources,
            ngram_size=config.ledger.ngram_size,
            max_ngrams_per_source=config.ledger.max_ngrams_per_source,
        )
        self.sessions = SessionRegistry(self.ledgers)
        self.approvals = ApprovalStore()
        self.detectors: list[Detector] = self._build_detectors()
        self.audit: AuditLog | None = AuditLog(config.audit.path) if config.audit.enabled else None
        self.policy_hash = policy_digest(policy)

    def _build_detectors(self) -> list[Detector]:
        """Advisory detectors, per config. Never a control (Hard Rule 1).

        Prompt Guard is added only when enabled *and* installed and verified; an
        enabled-but-missing model is logged and skipped, never a startup error,
        because the guarantee does not depend on it (Hard Rule 2).
        """
        cfg = self.config.detectors
        if not cfg.enabled:
            return []
        tools = tuple(self.policy.tools) if self.policy is not None else ()
        found: list[Detector] = []
        if cfg.heuristics:
            found.append(HeuristicDetector(tool_names=tools))
        if cfg.promptguard:
            if is_available(cfg.model_dir):
                found.append(PromptGuardDetector(cfg.model_dir))
            else:
                _log.warning(
                    "promptguard enabled but the model is not installed; skipping it",
                    extra={
                        "model_dir": str(cfg.model_dir),
                        "fix": "trilock check --download-models",
                    },
                )
        return found

    async def detect(self, texts: list[str]) -> dict[str, float]:
        """Score texts with every detector under the configured budget.

        Returns only the scores that exist. A timeout or crash is logged by the
        runner and simply absent here, which the engine treats as no evidence.
        """
        if not self.detectors or not texts:
            return {}
        outcomes = await run_detectors(
            self.detectors, texts, timeout_ms=self.config.detectors.timeout_ms
        )
        return merge_scores(outcomes)

    @property
    def mode(self) -> Mode:
        return self.policy.mode if self.policy is not None else Mode.MONITOR

    @property
    def active(self) -> bool:
        """False when there is no policy at all, so the proxy is a passthrough."""
        return self.policy is not None

    # -- the call path ---------------------------------------------------

    def prepare(
        self, session_obj: object, name: str, arguments: dict[str, Any] | None
    ) -> CallContext:
        """Assemble everything needed to decide about a call. Pure bookkeeping."""
        state = self.sessions.get(self.resolver.key_for(session_obj))
        state.calls += 1
        call = ToolCall(tool=name, arguments=dict(arguments or {}), call_id=new_call_id())
        classification = self.policy.classify(name) if self.policy is not None else None
        attribution = state.attribute_call(call.arguments, self.mode)
        return CallContext(
            call=call,
            session=state,
            classification=classification,
            attribution=attribution,
            trifecta=state.trifecta(external=is_external(classification)),
            # Scope resolution touches the filesystem to follow symlinks, which
            # is why it happens here and not inside `decide`: the engine sees
            # only the boolean, and stays pure (Hard Rule 4).
            scope=check_scope(classification, call.arguments, root=self.config.base_dir),
        )

    def snapshot(
        self, ctx: CallContext, egress_scores: dict[str, float] | None = None
    ) -> SessionSnapshot:
        """Freeze everything the engine may know about this call."""
        session_label = ctx.session.ledger.session_label()
        scores = dict(session_label.detector_scores)
        for name, value in (egress_scores or {}).items():
            scores[name] = max(scores.get(name, 0.0), value)
        return SessionSnapshot(
            trifecta=ctx.trifecta,
            attribution=ctx.attribution,
            classification=ctx.classification,
            session_label=session_label,
            detector_scores=scores,
            scope_violation=ctx.scope.violated,
            normalisation_removed=sum(r.removed_chars for r in ctx.session.normalisations),
        )

    async def egress_scores(self, ctx: CallContext) -> dict[str, float]:
        """Score the outbound arguments. The exfiltration shapes live here."""
        texts = [text for _, text in walk_arguments(ctx.call.arguments) if text]
        return await self.detect(texts) if texts else {}

    def decide(self, ctx: CallContext, egress_scores: dict[str, float] | None = None) -> Decision:
        """The verdict for this call. Returns ALLOW when there is no policy.

        With no policy Trilock is a passthrough (Hard Rule 7), and with a
        degraded session identity it cannot do session-level accounting at all,
        so it says so and allows rather than enforcing on state it knows is
        wrong. Both are logged; neither is silent.
        """
        if self.policy is None:
            return Decision(
                verdict=Verdict.ALLOW, rule_id="passthrough", reasons=("no policy is configured",)
            )
        if self.resolver.is_degraded(ctx.session.key):
            _log.error(
                "refusing to enforce on a degraded session identity",
                extra={"session": str(ctx.session.key), "tool": ctx.call.tool},
            )
            return Decision(
                verdict=Verdict.ALLOW,
                rule_id="identity_degraded",
                reasons=(
                    "session identity could not be established, so trifecta accounting "
                    "would be wrong; Trilock reports rather than enforcing on it",
                ),
            )
        decision = decide(ctx.call, self.snapshot(ctx, egress_scores), self.policy)
        if decision.verdict is Verdict.ESCALATE:
            if self.approvals.redeem_offline(
                ctx.session.key,
                ctx.call.tool,
                ctx.call.arguments,
                mailbox_path(self.config.state_dir),
            ):
                return Decision(
                    verdict=Verdict.ALLOW,
                    rule_id=decision.rule_id,
                    reasons=(
                        "a human approved this exact call out of band with 'trilock approve'",
                        *decision.reasons,
                    ),
                    trifecta=decision.trifecta,
                    tainted_args=decision.tainted_args,
                    label=decision.label,
                )
            remembered = self.approvals.recall(ctx.session.key, ctx.call.tool, ctx.call.arguments)
            if remembered is not None:
                _log.info(
                    "escalation satisfied by a standing approval",
                    extra={
                        "tool": ctx.call.tool,
                        "scope": remembered.scope.value,
                        "rule_id": decision.rule_id,
                    },
                )
                return Decision(
                    verdict=Verdict.ALLOW,
                    rule_id=decision.rule_id,
                    reasons=(
                        f"a human approved this exact call earlier in this session "
                        f"(scope: {remembered.scope.value})",
                        *decision.reasons,
                    ),
                    trifecta=decision.trifecta,
                    tainted_args=decision.tainted_args,
                    label=decision.label,
                )
        return decision

    def offer_always(self, ctx: CallContext) -> bool:
        """Whether a standing 'always' approval may be offered for this call.

        Never for arguments carrying untrusted provenance: an approval that
        remembers itself is the wrong answer to a call built from
        attacker-derived content.
        """
        return not ctx.attribution.matches and ctx.attribution.complete

    def record_approval(self, ctx: CallContext, scope: ApprovalScope) -> None:
        self.approvals.remember(
            ctx.session.key,
            ctx.call.tool,
            ctx.call.arguments,
            scope,
            tainted=bool(ctx.attribution.matches) or not ctx.attribution.complete,
        )

    async def ingest(self, ctx: CallContext, result: types.CallToolResult) -> types.CallToolResult:
        """Normalise, label, score and record a tool result; return what the agent sees."""
        if result.is_error:
            # An error is the upstream's own message, not content that entered
            # the session. Labelling it would let a failed call set a leg.
            return result
        texts = [b.text for b in result.content if isinstance(b, types.TextContent)]
        structured = _structured_text(result)
        contents = [*texts, structured] if structured is not None else texts
        if not contents:
            return result
        normalised, reports = ctx.session.record_result(
            ctx.call.server, ctx.call.tool, ctx.call.call_id, contents, ctx.classification
        )
        # Detectors see the *normalised* text, so a smuggled instruction is
        # scored as the readable sentence it is, plus how much had to be
        # stripped to make it readable.
        removed = sum(r.removed_chars for r in reports)
        scores = await self.detect(
            [
                f"{text}\n[{removed} hidden characters removed]" if removed else text
                for text in normalised
            ]
        )
        if scores:
            ctx.session.attach_scores(scores)
        # Only the content blocks are substituted back; the structured payload
        # is fingerprinted but returned as the upstream produced it, because
        # rewriting a schema-validated object is not Unicode normalisation and
        # Hard Rule 5 does not license it.
        return replace_text(result, normalised[: len(texts)])

    def observe(
        self,
        ctx: CallContext,
        decision: Decision,
        *,
        snapshot: SessionSnapshot | None = None,
        latency_ms: float = 0.0,
    ) -> None:
        """Log the provenance record and the verdict, and append to the audit chain."""
        _log.info("call decided", extra={**ctx.to_json(), "decision": decision.to_json()})
        if self.audit is None:
            return
        try:
            self.audit.record_decision(
                session=str(ctx.session.key),
                call=ctx.call,
                snapshot=snapshot if snapshot is not None else self.snapshot(ctx),
                decision=decision,
                policy_mode=self.mode.value,
                policy_hash=self.policy_hash,
                latency_ms=latency_ms,
            )
        except OSError as exc:  # a full disk must not take the proxy down
            _log.error(
                "audit write failed", extra={"error": str(exc), "path": str(self.audit.path)}
            )
