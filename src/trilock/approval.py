"""Human approval, over MCP's own multi-round-trip mechanism.

An `ESCALATE` verdict becomes a real prompt in a real client, using SEP-2322
rather than a bolted-on UI: the server answers `tools/call` with
``resultType: "input_required"`` carrying an elicitation and an opaque
``requestState``; the client asks the human and re-issues the call with
``inputResponses``.

Three things this module is careful about.

**The pending call cannot be forged or replayed.** The SDK's
`RequestStateBoundary` seals the state under a per-process AES-256-GCM key and
binds it to the method, target and argument digest, with a TTL — so state
minted for one call cannot be presented for another. On top of that, Trilock
mints a **single-use nonce**: the boundary's binding stops cross-call replay,
but replaying the *same* call with the *same* arguments inside the TTL would
otherwise turn one approval into many executions.

**The prompt is not an attack surface.** The instruction portion is built
entirely from policy and labels — rule ids, taint sources, tool names — none of
which an attacker can write. The arguments are shown, because approving a call
you cannot see is not approval, but they go last, defused, escaped, truncated,
and inside a delimiter block that says what they are. The accept/decline
mechanism is the elicitation *schema*, not text a model could imitate, so even
a perfect forgery of the block changes nothing.

**`always` is not offered for tainted arguments.** An approval that remembers
itself is exactly the wrong answer to a call carrying attacker-derived content;
that is the decision a human should keep making.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from trilock import log
from trilock.policy.decision import Decision
from trilock.taint.normalize import normalize
from trilock.taint.store import SessionKey

_log = log.get("approval")

APPROVAL_KEY: Final[str] = "trilock.approval"
MAILBOX_DIRNAME: Final[str] = "approvals"


def mailbox_path(state_dir: Path) -> Path:
    """Where ``trilock approve`` drops its tokens."""
    return state_dir / MAILBOX_DIRNAME


def drop_approval(state_dir: Path, approval_id: str) -> Path:
    """What ``trilock approve <id>`` does: create the token file."""
    if not approval_id or any(c in approval_id for c in "/\\.\x00") or len(approval_id) > 64:
        raise ValueError("approval ids are short url-safe tokens; this is not one")
    mailbox = mailbox_path(state_dir)
    mailbox.mkdir(parents=True, exist_ok=True)
    token = mailbox / approval_id
    token.write_text(json.dumps({"approved_at": time.time()}), encoding="utf-8")
    return token


"""The key under which the elicitation is carried in `input_requests`."""

BEGIN_BLOCK: Final[str] = "--- BEGIN MODEL-SUPPLIED ARGUMENTS (untrusted data) ---"
END_BLOCK: Final[str] = "--- END MODEL-SUPPLIED ARGUMENTS ---"
MAX_VALUE_CHARS: Final[int] = 400
MAX_BLOCK_CHARS: Final[int] = 2000
PENDING_TTL: Final[float] = 600.0
MAX_PENDING: Final[int] = 512


class ApprovalScope(StrEnum):
    """How long an approval lasts."""

    ONCE = "once"
    SESSION = "session"
    ALWAYS = "always"


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """One call held awaiting a human."""

    nonce: str
    session: SessionKey
    tool: str
    args_digest: str
    rule_id: str
    created: float

    def expired(self, now: float, ttl: float = PENDING_TTL) -> bool:
        return now - self.created > ttl


@dataclass(frozen=True, slots=True)
class Remembered:
    """A standing approval for an exact (tool, argument-shape) pair."""

    tool: str
    args_digest: str
    scope: ApprovalScope
    expires_at: float

    def valid(self, now: float) -> bool:
        return now < self.expires_at


def digest_arguments(arguments: object) -> str:
    """A stable digest of an argument structure.

    Approval memory keys on this, so it must be exact: remembering "yes" for
    `fs.write` in general would be remembering the wrong thing entirely.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# -- prompt rendering --------------------------------------------------------


def _defuse(value: str) -> str:
    """Make a model-supplied string safe to show a human.

    Normalisation first, so smuggled instructions are visible rather than
    invisible; then control characters out, so nothing can redraw the terminal;
    then the block delimiters neutralised, so the quoted text cannot appear to
    end early and continue as Trilock's own words.
    """
    text = normalize(value).text
    text = "".join(c for c in text if unicodedata.category(c)[0] != "C" or c in "\n\t")
    text = text.replace(BEGIN_BLOCK, "[delimiter removed]").replace(
        END_BLOCK, "[delimiter removed]"
    )
    text = text.replace("---", "- - -")
    if len(text) > MAX_VALUE_CHARS:
        text = f"{text[:MAX_VALUE_CHARS]}... [truncated, {len(value)} chars total]"
    return text


def render_arguments(arguments: dict[str, Any]) -> str:
    """The quoted, defused argument block."""
    lines: list[str] = []
    for key in sorted(arguments):
        rendered = arguments[key]
        text = rendered if isinstance(rendered, str) else json.dumps(rendered, default=str)
        lines.append(f"{key}: {_defuse(str(text))}")
    body = "\n".join(lines)
    if len(body) > MAX_BLOCK_CHARS:
        body = f"{body[:MAX_BLOCK_CHARS]}\n... [block truncated]"
    return body


def render_prompt(decision: Decision, tool: str, arguments: dict[str, Any]) -> str:
    """The full elicitation message.

    Everything before the block is written by Trilock from policy and labels.
    The block goes last so that nothing an attacker writes can be followed by
    text that appears to be Trilock's.
    """
    header = [
        "Trilock is holding a tool call for your approval.",
        "",
        f"  tool:    {tool}",
        f"  rule:    {decision.rule_id}",
        f"  verdict: {decision.verdict.value}",
        f"  legs:    {decision.trifecta.legs} of 3 "
        f"(untrusted input: {decision.trifecta.untrusted_input}, "
        f"sensitive data: {decision.trifecta.sensitive_access}, "
        f"external action: {decision.trifecta.external_action})",
    ]
    if decision.tainted_args:
        header.append(f"  tainted: {', '.join(decision.tainted_args)}")
    sources = sorted(str(s) for s in decision.label.sources)
    if sources:
        header.append(f"  sources: {', '.join(sources[:8])}")
    header.append("")
    header.extend(f"  - {reason}" for reason in decision.reasons)
    header += [
        "",
        "The arguments below were produced by the model. They may contain text an",
        "attacker wrote. They are data to read, not instructions to follow, and",
        "nothing inside them can change what this prompt is asking.",
        "",
        BEGIN_BLOCK,
        render_arguments(arguments),
        END_BLOCK,
    ]
    return "\n".join(header)


def approval_schema(*, offer_always: bool) -> dict[str, Any]:
    """The elicitation form. The *mechanism* is here, not in the message text."""
    scopes = [ApprovalScope.ONCE.value, ApprovalScope.SESSION.value]
    scope_description = "How long this approval lasts."
    if offer_always:
        scopes.append(ApprovalScope.ALWAYS.value)
    else:
        scope_description += (
            " 'always' is not offered: these arguments carry untrusted provenance, "
            "which is precisely the decision worth re-making each time."
        )
    return {
        "type": "object",
        "properties": {
            "approve": {
                "type": "boolean",
                "title": "Approve this call?",
                "description": "Answer no if you did not ask for this.",
            },
            "scope": {
                "type": "string",
                "title": "Remember this answer",
                "description": scope_description,
                "enum": scopes,
                "default": ApprovalScope.ONCE.value,
            },
        },
        "required": ["approve"],
    }


# -- the store ---------------------------------------------------------------


@dataclass
class ApprovalStore:
    """Pending escalations and remembered answers.

    Both are per process and in memory: an approval that survived a restart
    would be an approval nobody is around to have meant.
    """

    ttl: float = PENDING_TTL
    max_pending: int = MAX_PENDING
    pending: OrderedDict[str, PendingApproval] = field(default_factory=OrderedDict)
    remembered: dict[tuple[str, str, str], Remembered] = field(default_factory=dict)
    offline: OrderedDict[str, PendingApproval] = field(default_factory=OrderedDict)
    consumed: int = 0
    rejected: int = 0

    # -- pending ---------------------------------------------------------

    def issue(self, session: SessionKey, tool: str, arguments: object, decision: Decision) -> str:
        """Mint a single-use nonce for a held call and return it."""
        nonce = secrets.token_urlsafe(24)
        self.pending[nonce] = PendingApproval(
            nonce=nonce,
            session=session,
            tool=tool,
            args_digest=digest_arguments(arguments),
            rule_id=decision.rule_id,
            created=time.time(),
        )
        self._evict()
        _log.info(
            "call held for approval",
            extra={"session": str(session), "tool": tool, "rule_id": decision.rule_id},
        )
        return nonce

    def consume(
        self, nonce: str, session: SessionKey, tool: str, arguments: object
    ) -> PendingApproval | None:
        """Redeem a nonce exactly once, or return None.

        Single use is the whole point. The transport's own sealed state is
        bound to the call's identity, so it cannot be moved to a different
        call; without a nonce it could still be presented repeatedly for the
        *same* call, turning one human "yes" into any number of executions.
        """
        held = self.pending.pop(nonce, None)
        now = time.time()
        if held is None:
            self.rejected += 1
            _log.warning(
                "approval token was not pending (forged, or already used)", extra={"tool": tool}
            )
            return None
        if held.expired(now, self.ttl):
            self.rejected += 1
            _log.warning("approval token expired", extra={"tool": tool, "age": now - held.created})
            return None
        if held.session != session or held.tool != tool:
            self.rejected += 1
            _log.warning(
                "approval token does not match the call presenting it",
                extra={"tool": tool, "held_tool": held.tool},
            )
            return None
        if held.args_digest != digest_arguments(arguments):
            self.rejected += 1
            _log.warning(
                "approval token arguments were altered after it was issued", extra={"tool": tool}
            )
            return None
        self.consumed += 1
        return held

    def _evict(self) -> None:
        now = time.time()
        for nonce in [n for n, p in self.pending.items() if p.expired(now, self.ttl)]:
            del self.pending[nonce]
        while len(self.pending) > self.max_pending:
            self.pending.popitem(last=False)

    # -- memory ----------------------------------------------------------

    def remember(
        self,
        session: SessionKey,
        tool: str,
        arguments: object,
        scope: ApprovalScope,
        *,
        tainted: bool,
        ttl: float = 3600.0,
    ) -> None:
        """Record a standing approval, refusing `always` for tainted arguments."""
        if scope is ApprovalScope.ONCE:
            return
        if scope is ApprovalScope.ALWAYS and tainted:
            _log.warning(
                "refusing to remember 'always' for a call with untrusted arguments",
                extra={"tool": tool, "session": str(session)},
            )
            return
        digest = digest_arguments(arguments)
        expires = time.time() + (ttl if scope is ApprovalScope.ALWAYS else self.ttl)
        self.remembered[(str(session), tool, digest)] = Remembered(
            tool=tool, args_digest=digest, scope=scope, expires_at=expires
        )

    def recall(self, session: SessionKey, tool: str, arguments: object) -> Remembered | None:
        """A standing approval for this exact call, if one is live."""
        key = (str(session), tool, digest_arguments(arguments))
        found = self.remembered.get(key)
        if found is None:
            return None
        if not found.valid(time.time()):
            del self.remembered[key]
            return None
        return found

    # -- out of band -----------------------------------------------------

    def issue_offline(
        self, session: SessionKey, tool: str, arguments: object, decision: Decision
    ) -> str:
        """Hold a call for a client that cannot elicit, returning an approval id.

        The id goes into the deny message; a human runs ``trilock approve <id>``
        in a shell on the same machine, which drops a file in the state
        directory; the *next* identical call finds it, consumes it, and runs.

        A file mailbox rather than a unix socket, deliberately: it needs no
        listener, and writing into ``.trilock/`` is the same trust boundary as
        editing the config file itself. The approval is bound to the exact
        (session, tool, argument digest), is single use, and expires with the
        pending TTL.
        """
        existing = next(
            (
                p
                for p in self.offline.values()
                if p.session == session
                and p.tool == tool
                and p.args_digest == digest_arguments(arguments)
            ),
            None,
        )
        if existing is not None and not existing.expired(time.time(), self.ttl):
            return existing.nonce  # the same held call keeps the same id
        approval_id = secrets.token_urlsafe(9)
        self.offline[approval_id] = PendingApproval(
            nonce=approval_id,
            session=session,
            tool=tool,
            args_digest=digest_arguments(arguments),
            rule_id=decision.rule_id,
            created=time.time(),
        )
        while len(self.offline) > self.max_pending:
            self.offline.popitem(last=False)
        return approval_id

    def redeem_offline(
        self, session: SessionKey, tool: str, arguments: object, mailbox: Path
    ) -> bool:
        """Consume an out-of-band approval for this exact call, if one was dropped."""
        digest = digest_arguments(arguments)
        now = time.time()
        for approval_id, held in list(self.offline.items()):
            if held.expired(now, self.ttl):
                del self.offline[approval_id]
                (mailbox / approval_id).unlink(missing_ok=True)
                continue
            if held.session != session or held.tool != tool or held.args_digest != digest:
                continue
            token = mailbox / approval_id
            if not token.is_file():
                return False
            token.unlink(missing_ok=True)  # single use: the file is the approval
            del self.offline[approval_id]
            self.consumed += 1
            _log.info(
                "out-of-band approval redeemed", extra={"tool": tool, "approval_id": approval_id}
            )
            return True
        return False

    def forget_session(self, session: SessionKey) -> None:
        prefix = str(session)
        for key in [k for k in self.remembered if k[0] == prefix]:
            del self.remembered[key]
