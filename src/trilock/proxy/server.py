"""The MCP server Trilock exposes downstream, to the agent.

Trilock is a proxy: this server owns no tools. Everything it lists and
everything it executes comes from an upstream via the router. What it adds is
the decision point in the middle — which, until Phase 2, is a no-op.

Handlers are registered on the low-level `Server` rather than the decorator
API because a proxy must forward whatever it is handed, including shapes it
does not itself model.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

import mcp_types as types
from mcp.server import InitializationOptions, NotificationOptions, ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.request_state import RequestStateBoundary, RequestStateSecurity
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS

from trilock import __version__, log
from trilock.approval import (
    APPROVAL_KEY,
    PENDING_TTL,
    ApprovalScope,
    approval_schema,
    render_prompt,
)
from trilock.config import TrilockConfig
from trilock.policy.decision import Decision, Verdict
from trilock.policy.model import load_policy
from trilock.proxy.guard import CallContext, Guard
from trilock.proxy.pins import PinStore
from trilock.proxy.router import RouteError, Router
from trilock.proxy.upstream import UpstreamUnavailableError, open_pool

SERVER_NAME: Final[str] = "trilock"

_log = log.get("proxy.server")

Ctx = ServerRequestContext[None, Any]


def _as_mcp_error(exc: Exception) -> MCPError:
    """Turn a routing failure into a protocol error the client can render.

    `tools/call` reports failure in-band, as an isError result the model reads.
    `prompts/*` and `resources/*` have no such channel, so an unroutable name
    must surface as a JSON-RPC error rather than an unhandled traceback that
    takes the connection down.
    """
    return MCPError(INVALID_PARAMS, str(exc))


def _error_result(message: str) -> types.CallToolResult:
    """A tool error the *agent* reads.

    Deliberately terse and non-directive: this text goes back into a model's
    context, so it must not read as an instruction (Hard Rule 3 in the other
    direction). It states what happened and nothing more.
    """
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


def _scope_of(value: object) -> ApprovalScope:
    """The approval scope a client asked for, defaulting to the safest one.

    Anything unrecognised becomes `once`: a malformed answer must not widen an
    approval.
    """
    try:
        return ApprovalScope(str(value))
    except ValueError:
        return ApprovalScope.ONCE


def _client_can_elicit(ctx: Ctx) -> bool:
    """Whether this client can put a question to a human.

    On 2026-07-28 the elicitation rides inside the result, so the capability is
    what says whether anyone will read it. A client that cannot elicit gets a
    deny with instructions, never a silent allow.
    """
    capabilities = getattr(ctx.session, "client_capabilities", None)
    return getattr(capabilities, "elicitation", None) is not None


def _undeliverable(decision: Decision, approval_id: str) -> Decision:
    return Decision(
        verdict=Verdict.DENY,
        rule_id=decision.rule_id,
        reasons=(
            *decision.reasons,
            "this call needs a human decision, and this client cannot present one. "
            f"A person on this machine can approve exactly this call once by running "
            f"'trilock approve {approval_id}', after which the same call will go through; "
            "or use a client that supports elicitation. An unanswerable question is "
            "never treated as a yes.",
        ),
        trifecta=decision.trifecta,
        tainted_args=decision.tainted_args,
        label=decision.label,
    )


def _declined(decision: Decision) -> Decision:
    return Decision(
        verdict=Verdict.DENY,
        rule_id=decision.rule_id,
        reasons=("a human was asked to approve this call and declined.", *decision.reasons),
        trifecta=decision.trifecta,
        tainted_args=decision.tainted_args,
        label=decision.label,
    )


def _replayed(decision: Decision) -> Decision:
    return Decision(
        verdict=Verdict.DENY,
        rule_id=decision.rule_id,
        reasons=(
            "the approval token presented with this call was forged, expired, altered, "
            "or already used. Approval tokens are single use.",
        ),
        trifecta=decision.trifecta,
        tainted_args=decision.tainted_args,
        label=decision.label,
    )


def _consume(
    guard: Guard, call_ctx: CallContext, params: types.CallToolRequestParams
) -> object | None:
    """Redeem the nonce carried in the (already unsealed) request state."""
    raw = params.request_state
    if not raw:
        return None
    try:
        nonce = json.loads(raw).get("nonce")
    except (ValueError, AttributeError):
        return None
    if not isinstance(nonce, str):
        return None
    return guard.approvals.consume(nonce, call_ctx.session.key, params.name, params.arguments)


def _refusal(decision: Decision) -> types.CallToolResult:
    """The tool error returned for a blocked call.

    Three things this must not be. Not a fabricated success — an agent told a
    send succeeded will report to the user that it did. Not an echo of the
    call's arguments — those may carry content an attacker wrote, and this text
    goes straight back into the model's context. And not advice: no "you
    should", no "try instead", nothing a hijacked model can read as the next
    instruction. It names the rule and states the finding, so a *developer*
    reading the transcript can act on it.
    """
    lines = [
        f"Trilock refused this call. rule={decision.rule_id} verdict={decision.verdict.value}",
        *(f"- {reason}" for reason in decision.reasons),
    ]
    if decision.tainted_args:
        lines.append(
            f"- arguments carrying untrusted provenance: {', '.join(decision.tainted_args)}"
        )
    return _error_result("\n".join(lines))


def _progress_bridge(ctx: Ctx) -> Any:
    """Forward upstream progress to whoever asked for it downstream.

    `session.report_progress` is scoped to the inbound request and is a no-op
    when the caller did not ask for progress, which makes it the only correct
    bridge here. The obvious alternative — reading `progress_token` out of the
    downstream `_meta` and calling `send_progress_notification` — works only
    over JSON-RPC: an in-process client (and every 2026-07-28 caller, where
    client-to-server progress is deprecated) passes a callback with no token on
    the wire, so the token lookup finds nothing and every notification is
    silently dropped.

    The bridge is therefore installed unconditionally. The cost is that an
    upstream may produce progress no one consumes; the alternative is a proxy
    that swallows progress, which is worse.
    """

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        await ctx.session.report_progress(progress, total, message)

    return on_progress


def _elicit(
    decision: Decision, tool: str, arguments: dict[str, Any], *, offer_always: bool
) -> types.ElicitRequest:
    """The approval request embedded in an `input_required` result."""
    return types.ElicitRequest(
        params=types.ElicitRequestFormParams(
            mode="form",
            message=render_prompt(decision, tool, arguments),
            requested_schema=approval_schema(offer_always=offer_always),
        )
    )


def _answer(params: types.CallToolRequestParams) -> types.ElicitResult | None:
    """The human's answer to a held call, if this request carries one."""
    responses = params.input_responses or {}
    answer = responses.get(APPROVAL_KEY)
    return answer if isinstance(answer, types.ElicitResult) else None


def build_server(router: Router, guard: Guard | None = None) -> Server[None]:
    """Construct the downstream-facing MCP server over `router`."""
    server: Server[None] = Server(SERVER_NAME, version=__version__)

    async def on_list_tools(_ctx: Ctx, _p: types.PaginatedRequestParams) -> types.ListToolsResult:
        return await router.list_tools()

    async def on_call_tool(
        ctx: Ctx, params: types.CallToolRequestParams
    ) -> types.CallToolResult | types.InputRequiredResult:
        call_ctx = guard.prepare(ctx.session, params.name, params.arguments) if guard else None
        if guard is not None and call_ctx is not None:
            decision = guard.decide(call_ctx)
            guard.observe(call_ctx, decision)
            if decision.verdict is Verdict.ESCALATE:
                held = _handle_escalation(ctx, guard, call_ctx, decision, params)
                if held is not None:
                    return held
            elif decision.blocked:
                # The upstream is never reached. Blocking after the fact would
                # mean the side effect already happened.
                _log.warning(
                    "call refused",
                    extra={"tool": params.name, "decision": decision.to_json()},
                )
                return _refusal(decision)
        try:
            result = await router.call_tool(
                params.name,
                params.arguments,
                meta=ctx.meta,
                progress_callback=_progress_bridge(ctx),
            )
        except (RouteError, UpstreamUnavailableError) as exc:
            _log.warning("tools/call not routed", extra={"tool": params.name, "error": str(exc)})
            return _error_result(str(exc))
        if guard is not None and call_ctx is not None:
            result = guard.ingest(call_ctx, result)
        return result

    async def on_list_prompts(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListPromptsResult:
        return await router.list_prompts()

    async def on_get_prompt(
        ctx: Ctx, params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        return await router.get_prompt(params.name, params.arguments, meta=ctx.meta)

    async def on_list_resources(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListResourcesResult:
        return await router.list_resources()

    async def on_list_resource_templates(
        _ctx: Ctx, _p: types.PaginatedRequestParams
    ) -> types.ListResourceTemplatesResult:
        return await router.list_resource_templates()

    async def on_read_resource(
        ctx: Ctx, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        return await router.read_resource(str(params.uri), meta=ctx.meta)

    def _handle_escalation(
        ctx: Ctx,
        guard: Guard,
        call_ctx: CallContext,
        decision: Decision,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult | None:
        """Drive one round of human approval.

        Returns the result to send back, or ``None`` to let the call proceed
        because a human said yes.
        """
        answer = _answer(params)
        if answer is None:
            if not _client_can_elicit(ctx):
                # Task 3.2: a client that cannot ask a human gets a DENY that
                # explains the out-of-band path. ESCALATE never degrades to
                # ALLOW — that would turn an unanswerable question into a yes.
                approval_id = guard.approvals.issue_offline(
                    call_ctx.session.key, params.name, params.arguments, decision
                )
                _log.warning(
                    "client cannot elicit; escalation degraded to deny",
                    extra={
                        "tool": params.name,
                        "rule_id": decision.rule_id,
                        "approval_id": approval_id,
                    },
                )
                return _refusal(_undeliverable(decision, approval_id))
            nonce = guard.approvals.issue(
                call_ctx.session.key, params.name, params.arguments, decision
            )
            return types.InputRequiredResult(
                input_requests={
                    APPROVAL_KEY: _elicit(
                        decision,
                        params.name,
                        params.arguments or {},
                        offer_always=guard.offer_always(call_ctx),
                    )
                },
                request_state=json.dumps({"nonce": nonce}),
            )

        # The client came back with an answer. The transport has already
        # verified the sealed state's signature, TTL and binding to this exact
        # call; the nonce below is what makes it single use.
        held = _consume(guard, call_ctx, params)
        if held is None:
            return _refusal(_replayed(decision))
        if answer.action != "accept" or not (answer.content or {}).get("approve"):
            _log.info("human declined", extra={"tool": params.name, "action": answer.action})
            return _refusal(_declined(decision))
        raw_scope = (answer.content or {}).get("scope")
        scope = _scope_of(raw_scope)
        guard.record_approval(call_ctx, scope)
        _log.info(
            "human approved",
            extra={"tool": params.name, "scope": scope.value, "rule_id": decision.rule_id},
        )
        return None

    server.add_request_handler("tools/list", types.PaginatedRequestParams, on_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, on_call_tool)
    server.add_request_handler("prompts/list", types.PaginatedRequestParams, on_list_prompts)
    server.add_request_handler("prompts/get", types.GetPromptRequestParams, on_get_prompt)
    server.add_request_handler("resources/list", types.PaginatedRequestParams, on_list_resources)
    server.add_request_handler(
        "resources/templates/list", types.PaginatedRequestParams, on_list_resource_templates
    )
    server.add_request_handler("resources/read", types.ReadResourceRequestParams, on_read_resource)

    # The multi-round-trip boundary seals every `requestState` we mint under a
    # per-process AES-256-GCM key and binds it to the method, target and
    # argument digest with a TTL, refusing anything forged, expired, altered or
    # addressed to another call. Trilock's own single-use nonce sits inside
    # that envelope and is what stops the *same* call being replayed.
    server.middleware.append(
        RequestStateBoundary(
            RequestStateSecurity.ephemeral(ttl=PENDING_TTL), default_audience=SERVER_NAME
        )
    )
    return server


def initialization_options(server: Server[None]) -> InitializationOptions:
    """Capabilities Trilock advertises downstream.

    The union of what the upstreams can do is not known until they connect, and
    a client that learns of a capability late cannot use it. Trilock therefore
    advertises the full set it is willing to forward, and answers with an empty
    listing when no upstream provides one.
    """
    return server.create_initialization_options(
        NotificationOptions(prompts_changed=True, resources_changed=True, tools_changed=True)
    )


@asynccontextmanager
async def build_proxy(
    config: TrilockConfig,
) -> AsyncIterator[tuple[Server[None], Router, Guard]]:
    """Open the upstream pool and build the downstream server over it."""
    policy = load_policy(config.policy) if config.policy is not None else None
    # `strict` mode implies strict pinning: a policy that refuses an
    # unclassified tool would be inconsistent if it still exposed one whose
    # definition had changed underneath it.
    strict_pins = config.pins.strict or (policy is not None and policy.mode.value == "strict")
    pins = PinStore.load(config.pins.path, strict=strict_pins) if config.pins.enabled else None
    guard = Guard(config, policy)
    async with open_pool(config) as pool:
        router = Router(pool, pins)
        _log.info(
            "proxy ready",
            extra={
                "upstreams": pool.statuses(),
                "policy": str(config.policy) if config.policy else None,
                "mode": guard.mode.value,
            },
        )
        yield build_server(router, guard), router, guard


async def serve_stdio(config: TrilockConfig) -> None:
    """Serve the proxy over stdio until the client closes the connection."""
    from mcp.server.stdio import stdio_server

    async with build_proxy(config) as (server, _router, _guard):
        _log.info("serving over stdio", extra={"upstreams": sorted(config.servers)})
        # stdio_server() claims fd 1 and points it at stderr, so stray *native*
        # writes miss the wire. The guard goes inside that claim, not around it:
        # it adds a log record for stray Python-level writes, and installing it
        # first would hide the real stdout the SDK needs to take over.
        async with stdio_server() as (read_stream, write_stream):
            with log.guard_stdout():
                await server.run(read_stream, write_stream, initialization_options(server))
