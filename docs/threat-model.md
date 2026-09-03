# Threat model

This document states precisely what Trilock defends, what it does not, where
the trust boundaries are, and which link is weakest. It is written to be
argued with. If a sentence here turns out to be false, that is a bug in Trilock,
and the fix is to change the code or to change this sentence — never to leave
them disagreeing.

## What Trilock defends

**The blast radius of a hijacked agent.** Trilock assumes that indirect prompt
injection *succeeds*: that some tool result the agent reads will contain text
the agent then follows. Nothing in Trilock's guarantee depends on that not
happening. What Trilock bounds is what the hijacked agent can then *do*.

Concretely, within one session, Trilock refuses or escalates any tool call that
would complete the lethal trifecta — {untrusted input, sensitive data, external
action} — under a deterministic policy. The exfiltration in BUILD_SPEC §2 is the
canonical case: the agent reads mail (untrusted, sensitive), is told to forward
credentials, and emits `mail.send` to an attacker. The call never reaches the
mail server. The agent was compromised; the damage was zero.

The guarantee is carried by the **policy engine**, a pure function over labels
(`policy/engine.py::decide`). It does not rest on detecting injection, and
disabling every detector leaves it intact (`tests/integration/test_detectors.py`).

## What Trilock does not defend

* **The model being fooled.** Trilock does not stop injection. It stops the
  consequence. A hijacked agent behind Trilock will still *say* wrong things to
  the user, still summarise the attacker's text as if it were real, still try
  the attacker's call. That the call fails is the whole product.
* **A user who approves everything.** Escalations put the exact call, its
  taint sources and the rule that fired in front of a human. A human who says
  yes to everything is not defended, and approval fatigue is *measured* in the
  adaptive attacks rather than solved.
* **A malicious upstream server, mostly.** Tool pinning catches a server that
  changes a definition after review (the rug pull). It does nothing about a
  server that was malicious from the start, or one whose *results* are
  attacker-controlled — those results are simply labelled untrusted, which is
  the same treatment every tool result gets.
* **Anything outside the MCP path.** An agent with a shell can start an MCP
  server Trilock never sees, open its own sockets, or write files directly.
  Trilock governs the tool calls that pass through it and nothing else.
* **Multi-agent topologies.** One client, N tool servers is v1. Agent-to-agent
  delegation, where another agent is both a tool and a client, is not modelled.
* **Redirects.** A URL is checked as written. An allowlisted host that
  redirects to an attacker's host passes the scope check.
* **The model's output to the user.** Text the agent returns to the user is
  not a tool call and is not inspected. Exfiltration by *telling the user* to
  paste something somewhere is a social attack Trilock does not see.

## Trust boundaries

```
  user ──► agent (LLM) ──► MCP client ──► Trilock ──► upstream MCP servers
                                            │
                                            ├─ policy file      TRUSTED (operator-authored)
                                            ├─ tool results     UNTRUSTED (attacker may write every byte)
                                            ├─ tool arguments   UNTRUSTED (a hijacked model chose them)
                                            ├─ .trilock/        TRUSTED as the config file (same filesystem ACL)
                                            └─ audit log        INTEGRITY-PROTECTED (hash chain), not confidential
```

* **Policy is the only authority.** Nothing a tool returns can name a rule,
  add a classification or change a verdict. Tool output is data (Hard Rule 3).
* **Arguments are attacker-influenced.** They came from a model that may have
  been hijacked. They are attributed to their sources and shown to humans only
  inside a delimited, defused block.
* **The refusal text is model-visible.** What Trilock says back to the agent
  goes into a model's context. It names the rule and states the finding. It
  never echoes arguments, never fabricates success, never gives advice.
* **`.trilock/` is as trusted as `trilock.yaml`.** Writing a token into the
  approvals mailbox is equivalent to editing the config; both require the same
  local filesystem access. Pins, audit and the model directory live there too.
* **The audit log is tamper-*evident*, not secret.** Anyone who can read it
  learns tool names, taint labels, argument shapes and content hashes — never
  values (Hard Rule 6, tested by seeding fifteen secret formats). Anyone who
  can write it can break the chain, and `trilock replay` will say so.

## Session identity — the weakest structural link

Everything Trilock decides is *per session*. "This session has read untrusted
content" only means something if Trilock knows which calls belong to the same
session. It resolves identity in this order (`proxy/guard.py::SessionResolver`):

| source | when | strength |
|---|---|---|
| the protocol's `Mcp-Session-Id` | stateful Streamable HTTP | exact |
| the stdio process | stdio transport | exact — one process serves exactly one client for its life |
| an authenticated principal | HTTP with auth | exact per user; merges that user's concurrent sessions (over-taints, safe) |
| the connection object | anything else | **degraded** |

The degraded case is the one to understand. On a **stateless 2026-07-28**
connection the SDK constructs a fresh `Connection` for every request and
`session_id` is `None`. Keying on the connection object then yields one session
per call: taint never accumulates, the trifecta never reaches two legs, and
Trilock protects nothing while every log looks healthy. This is not
hypothetical — it is what an earlier version of the proxy did, and the
integration test that caught it (`tests/unit/test_session_identity.py`) is the
regression guard.

Trilock's answer is to **refuse to enforce on a degraded identity**. The
decision is recorded with `rule_id: identity_degraded`, the verdict is ALLOW,
and an error is logged once explaining that enforcement is off and why. A
defence that quietly does nothing is worse than one that says it cannot run.
Deployments on stateless HTTP must supply a principal (via auth, or
`connection.state["trilock.principal"]`) or use a session-ful transport.

Two further consequences, both accepted and documented:

* **Session eviction resets legs.** The ledger store caps live sessions
  (default 256, LRU). A very long-idle session that is evicted resumes clean.
  This is unlike *source* eviction within a session, which is conservative
  (evicted labels fold into a permanent floor and attribution latches
  incomplete) — dropping a whole session is a fresh start by design.
* **Reset is explicit.** Nothing un-sets a leg except `SessionRegistry.reset`.
  There is no timeout after which "the agent has probably moved on".

## Provenance that outlives a session

Two of the red team's published losses were *structural*: they did not defeat a
rule, they stepped outside the unit the rules account over — the session. Both
are now closed, with the before/after numbers kept in RESULTS.md.

**Sink taint** (`taint/sinks.py`, on by default). Any allowed call whose
arguments carried taint records the SHA-256 of every string argument as a
*sink*, with the taint it carried, in `.trilock/sinks.json`. Any later call — this
session, another, after a restart — whose arguments name that identifier
inherits the taint on its result. So a `memory.store(key, <tainted>)` that the
policy author classified as a plain local tool (`effect: none`, two legs, allowed)
does not launder the secret: the `memory.recall(key)` in a fresh session returns
content labelled untrusted+sensitive, and the send is the third leg. Laundering
went from 0.250 to 0.000 in both modes. It deliberately over-approximates —
every string argument of a tainted write is a sink, because guessing which one
"is the key" is how a defence gets bypassed — and it stores hashes, never values.

**Durable sessions** (`taint/durable.py`, opt-in via `sessions: {durable: true}`).
A session's legs, evicted floor and n-gram fingerprints — never exact tokens,
which are emails, URLs and secret-shaped strings — are persisted per (OS user,
config file) and resumed by the next stdio process within a TTL (24 h). Read in
one session, reconnect, send from a fresh one: the send is now the third leg.
Session splitting went from 1.000 to 0.000 with it on. It is opt-in because it
trades utility — a morning of reading untrusted pages makes the afternoon's
first external action an escalation — and it does not cross OS users, machines,
or the TTL.

**What neither closes.** A different OS user, a different machine, an attacker
who waits out the TTL, or content that leaves through a channel Trilock does not
see (the model telling the user to paste something) all remain outside the
session boundary and are listed below.

## Known gaps in attribution (why `strict` exists)

`dataflow` mode decides on argument attribution: which ledger sources an
outbound argument derives from, by n-gram and identifier matching. This is
useful and it is imperfect, and the imperfections are enumerated rather than
assumed away (`tests/unit/test_propagate.py`, rows marked KNOWN MISS):

* **Paraphrase.** Restated content shares no 5-grams. Not attributed.
* **Short fragments.** Fewer tokens than the window and no identifier shape.
  Not attributed.
* **Multi-layer encoding.** One layer of base64 is decoded; two are not.
* **Long-document tail.** Each source's fingerprint is capped (default 4096
  n-grams ≈ the first ~20 KB); content beyond the cap is not fingerprinted.
* **Laundering through a `public`/trusted tool — within a session, before the
  content is written anywhere.** Content passed through an in-memory tool and
  back is still attributed to its original source by n-gram (the red team's
  `via_trusted_public_tool` scores 0). Once it is *written* somewhere, sink taint
  takes over (above).

`strict` mode ignores attribution and decides on session-level legs, so every
one of these misses is caught — at the utility cost measured in RESULTS.md.
The adaptive attacker (`bench/adaptive/`) targets each of these seams on
purpose and publishes the resulting ASR per mode.

## The weakest links, ranked

1. **Session identity under stateless HTTP** (above). Structural; mitigated by
   refusing to enforce rather than by being right. Session *splitting* on stdio
   is closed by durable sessions only when opted in and only for the same user,
   machine and TTL window.
2. **Approval fatigue.** A present human is the last line for ESCALATE, and
   humans habituate. Measured, not solved.
3. **Attribution misses in `dataflow`.** Enumerated above; `strict` is the
   remedy and costs utility.
3a. **Two-leg integrity attacks.** The trifecta bounds disclosure, not every
   action; `policies/integrity.yaml` escalates any external action after
   untrusted input, at a measured utility cost (RESULTS.md).
4. **Policy authoring.** An unclassified tool is never allowed, but a
   *misclassified* one — an egress marked `reads: trusted`, say — is a hole the
   author made. `trilock check` prints the resolved table so it can be reviewed.
5. **Redirects and out-of-band exfiltration** (telling the user, DNS, timing).
   Out of scope and stated as such.
