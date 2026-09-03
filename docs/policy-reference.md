# Policy reference

A Trilock policy is a YAML document validated by Pydantic v2 models
(`src/trilock/policy/model.py`). Unknown keys are errors everywhere: a typo in a
security tool's configuration must never silently disable a control. Policy is
the *only* source of authority — nothing a tool returns can name a rule, add a
classification, or change a verdict.

`trilock check` validates a policy and prints the resolved classification for
every tool it can see.

## Top level

```yaml
version: 1                 # required literal
mode: dataflow             # strict | dataflow | monitor      (default: dataflow)
unclassified: escalate     # escalate | deny                  (default: by mode; never allow)
tools: { ... }             # tool classifications, keyed by "<server>.<tool>" or a glob
rules: [ ... ]             # ordered; first match wins; implicit terminal deny
```

### `mode`

| mode | what a decision may consult | intent |
|---|---|---|
| `strict` | session-level legs only | Maximum security. Attribution is ignored entirely, so paraphrase, re-encoding and laundering cannot make an argument look clean. An unclassified tool is denied. Costs utility (measured in RESULTS.md). |
| `dataflow` | session legs **and** argument attribution | A call whose arguments provably carry no untrusted content is allowed even in a session holding all three legs. Exactly as strong as attribution — see the KNOWN MISS rows in `tests/unit/test_propagate.py`. |
| `monitor` | everything | Decide and log, block nothing. For onboarding onto a live deployment: run it, read the log, fix the policy, then switch. |

### `unclassified`

What a tool nobody classified receives. Defaults to `deny` in `strict` and
`escalate` otherwise. **`allow` is rejected at load time.** This is applied as
a *floor* after rule evaluation — a rule may make an unclassified tool
stricter, never looser — so a policy whose rules end in a broad `allow` still
never lets an unclassified tool through.

## `tools`

Each entry classifies one tool (exact name) or a set of tools (glob). Exact
matches beat globs; among globs the longest pattern wins and ties break
lexicographically, so resolution is reproducible.

```yaml
tools:
  "mail.search": { reads: untrusted, sensitivity: sensitive }
  "mail.send":   { effect: external, describe: "sends email externally" }
  "fs.write":    { effect: external, scope: "./workspace/**" }
  "web.*":       { reads: untrusted, sensitivity: public }
```

| field | values | default | meaning |
|---|---|---|---|
| `reads` | `trusted` \| `untrusted` \| absent | absent | Trust level of the content this tool **returns**. `untrusted` sets the session's *untrusted input* leg when the tool returns. Absent means the output is not worth labelling — but note an *unclassified* tool's output is treated as untrusted. |
| `sensitivity` | `public` \| `sensitive` | `public` | Whether the content the tool returns or touches is private. `sensitive` sets the *sensitive access* leg on return. |
| `effect` | `none` \| `external` | `none` | `external` means calling the tool changes state or communicates outside the session. Evaluated **per call**: it is the third leg for that call only. |
| `scope` | string or list of patterns | `()` | Where an external action may act. See below. |
| `describe` | string | `""` | Human note carried into the approval prompt. |

### `scope`

Deny-by-default within each declared kind. Kind is inferred from the pattern
or stated with a prefix:

| pattern | kind | matched against |
|---|---|---|
| `./workspace/**`, `/data/**`, `path:...` | path | the argument, **resolved**: `..`, symlinks, percent-encoding, backslashes and Unicode-confusable components are undone first, and a glob is anchored at its own non-glob prefix |
| `api.example.com`, `*.cdn.example.com`, `host:...` | host | the parsed hostname of every URL in the arguments. Userinfo, fragments and ports cannot fake membership; `*.example.com` requires a real label boundary; non-`http(s)` schemes are refused; a mixed-script (homoglyph) host is refused outright |
| `@example.com`, `@.corp.example.com`, `email:...` | email | the domain after the last `@` of every address in the arguments |

Only kinds the policy declares are enforced: a path-scoped tool is not also an
email allowlist. A violation feeds the `scope_violation` condition. **Redirects
are not followed**; a URL is checked as written.

## `rules`

```yaml
rules:
  - id: tainted_egress                      # required, unique, [a-z0-9_]+
    when: { effect: external, args_tainted_by: untrusted, session_touched: sensitive }
    then: deny                              # allow | deny | escalate
    because: "why, shown to the human"      # optional
```

Rules are evaluated **in order; the first whose every condition holds wins.**
If none matches, the terminal `default_deny` applies. Every decision names the
rule that produced it.

### Conditions

All fields present on a `when` must hold. An empty `when` is rejected (it
would match everything and shadow every later rule).

| condition | type | holds when |
|---|---|---|
| `tool` | glob | the namespaced tool name matches |
| `effect` | `none` \| `external` | the tool's classified effect equals this |
| `trifecta_legs` | 0–3 | the call stands on **at least** this many legs (so `0` matches every call) |
| `args_tainted_by` | `untrusted` | the call's arguments carry untrusted taint — **mode-dependent**, see below |
| `session_touched` | `sensitive` | the session has ingested sensitive content |
| `session_untrusted` | bool | the session has ingested untrusted content. With `effect: external` this is the *integrity* rule (`policies/integrity.yaml`): every external action after untrusted input, whether or not private data was touched |
| `unclassified` | bool | the tool has no classification |
| `scope_violation` | bool | an argument fell outside the tool's declared scope |
| `detector_above` | `{name: threshold}` | **every** named detector scored above its threshold. A detector with no score (timed out, crashed, disabled) never satisfies this. Advisory only: may select a stricter verdict, never a looser one |

### How `args_tainted_by: untrusted` is decided

This one condition is where the modes differ, and it is the whole
security/utility trade:

* **`strict`**: attribution is not consulted. The condition holds if the
  *session* has ingested any untrusted content. Paraphrase cannot launder.
* **`dataflow`**: holds if attribution matched the arguments to an untrusted
  source — **or** if the ledger has evicted sources, in which case a negative
  result proves nothing and the session-level answer is used instead.

### Verdicts

| verdict | effect |
|---|---|
| `allow` | forwarded to the upstream |
| `deny` | refused with an MCP tool error naming the rule; the upstream is never called |
| `escalate` | held for a human via MRTR (`resultType: input_required`). A client without elicitation gets a `deny` naming an approval id for `trilock approve <id>`. **Never degrades to allow.** |

### The detector floor

Independently of any rule, an `allow` becomes `escalate` when any advisory
detector scores ≥ 0.9. Nothing a detector does can make a verdict looser
(property-tested: zeroing every score never makes a decision stricter; maxing
every score never makes one looser).

## Worked examples

**The shipped default** (`policies/default.yaml`), abridged:

```yaml
rules:
  - { id: scope_violation, when: { scope_violation: true }, then: deny }
  - { id: tainted_egress,  when: { effect: external, args_tainted_by: untrusted, session_touched: sensitive }, then: deny }
  - { id: rule_of_two,     when: { trifecta_legs: 3 }, then: escalate }
  - { id: unclassified_tool, when: { unclassified: true }, then: escalate }
  - { id: fewer_than_three_legs, when: { trifecta_legs: 0 }, then: allow }
```

Reading: an out-of-scope action is refused first; an external action carrying
untrusted content out of a session that has seen private data is the
exfiltration and is refused; any other third leg goes to a human; an unknown
tool goes to a human; everything else — at most two legs — is allowed.

**Integrity** (`policies/integrity.yaml`) is `dataflow` plus one rule ahead of
`rule_of_two`:

```yaml
  - { id: untrusted_then_external, when: { effect: external, session_untrusted: true }, then: escalate }
```

Once a session has read untrusted content, every external action is put to a
human — including the two-leg integrity attacks (book a hotel, invite a user)
that the trifecta's confidentiality rule permits. RESULTS.md measures what it
costs.

**Strict** removes `tainted_egress` (it would be redundant: `rule_of_two` is
now a `deny`) and denies unclassified tools.

**Forbid one tool outright, regardless of legs:**

```yaml
rules:
  - { id: never_delete, when: { tool: "fs.delete*" }, then: deny }
  # ... then the default rules
```

**Ask a human whenever a detector is confident, even with one leg:**

```yaml
rules:
  - { id: flagged, when: { detector_above: { promptguard: 0.95 } }, then: escalate }
```

**Scope an egress to a recipient domain:**

```yaml
tools:
  "mail.send": { effect: external, scope: ["@example.com", "@.corp.example.com"] }
```

## Runtime state in `trilock.yaml` that shapes decisions

These live in the runtime config, not the policy, but they change what a
decision can know:

```yaml
sinks:                       # taint that persists on what the agent writes (default on)
  enabled: true
  path: .trilock/sinks.json
  max_entries: 5000
  ttl_hours: 168
sessions:                    # session state that survives a reconnect (default off)
  durable: false
  ttl_hours: 24
  path: .trilock/sessions
```

`sinks` records the hashed identifiers of every allowed call whose arguments
carried taint and re-attaches that taint to any later call naming one of them.
`sessions.durable` resumes a stdio session's legs and fingerprints for the same
OS user and config within the TTL. Both store hashes and labels only. See
`docs/threat-model.md`, "Provenance that outlives a session".

## Errors

Every rejection names the field and says what to do. `tests/unit/test_policy_model.py`
holds 21 malformed policies and the message each must produce.
