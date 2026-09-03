# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-03

Provenance that outlives the session, and the integrity policy.

### Added
- **Persistent sink taint** (`taint/sinks.py`, on by default): the hashed
  identifiers of every allowed call whose arguments carried taint are recorded,
  and any later call naming one of them inherits the taint - across sessions and
  restarts. Closes laundering through a misclassified store: 0.250 -> 0.000 in
  both modes.
- **Durable sessions** (`taint/durable.py`, opt-in `sessions: {durable: true}`):
  a stdio session's legs and fingerprints (never raw tokens) persist per OS user
  and config and resume within a TTL. Closes session splitting for same-user
  reconnects: 1.000 -> 0.000.
- **`integrity` policy** and the `session_untrusted` rule condition: escalate
  every external action after untrusted input, catching the two-leg integrity
  attacks that make up the residual AgentDojo ASR; measured as a fifth
  configuration.
- The red-team harness now models a persistent store honestly: a denied write
  leaves nothing to read back, and an exfil body must come from what the model
  actually read. The first version let a denied write be read back, which
  overstated one loss.

## [0.1.0] - 2026-09-03

First release. Everything below was built from `BUILD_SPEC.md`, phase by phase,
with each task's verification committed alongside it.

### Added
- **MCP proxy** over stdio and Streamable HTTP, serving protocol `2026-07-28` and
  `2025-11-25`, with supervised upstream reconnection, tool/prompt namespacing
  (`<server>.<tool>`), resource routing, progress and cancellation forwarding.
  Byte-faithful passthrough with no policy, proven by a 33-operation differential
  test on both revisions.
- **Tool definition pinning** (`.trilock/pins.json`, `trilock check --repin`);
  strict mode withholds *and refuses* a tool whose definition changed. Prior art:
  airlock-agent.
- **Provenance**: a taint lattice with property-tested join; a bounded per-session
  ledger whose eviction widens taint rather than narrowing it; Unicode/HTML
  invisible-text normalisation that decodes Tag-block and variation-selector
  payloads and surfaces CSS-hidden text (18-case corpus); n-gram and identifier
  attribution of outbound arguments with its misses documented.
- **Policy engine**: YAML policy validated by Pydantic; a pure, deterministic
  `decide()` (5000-example determinism property; 46 hand-reasoned scenarios);
  three modes (`strict`, `dataflow`, `monitor`); scoped capabilities for paths,
  hosts and recipient domains with 54 escape attempts refused; an unclassified
  tool is never allowed.
- **Human in the loop** over MCP's own multi-round-trip mechanism
  (`input_required` + sealed `requestState` + single-use nonce); a client that
  cannot elicit gets a deny naming `trilock approve <id>`; approval memory
  (`once`/`session`/`always`, with `always` withheld for tainted arguments);
  a spoof-resistant approval prompt.
- **Advisory detectors** under a hard per-detector timeout: deterministic
  heuristics (measured precision 0.962 / recall 0.806) and Llama Prompt Guard 2
  22M on ONNX Runtime (off by default; measured 252 ms p50 on 4 KB). Scores can
  only tighten a verdict (3000-example monotonicity property); disabling every
  detector changes no block.
- **Audit**: hash-chained JSONL of labels, shapes and hashes — never values —
  with `trilock replay` re-deriving every decision; a mandatory test seeds
  fifteen secret formats and finds none in any artefact.
- **Benchmark**: AgentDojo harness (`bench/run_bench.py`) over 949 security
  cases in four configurations with an oracle agent; `RESULTS.md` is generated.
  Adaptive red team (`bench/adaptive/`) with eight strategies and three human
  models; the losses are published.
- **Perplexity negative result** reproduced on our corpus (`bench/perplexity_experiment.py`).
- **Integrations**: `trilock init` / `trilock uninstall` wrap and byte-exactly
  restore Claude Code, Claude Desktop, Cursor, VS Code, Windsurf and Zed configs;
  `trilock check --suggest` drafts a policy from live tool listings.
- Soak test (100 concurrent sessions), chaos fixture with twelve edge cases, CI
  with a nightly ASR regression gate.

### Fixed (before release)
- Approval prompts on handshake-era sessions (`2025-11-25`, which Claude Code 2.1
  negotiates): an `ESCALATE` returned the `2026-07-28` `input_required` shape,
  which the SDK rejected, so the human was never asked (it failed closed). Such
  sessions now receive a standalone `elicitation/create` request; verified over a
  real stdio transport for approve, decline and no-elicitation clients.

### Known limitations
- See README "Known limitations" and `docs/threat-model.md`. In particular:
  session identity under stateless HTTP is degraded and enforcement is refused
  there; two-leg integrity attacks are outside the confidentiality model;
  attribution loses to paraphrase and `strict` costs utility; the benchmark
  agent is an oracle, not an LLM.
