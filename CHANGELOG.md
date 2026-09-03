# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Known limitations
- See README "Known limitations" and `docs/threat-model.md`. In particular:
  session identity under stateless HTTP is degraded and enforcement is refused
  there; two-leg integrity attacks are outside the confidentiality model;
  attribution loses to paraphrase and `strict` costs utility; the benchmark
  agent is an oracle, not an LLM.
