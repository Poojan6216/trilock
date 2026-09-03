# Contributing

Thanks for looking. Two kinds of contribution are most valuable here, in this
order: **an attack that beats it**, and a fix with a before/after number.

## Setup

```bash
git clone https://github.com/Poojan6216/trilock.git && cd trilock
uv sync                      # Python 3.12+, dev + detector + benchmark groups
uv run pytest -q             # ~5 min; model-backed tests skip without the ONNX model
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src/
```

## Rules the code keeps, and pull requests must too

1. `decide()` is pure and deterministic. Same policy, same session state, same
   call, same verdict. No clocks, no randomness, no network.
2. Detectors are advisory. Nothing in `decide()` may branch on a detector score.
3. Secret values are never logged, hashed only. If a test needs a secret-shaped
   string, store it split (see `tests/fixtures/secrets/seeded.json`).
4. No telemetry. Trilock phones nobody.
5. Numbers in docs come from a run, with the results file committed under
   `bench/results/`. Never type a number by hand.

## Adding an attack

Put a strategy in `bench/adaptive/strategies.py`, run
`uv run python -m bench.adaptive.attacker`, and commit the JSON it writes. If
your attack wins, say so in the pull request title. Published losses are the
point of the red team, not an embarrassment.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `bench:`). One change per
commit, tests in the same commit as the code they cover.
