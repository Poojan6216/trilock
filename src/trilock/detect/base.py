"""The detector protocol, and the budget every detector runs under.

Detectors are **advisory**. Hard Rule 1 says a score may contribute to a DENY or
raise an ALLOW to an ESCALATE, and may never be the reason a call is permitted;
the engine enforces that in `_apply_detectors`. This module enforces the other
half, Hard Rule 2: a detector that hangs, crashes, or will not load is skipped
and logged. It never blocks the pipeline, and its absence never changes what
policy would have decided on its own.

Every detector runs concurrently with the others under one hard timeout. On
timeout or error its score is ``None`` — not 0.0, which would read as "checked
and clean", and not 1.0, which would let a broken classifier deny things.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

import anyio

from trilock import log

_log = log.get("detect")

DEFAULT_TIMEOUT_MS: Final[int] = 150


@runtime_checkable
class Detector(Protocol):
    """Something that scores text for injection-likelihood in [0, 1]."""

    name: str

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        """One score per text, or ``None`` where the detector could not say."""
        ...


@dataclass(frozen=True, slots=True)
class DetectorOutcome:
    """What one detector produced for one batch, and how it went."""

    name: str
    scores: tuple[float | None, ...]
    elapsed_ms: float
    timed_out: bool = False
    error: str | None = None

    @property
    def score(self) -> float | None:
        """The batch's worst case: the maximum over texts that were scored."""
        present = [s for s in self.scores if s is not None]
        return max(present) if present else None

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.error is None

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "score": self.score,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "timed_out": self.timed_out,
            "error": self.error,
        }


async def run_detectors(
    detectors: Sequence[Detector],
    texts: Sequence[str],
    *,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> tuple[DetectorOutcome, ...]:
    """Run every detector on `texts` concurrently, each under the same deadline.

    The deadline is per detector and hard: a detector that has not answered by
    then is recorded as timed out with ``None`` scores and the pipeline moves
    on. The wall-clock cost of this call is therefore bounded by the timeout,
    not by the slowest detector.
    """
    if not detectors or not texts:
        return ()
    outcomes: dict[str, DetectorOutcome] = {}

    async def one(detector: Detector) -> None:
        started = time.perf_counter()
        scores: Sequence[float | None] | None = None
        error: str | None = None
        with anyio.move_on_after(timeout_ms / 1000) as scope:
            try:
                scores = await detector.score(texts)
            except anyio.get_cancelled_exc_class():
                raise
            except Exception as exc:  # a broken detector is skipped, never fatal
                error = f"{type(exc).__name__}: {exc}"
        elapsed = (time.perf_counter() - started) * 1000
        timed_out = scope.cancelled_caught
        if timed_out:
            _log.warning(
                "detector timed out; score skipped",
                extra={"detector": detector.name, "timeout_ms": timeout_ms, "elapsed_ms": elapsed},
            )
        elif error is not None:
            _log.warning(
                "detector failed; score skipped", extra={"detector": detector.name, "error": error}
            )
        if scores is None or len(scores) != len(texts):
            scores = [None] * len(texts)
        outcomes[detector.name] = DetectorOutcome(
            name=detector.name,
            scores=tuple(_clamp(s) for s in scores),
            elapsed_ms=elapsed,
            timed_out=timed_out,
            error=error,
        )

    async with anyio.create_task_group() as tg:
        for detector in detectors:
            tg.start_soon(one, detector)
    return tuple(outcomes[d.name] for d in detectors if d.name in outcomes)


def _clamp(score: float | None) -> float | None:
    if score is None:
        return None
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value != value:  # NaN: the detector said nothing usable
        return None
    return min(1.0, max(0.0, value))


def merge_scores(outcomes: Sequence[DetectorOutcome]) -> dict[str, float]:
    """The per-detector scores that actually exist, for the taint label.

    Detectors that timed out or failed are simply absent. An absent score never
    satisfies a rule threshold (see `engine._detector_above`), so a broken
    detector cannot deny anything, and it cannot allow anything because no
    score ever allows anything.
    """
    return {o.name: o.score for o in outcomes if o.score is not None}
