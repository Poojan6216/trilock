"""detect/perplexity.py is an experiment, not a detector.

Its arithmetic still has to be right, and it must stay out of the decision path.
"""

from __future__ import annotations

import importlib.util
import math

import pytest

from trilock.detect.perplexity import PerplexityReport, PerplexityScorer, _windows

needs_torch = pytest.mark.skipif(
    importlib.util.find_spec("torch") is None or importlib.util.find_spec("transformers") is None,
    reason="torch/transformers not installed (uv sync --extra perplexity)",
)


def test_windows_cover_the_sequence_with_overlap() -> None:
    values = list(map(float, range(10)))
    windows = list(_windows(values, window=4, stride=2))
    assert windows[0] == [0.0, 1.0, 2.0, 3.0]
    assert windows[1] == [2.0, 3.0, 4.0, 5.0]
    assert windows[-1] == [6.0, 7.0, 8.0, 9.0]
    assert list(_windows([1.0, 2.0], window=4, stride=2)) == [[1.0, 2.0]]


def test_report_max_window_falls_back_to_mean() -> None:
    report = PerplexityReport(text_chars=3, tokens=1, mean=12.5, windows=())
    assert report.max_window == 12.5
    assert report.to_json()["mean"] == 12.5


def test_it_is_not_wired_into_policy() -> None:
    """The whole point of the module: nothing in the decision path imports it."""
    from pathlib import Path

    import trilock.policy.engine as engine
    import trilock.proxy.guard as guard

    for module in (engine, guard):
        assert module.__file__ is not None
        assert "perplexity" not in Path(module.__file__).read_text(encoding="utf-8")


@needs_torch
def test_fluent_english_scores_lower_than_token_salad() -> None:
    scorer = PerplexityScorer()
    fluent = scorer.score("The retro moved to Thursday; the agenda is in the shared doc.")
    salad = scorer.score(
        "describing. -- ;) similarlyNow write oppositeley.]( Me giving**ONE please?"
    )
    assert math.isfinite(fluent.mean) and math.isfinite(salad.mean)
    assert fluent.mean < salad.mean
    assert fluent.tokens > 1 and fluent.windows
