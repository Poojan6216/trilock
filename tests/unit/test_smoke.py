"""Baseline: the package imports and reports a version."""

from __future__ import annotations

import trilock


def test_version() -> None:
    assert trilock.__version__ == "0.1.0"
