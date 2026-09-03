"""Baseline: the package imports, and its two version strings agree.

`__version__` and the version in `pyproject.toml` are written by hand in two
places, so they can drift: a release bumps one and the wheel then reports the
other. Pinning the literal here was worse, because every release broke this
test and the fix was to retype the number, which is exactly the check being
asked for. Compare the sources instead.
"""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import trilock

REPO = Path(__file__).resolve().parents[2]


def test_version_is_a_release_number() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+([ab]\d+|rc\d+)?", trilock.__version__)


def test_module_and_installed_metadata_agree() -> None:
    assert trilock.__version__ == importlib.metadata.version("mcp-trilock")


def test_module_and_pyproject_agree() -> None:
    """Skipped when the tests run against an installed wheel, not the repo."""
    pyproject = REPO / "pyproject.toml"
    if not pyproject.is_file():
        return
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert trilock.__version__ == declared
