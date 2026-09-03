"""Deterministic, zero-model injection signals.

Everything here is a string test that runs in linear time and needs no weights.
The signals are the ones that cost an attacker something to avoid: role tokens
and override phrasing are how injections are *written*; a URL with a long
opaque payload is how data *leaves*; a base64 blob is how it hides; and the
count of characters normalisation had to strip is how it was smuggled in.

The score is a capped sum of fired signal weights, so it is reproducible from
the text alone. It is advisory (Hard Rule 1) and, like every detector, it is
measured rather than trusted: `tests/unit/test_heuristics.py` reports precision
and recall over the attack and benign corpora, and does not tune to them.

ReDoS discipline (see `taint/propagate.py`): no pattern with an unbounded
leading class runs over the whole text. Signals are tested per line, and each
line is capped, so a hostile 100 MB result costs O(n) and nothing more.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from trilock.taint.propagate import _TOKEN_SPLIT, _TRIM_CHARS, _URL_RE

MAX_LINE_CHARS: Final[int] = 4000
"""A line longer than this is scanned only up to here. Prose lines are short;
a longer one is a blob, and the blob signals below catch it by shape."""

_ROLE_TOKENS: Final[tuple[str, ...]] = (
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "[INST]",
    "[/INST]",
    "<<SYS>>",
    "<</SYS>>",
    "### Instruction",
    "###Instruction",
    "### System",
    "<|endoftext|>",
    "<|eot_id|>",
    "<start_of_turn>",
)
_ROLE_LINE_PREFIXES: Final[tuple[str, ...]] = ("system:", "assistant:", "human:", "user:", "ai:")

_OVERRIDE_PHRASES: Final[tuple[str, ...]] = (
    "ignore all previous instructions",
    "ignore the previous instructions",
    "ignore prior instructions",
    "ignore the above",
    "ignore your instructions",
    "disregard all previous",
    "disregard the above",
    "disregard your instructions",
    "forget all previous",
    "forget your previous",
    "new instructions:",
    "your new instructions",
    "you are now",
    "from now on you",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "do not mention this",
    "say you are done",
    "then say you are done",
    "system override",
    "override:",
    "admin mode",
    "developer mode",
    "jailbreak",
    "act as an unrestricted",
    "forward all messages",
    "forward all emails",
    "send all",
    "exfiltrate",
    "to attacker",
    "important: forward",
    "important: send",
    "assistant: i will",
    "this is a routine approval",
)

_EMPHATIC_MARKERS: Final[tuple[str, ...]] = (
    "IMPORTANT:",
    "URGENT:",
    "SYSTEM:",
    "ATTENTION:",
    "NOTE TO AI",
    "AI ASSISTANT:",
)

_MARKDOWN_IMAGE: Final[re.Pattern[str]] = re.compile(
    r"!\[[^\]\n]{0,200}\]\((https?://[^)\s]{1,2000})\)"
)
_LONG_OPAQUE_QUERY: Final[re.Pattern[str]] = re.compile(r"[?&=/#][A-Za-z0-9+/_=%-]{32,}")
_BASE64_TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")


@dataclass(frozen=True, slots=True)
class Signal:
    """One heuristic that fired, with the weight it contributed and why."""

    name: str
    weight: float
    evidence: str

    def to_json(self) -> dict[str, object]:
        return {"name": self.name, "weight": self.weight, "evidence": self.evidence[:120]}


@dataclass(frozen=True, slots=True)
class HeuristicReport:
    score: float
    signals: tuple[Signal, ...]

    def to_json(self) -> dict[str, object]:
        return {"score": self.score, "signals": [s.to_json() for s in self.signals]}


def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        yield line[:MAX_LINE_CHARS]


def analyse(
    text: str,
    *,
    tool_names: Iterable[str] = (),
    normalisation_removed: int = 0,
) -> HeuristicReport:
    """Score one text. Pure and linear."""
    signals: list[Signal] = []
    lowered_lines = [(line, line.casefold()) for line in _lines(text)]

    # -- role tokens and override phrasing: how injections are written --------
    for line, _low in lowered_lines:
        stripped = line.lstrip()
        if any(tok in line for tok in _ROLE_TOKENS) or any(
            stripped.lower().startswith(p) for p in _ROLE_LINE_PREFIXES
        ):
            signals.append(Signal("role_token", 0.5, stripped[:80]))
            break
    for _line, low in lowered_lines:
        hit = next((p for p in _OVERRIDE_PHRASES if p in low), None)
        if hit:
            signals.append(Signal("override_phrase", 0.45, hit))
            break
    for line, _ in lowered_lines:
        hit = next((m for m in _EMPHATIC_MARKERS if m in line), None)
        if hit:
            signals.append(Signal("emphatic_marker", 0.15, hit))
            break

    # -- tool-name mentions: content that names the tools it wants used -------
    names = {n for n in tool_names if n}
    if names:
        low_text = text.casefold()
        mentioned = sorted(
            n
            for n in names
            if (("." in n and n.casefold() in low_text) or _bare_mentioned(n, low_text))
        )
        if mentioned:
            signals.append(Signal("tool_mention", 0.3, ", ".join(mentioned[:5])))

    # -- exfiltration vectors: how data leaves ----------------------------------
    for line, _ in lowered_lines:
        image = _MARKDOWN_IMAGE.search(line)
        if image and (len(image.group(1)) > 80 or _LONG_OPAQUE_QUERY.search(image.group(1))):
            signals.append(Signal("markdown_image_exfil", 0.6, image.group(1)[:80]))
            break
    else:
        for url in _URL_RE.findall(text[: 64 * MAX_LINE_CHARS]):
            if _LONG_OPAQUE_QUERY.search(url) and len(url) > 120:
                signals.append(Signal("url_with_payload", 0.4, url[:80]))
                break

    # -- blobs: how it hides ----------------------------------------------------
    for raw in _TOKEN_SPLIT.split(text):
        token = raw.strip(_TRIM_CHARS)
        if len(token) >= 64 and _BASE64_TOKEN.fullmatch(token[:4096]):
            signals.append(Signal("base64_blob", 0.3, f"{len(token)} chars"))
            break

    # -- how it was smuggled in -------------------------------------------------
    if normalisation_removed >= 20:
        signals.append(Signal("hidden_text", 0.6, f"{normalisation_removed} chars stripped"))
    elif normalisation_removed >= 1:
        signals.append(Signal("hidden_text", 0.3, f"{normalisation_removed} chars stripped"))

    score = min(1.0, round(sum(s.weight for s in signals), 4))
    return HeuristicReport(score=score, signals=tuple(signals))


def _bare_mentioned(name: str, low_text: str) -> bool:
    """A bare tool name counts only if it is distinctive enough to mean something."""
    bare = name.rpartition(".")[2].casefold()
    if len(bare) < 6 or bare in {
        "search",
        "read",
        "write",
        "list",
        "get",
        "fetch",
        "create",
        "update",
        "delete",
    }:
        return False
    return re.search(rf"(?<![a-z0-9_]){re.escape(bare)}(?![a-z0-9_])", low_text) is not None


class HeuristicDetector:
    """The `Detector` protocol over `analyse`."""

    name = "heuristics"

    def __init__(self, tool_names: Iterable[str] = ()) -> None:
        self.tool_names = tuple(tool_names)

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        return [analyse(t, tool_names=self.tool_names).score for t in texts]
