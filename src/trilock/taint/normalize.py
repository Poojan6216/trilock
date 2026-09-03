"""Defuse invisible and deceptive text in inbound tool results.

This is the **only** place Trilock modifies content, and Hard Rule 5 permits it
only here and only for inbound results. Every modification is counted, typed
and logged with a diff.

What it does, and why each one is narrower than it first looks:

* **Unicode Tags** (U+E0000–U+E007F) carry a full shadow ASCII alphabet that
  most renderers draw as nothing. Stripped, and *decoded*, because the decoded
  text is the actual instruction and a human approving a call needs to read it.
* **Variation-selector smuggling** encodes arbitrary bytes in VS1–VS16 and the
  Variation Selectors Supplement. Decoded the same way — but VS16 after an
  emoji base is ordinary presentation, so a lone selector on a pictographic
  base is left alone.
* **Zero-width characters.** ZWSP and BOM are stripped unconditionally. ZWJ and
  ZWNJ are *not*: they are load-bearing in emoji sequences and in Indic and
  Perso-Arabic scripts, and stripping them corrupts legitimate text. They are
  removed only where neither neighbour is a script that uses them — which is
  removed only where neither neighbour is a script that uses them - which is
* **Bidi overrides** reorder display without changing logical order, so they
  fool a human reviewer rather than the model. Stripped, and the
  visually-rendered reading is surfaced so the human sees what the *renderer*
  would have shown.
* **Homoglyphs** — Cyrillic and Greek letters standing in for Latin ones —
  are folded, and the fold is reported.
* **CSS/HTML invisibility** — `display:none`, `opacity:0`, `font-size:0`,
  white-on-white, and HTML comments — is unwrapped so hidden text becomes
  ordinary visible text.

Note what it does *not* do: decide anything. Normalisation produces content and
a report. It never blocks, and its findings are advisory input to the detectors
(Hard Rule 1). Trilock's guarantee does not rest on this module — it rests on
the policy engine — but a human approving a call deserves to read what was
really there.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Final

from trilock import log
from trilock.taint.propagate import content_hash

_log = log.get("taint.normalize")

# -- character classes -------------------------------------------------------

TAG_BLOCK: Final[range] = range(0xE0000, 0xE0080)
"""Unicode Tags. U+E0020–U+E007E mirror printable ASCII; U+E007F is the terminator."""

VS_SUPPLEMENT: Final[range] = range(0xE0100, 0xE01F0)
VS_BASIC: Final[range] = range(0xFE00, 0xFE10)

ZERO_WIDTH_ALWAYS: Final[frozenset[str]] = frozenset(
    {
        "\u200b",  # ZERO WIDTH SPACE
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
        "\u2060",  # WORD JOINER
        "\u00ad",  # SOFT HYPHEN
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR
    }
)

ZERO_WIDTH_CONTEXTUAL: Final[frozenset[str]] = frozenset({"\u200c", "\u200d"})
"""ZWNJ and ZWJ: load-bearing in real scripts, so only stripped out of context."""

BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    {
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
    }
)

_JOINING_SCRIPT_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x0600, 0x06FF),  # Arabic
    (0x0700, 0x074F),  # Syriac
    (0x0750, 0x077F),  # Arabic Supplement
    (0x0900, 0x0DFF),  # Devanagari through Sinhala
    (0x0E00, 0x0E7F),  # Thai
    (0x1000, 0x109F),  # Myanmar
    (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
    (0xFE70, 0xFEFF),  # Arabic Presentation Forms-B
)

# ruff: noqa: RUF001, RUF002
# This module's *subject* is confusable and ambiguous characters, so the
# homoglyph table must contain the real Cyrillic and Greek codepoints in order
# to fold them, and the prose necessarily names them.
HOMOGLYPHS: Final[dict[str, str]] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "с": "c",
    "е": "e",
    "һ": "h",
    "і": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "о": "o",
    "р": "p",
    "ѕ": "s",
    "т": "t",
    "у": "y",
    "х": "x",
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "І": "I",
    "Ј": "J",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Ѕ": "S",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    # Greek
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
    "κ": "k",
    "τ": "t",
    "υ": "u",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Fullwidth
    "／": "/",
    "：": ":",
    "．": ".",
    "＠": "@",
}


# -- report types ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Modification:
    """One class of change made to the content."""

    kind: str
    count: int
    detail: str = ""

    def to_json(self) -> dict[str, object]:
        return {"kind": self.kind, "count": self.count, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Normalized:
    """The defused content plus an account of what was done to it."""

    text: str
    original_hash: str
    normalized_hash: str
    modifications: tuple[Modification, ...] = ()
    surfaced: tuple[str, ...] = ()
    """Text that was hidden and is now readable. Shown to the human, never
    spliced into the content as if Trilock had said it."""

    @property
    def changed(self) -> bool:
        return self.original_hash != self.normalized_hash

    @property
    def removed_chars(self) -> int:
        """Total characters removed. A zero-cost detector signal (task 4.2)."""
        return sum(m.count for m in self.modifications if m.kind != "homoglyph")

    def kinds(self) -> frozenset[str]:
        return frozenset(m.kind for m in self.modifications)

    def to_json(self) -> dict[str, object]:
        return {
            "original_hash": self.original_hash,
            "normalized_hash": self.normalized_hash,
            "changed": self.changed,
            "modifications": [m.to_json() for m in self.modifications],
            "surfaced_count": len(self.surfaced),
        }


@dataclass
class _Report:
    mods: list[Modification] = field(default_factory=list)
    surfaced: list[str] = field(default_factory=list)

    def add(self, kind: str, count: int, detail: str = "") -> None:
        if count:
            self.mods.append(Modification(kind=kind, count=count, detail=detail))

    def surface(self, text: str) -> None:
        cleaned = text.strip()
        if cleaned:
            self.surfaced.append(cleaned)


# -- helpers -----------------------------------------------------------------


def _uses_joiners(char: str) -> bool:
    """True if `char` belongs to a script where ZWJ/ZWNJ are meaningful."""
    cp = ord(char)
    if unicodedata.category(char) == "So" or cp >= 0x1F000:
        return True  # pictographic: ZWJ builds emoji sequences
    return any(lo <= cp <= hi for lo, hi in _JOINING_SCRIPT_RANGES)


def _decode_tags(text: str) -> tuple[str, str, int]:
    """Strip Unicode Tag characters, returning (clean, decoded, count)."""
    kept: list[str] = []
    decoded: list[str] = []
    for char in text:
        cp = ord(char)
        if cp in TAG_BLOCK:
            if 0xE0020 <= cp <= 0xE007E:
                decoded.append(chr(cp - 0xE0000))
            continue
        kept.append(char)
    return "".join(kept), "".join(decoded), len(text) - len(kept)


def _decode_variation_selectors(text: str) -> tuple[str, str, int]:
    """Strip selector-smuggled bytes, keeping legitimate emoji presentation.

    The published technique encodes byte *b* as U+FE00+b for b < 16 and
    U+E0100+(b-16) otherwise. A single selector directly after a pictographic
    base is ordinary presentation and is preserved; a run is a payload.
    """
    kept: list[str] = []
    payload: list[int] = []
    removed = 0
    i = 0
    while i < len(text):
        cp = ord(text[i])
        if cp in VS_BASIC or cp in VS_SUPPLEMENT:
            run_end = i
            while run_end < len(text) and (
                ord(text[run_end]) in VS_BASIC or ord(text[run_end]) in VS_SUPPLEMENT
            ):
                run_end += 1
            run = text[i:run_end]
            previous = kept[-1] if kept else ""
            if len(run) == 1 and previous and _uses_joiners(previous):
                kept.append(run)  # emoji presentation selector: legitimate
            else:
                for char in run:
                    c = ord(char)
                    payload.append(c - 0xFE00 if c in VS_BASIC else c - 0xE0100 + 16)
                removed += len(run)
            i = run_end
            continue
        kept.append(text[i])
        i += 1
    decoded = bytes(b for b in payload if 0 <= b < 256).decode("utf-8", errors="replace")
    return "".join(kept), decoded, removed


def _strip_zero_width(text: str) -> tuple[str, int]:
    """Remove zero-width carriers, preserving joiners that real scripts need."""
    kept: list[str] = []
    removed = 0
    for index, char in enumerate(text):
        if char in ZERO_WIDTH_ALWAYS:
            removed += 1
            continue
        if char in ZERO_WIDTH_CONTEXTUAL:
            before = kept[-1] if kept else ""
            after = text[index + 1] if index + 1 < len(text) else ""
            if (before and _uses_joiners(before)) or (after and _uses_joiners(after)):
                kept.append(char)  # load-bearing joiner
            else:
                removed += 1
            continue
        kept.append(char)
    return "".join(kept), removed


def _strip_bidi(text: str) -> tuple[str, str, int]:
    """Remove bidi controls and render what a display would have shown."""
    if not any(c in BIDI_CONTROLS for c in text):
        return text, "", 0
    rendered_parts: list[str] = []
    buffer: list[str] = []
    reversing = False
    kept: list[str] = []
    removed = 0
    for char in text:
        if char in BIDI_CONTROLS:
            removed += 1
            if char in ("\u202e", "\u2067"):  # right-to-left override / isolate
                rendered_parts.append("".join(buffer))
                buffer = []
                reversing = True
            elif char in ("\u202c", "\u2069"):  # pop / pop isolate
                rendered_parts.append("".join(reversed(buffer)) if reversing else "".join(buffer))
                buffer = []
                reversing = False
            continue
        buffer.append(char)
        kept.append(char)
    rendered_parts.append("".join(reversed(buffer)) if reversing else "".join(buffer))
    return "".join(kept), "".join(rendered_parts), removed


def _fold_homoglyphs(text: str) -> tuple[str, int]:
    """Map confusable Cyrillic/Greek/fullwidth letters onto their Latin twins.

    Only applied to runs that are *mixed* — a genuinely Cyrillic word is left
    alone, because folding it would corrupt legitimate text for no benefit.
    """
    folded: list[str] = []
    count = 0
    for word in re.split(r"(\s+)", text):
        confusable = sum(1 for c in word if c in HOMOGLYPHS)
        latin = sum(1 for c in word if "a" <= c.lower() <= "z")
        if confusable and latin:  # mixed script: the deceptive case
            folded.append("".join(HOMOGLYPHS.get(c, c) for c in word))
            count += confusable
        else:
            folded.append(word)
    return "".join(folded), count


class _HiddenTextExtractor(HTMLParser):
    """Unwrap text that HTML or CSS renders invisible.

    Deliberately a small parser over `html.parser` rather than a dependency:
    the goal is to find text a human would not see, not to model CSS.
    """

    HIDDEN_STYLE = re.compile(
        r"display\s*:\s*none"
        r"|visibility\s*:\s*hidden"
        r"|opacity\s*:\s*0(?:\.0+)?(?!\d)"
        r"|font-size\s*:\s*0(?:\.0+)?\s*(?:px|pt|em|rem|%)?(?!\d)"
        r"|color\s*:\s*(?:#f{3}\b|#f{6}\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)"
        r"|text-indent\s*:\s*-\s*\d{4,}"
        r"|(?:left|top)\s*:\s*-\s*\d{4,}",
        re.IGNORECASE,
    )
    ALWAYS_HIDDEN_TAGS = frozenset({"script", "style", "template", "head", "title"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden: list[str] = []
        self.visible: list[str] = []
        self._depth = 0
        self._suppress = 0

    def _is_hidden(self, attrs: list[tuple[str, str | None]]) -> bool:
        for name, value in attrs:
            if value is None:
                continue
            if name.lower() in {"style", "class"} and self.HIDDEN_STYLE.search(value):
                return True
            if name.lower() == "hidden":
                return True
            if name.lower() == "aria-hidden" and value.lower() == "true":
                return True
        return False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.ALWAYS_HIDDEN_TAGS:
            self._suppress += 1
            return
        if self._depth or self._is_hidden(attrs):
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self.ALWAYS_HIDDEN_TAGS and self._suppress:
            self._suppress -= 1
            return
        if self._depth:
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._suppress or self._depth:
            # script/style/template content is invisible to a reader and fully
            # visible to a model, which is the exact shape worth surfacing —
            # so it is collected as hidden text, never discarded.
            self.hidden.append(data)
            return
        self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        # An HTML comment is invisible to a reader and fully visible to a model.
        self.hidden.append(data)


def _unwrap_html(text: str) -> tuple[str, list[str], int]:
    """Surface HTML/CSS-hidden text. Returns (text, hidden runs, count)."""
    if "<" not in text:
        return text, [], 0
    parser = _HiddenTextExtractor()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:  # malformed markup is data, not a crash
        _log.debug("html parse failed; leaving content as-is", extra={"error": str(exc)})
        return text, [], 0
    hidden = [h.strip() for h in parser.hidden if h.strip()]
    if not hidden:
        return text, [], 0
    # The hidden runs are already present in the raw text the model reads; what
    # changes is that they are now separated out, so a human sees them and the
    # detectors score them as ordinary text.
    return text, hidden, len(hidden)


# -- the entry point ---------------------------------------------------------


def normalize(content: str) -> Normalized:
    """Defuse `content` and report every change.

    Applied to inbound tool results before anything else — provenance,
    detectors, the ledger — sees them.
    """
    original = content
    report = _Report()

    text, tag_payload, tag_count = _decode_tags(content)
    report.add("unicode-tag", tag_count, "Unicode Tags block (U+E0000-U+E007F)")
    if tag_payload.strip():
        report.surface(tag_payload)

    text, vs_payload, vs_count = _decode_variation_selectors(text)
    report.add("variation-selector", vs_count, "selector-smuggled bytes")
    if vs_payload.strip():
        report.surface(vs_payload)

    text, zw_count = _strip_zero_width(text)
    report.add("zero-width", zw_count, "zero-width carriers outside joining scripts")

    text, bidi_render, bidi_count = _strip_bidi(text)
    report.add("bidi", bidi_count, "bidirectional overrides and isolates")
    if bidi_render.strip() and bidi_render != text:
        report.surface(bidi_render)

    text, homoglyph_count = _fold_homoglyphs(text)
    report.add("homoglyph", homoglyph_count, "mixed-script confusables folded to Latin")

    text, hidden_runs, hidden_count = _unwrap_html(text)
    report.add("html-hidden", hidden_count, "text hidden by HTML or CSS")
    for run in hidden_runs:
        report.surface(run)

    result = Normalized(
        text=text,
        original_hash=content_hash(original),
        normalized_hash=content_hash(text),
        modifications=tuple(report.mods),
        surfaced=tuple(report.surfaced),
    )
    if result.modifications:
        _log.info(
            "inbound content normalised",
            extra={
                "original_hash": result.original_hash[:16],
                "normalized_hash": result.normalized_hash[:16],
                "modifications": [m.to_json() for m in result.modifications],
                "surfaced": len(result.surfaced),
                "diff_chars": len(original) - len(text),
            },
        )
    return result
