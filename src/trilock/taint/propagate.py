"""Attribution: which untrusted sources does this outbound argument derive from?

Phase 1.4 builds the full argument walker on top of these primitives. What
lives here now is the shared text machinery the ledger also needs: normalised
tokenisation, n-gram extraction, and high-entropy token extraction.

**This is imperfect and the design does not pretend otherwise.** Matching
n-grams finds verbatim and lightly-edited reuse. A model that *paraphrases*
untrusted content defeats it. That is why `dataflow` mode uses attribution only
as a utility optimisation — to avoid blocking calls that provably carry no
untrusted content — while `strict` mode ignores attribution entirely and
accounts for the trifecta at session level. Phase 5 measures the exact
security/utility cost of that choice.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from trilock.taint.labels import IDENTITY, SourceId, TaintLabel

if TYPE_CHECKING:
    from trilock.taint.store import SessionLedger

DEFAULT_NGRAM_SIZE: Final[int] = 5
MIN_ENTROPY_TOKEN_LEN: Final[int] = 12

_WORD = re.compile(r"[0-9a-z]+", re.ASCII)

_HIGH_ENTROPY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),  # email addresses
    re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),  # URLs
    re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE),  # hex ids, hashes
    re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b"),  # base64-ish blobs
    re.compile(r"\b[A-Za-z0-9_.:-]{12,}\b"),  # candidate secret shapes, filtered below
)
"""Shapes worth matching exactly rather than by n-gram.

A single email address or URL is shorter than an n-gram window but is precisely
the payload an exfiltration carries, so it gets its own exact-match path.
"""


def tokenise(text: str) -> list[str]:
    """Case-folded alphanumeric tokens. Deliberately lossy and deterministic."""
    return _WORD.findall(text.casefold())


def ngrams(text: str, n: int = DEFAULT_NGRAM_SIZE) -> Iterator[tuple[str, ...]]:
    """Every contiguous `n`-token window of `text`."""
    tokens = tokenise(text)
    if len(tokens) < n:
        if tokens:
            yield tuple(tokens)
        return
    for i in range(len(tokens) - n + 1):
        yield tuple(tokens[i : i + n])


def ngram_hash(gram: Iterable[str]) -> int:
    """A stable 64-bit hash of one n-gram.

    Storing hashes rather than the grams themselves keeps the ledger free of
    reconstructible content (Hard Rule 6) and bounds its memory. Not
    `hash()`, whose string seed is randomised per process — the ledger has to
    be reproducible across a `trilock replay`.
    """
    digest = hashlib.blake2b(" ".join(gram).encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def extract_ngrams(
    text: str, n: int = DEFAULT_NGRAM_SIZE, limit: int | None = None
) -> frozenset[int]:
    """The hashed n-gram fingerprint of `text`, capped at `limit` grams."""
    seen: set[int] = set()
    for gram in ngrams(text, n):
        seen.add(ngram_hash(gram))
        if limit is not None and len(seen) >= limit:
            break
    return frozenset(seen)


def _is_secret_shaped(token: str) -> bool:
    """Whether a long token looks like a credential or identifier, not a word.

    Requires digits *and* letters, plus a separator or mixed case. That keeps
    `hunter2-STAGING-9f31` and drops `internationalization`, which matters
    because a false positive here costs an escalation a human resolves, while
    a plain long word matching everything would cost all of `dataflow` mode's
    utility advantage over `strict`.
    """
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    if not (has_digit and has_alpha):
        return False
    has_separator = any(c in "-_.:" for c in token)
    mixed_case = token != token.lower() and token != token.upper()
    # A long unbroken alphanumeric run with digits in it is key-shaped even
    # without a separator or case change - AWS access key ids look like that.
    return has_separator or mixed_case or len(token) >= 16


def high_entropy_tokens(text: str) -> frozenset[str]:
    """Identifier-shaped substrings worth matching exactly.

    Emails, URLs and hex digests match on shape alone. Everything else has to
    look like a secret rather than like a long word.
    """
    found: set[str] = set()
    for index, pattern in enumerate(_HIGH_ENTROPY_PATTERNS):
        for match in pattern.finditer(text):
            token = match.group(0)
            if len(token) < MIN_ENTROPY_TOKEN_LEN:
                continue
            is_candidate_class = index == len(_HIGH_ENTROPY_PATTERNS) - 1
            if is_candidate_class and not _is_secret_shaped(token):
                continue
            found.add(token)
    return frozenset(found)


def content_hash(text: str) -> str:
    """SHA-256 of the content, for the audit log. Never the content itself."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -- attribution -------------------------------------------------------------
#
# Everything above is the shared text machinery. What follows walks an outbound
# tool call's arguments and asks, for each string in them, which ledger sources
# it derives from.


@dataclass(frozen=True, slots=True)
class ArgumentMatch:
    """One argument path attributed to one or more sources."""

    path: str
    """JSON path into the arguments, e.g. ``$.body`` or ``$.items[2].text``."""
    sources: frozenset[SourceId]
    evidence: str
    """How it matched: ``ngram``, ``exact-token``, or ``base64``."""
    strength: float
    """Fraction of the argument's fingerprint that matched, in [0, 1]."""

    def to_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sources": sorted(str(s) for s in self.sources),
            "evidence": self.evidence,
            "strength": round(self.strength, 4),
        }


@dataclass(frozen=True, slots=True)
class Attribution:
    """What an outbound call's arguments were shown to derive from."""

    matches: tuple[ArgumentMatch, ...] = ()
    label: TaintLabel = IDENTITY
    """Join of every matched source's label, widened when attribution is incomplete."""
    complete: bool = True
    """False when the ledger has evicted sources, so a *negative* result proves nothing."""

    @property
    def tainted_paths(self) -> tuple[str, ...]:
        return tuple(sorted({m.path for m in self.matches}))

    @property
    def sources(self) -> frozenset[SourceId]:
        return (
            frozenset().union(*(m.sources for m in self.matches)) if self.matches else frozenset()
        )

    def to_json(self) -> dict[str, object]:
        return {
            "matches": [m.to_json() for m in self.matches],
            "label": self.label.to_json(),
            "complete": self.complete,
            "tainted_paths": list(self.tainted_paths),
        }


_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

DEFAULT_MATCH_THRESHOLD: Final[float] = 0.15
"""Fraction of an argument's n-grams that must match one source to attribute it.

Low on purpose. A partial quote is still a quote, and the cost of a false
positive here is an escalation a human resolves, while the cost of a false
negative is an exfiltration. It is not zero, because a single coincidental
5-gram of common words ("please let me know if") would otherwise attribute
every argument to every source.
"""


def walk_arguments(value: object, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield every (json path, string) pair inside an argument structure."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from walk_arguments(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from walk_arguments(item, f"{path}[{index}]")


def decode_base64_blobs(text: str) -> list[str]:
    """Decode base64-looking runs to text, so encoded reuse still matches.

    Only a first layer, and deliberately so: chained or exotic encodings are an
    adaptive attack, measured in Phase 6 rather than papered over here.
    """
    decoded: list[str] = []
    for match in _BASE64_BLOB.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            continue
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if candidate.isprintable() or "\n" in candidate:
            decoded.append(candidate)
    return decoded


def attribute(
    arguments: object,
    ledger: SessionLedger,
    *,
    threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> Attribution:
    """Attribute an outbound call's arguments to the sources they derive from.

    Three matching strategies, in increasing order of how much text they need:

    * **exact tokens** — an email address, URL or key-shaped identifier lifted
      from a source. Short, high-signal, and precisely what an exfiltration
      carries.
    * **n-grams** — verbatim or lightly-edited reuse of five or more tokens.
    * **base64** — the same two, applied to decoded blobs.

    Known misses, stated plainly because `dataflow` mode's security depends on
    knowing them: a model that **paraphrases** untrusted content produces no
    shared n-grams and is not attributed; a **short** argument with fewer than
    `n` tokens and no identifier shape has nothing to match on; encodings beyond
    one layer of base64 are not unwrapped. `strict` mode exists for exactly
    these cases — it ignores attribution and accounts for the trifecta at
    session level — and Phase 5 measures what that costs in utility.
    """
    matches: list[ArgumentMatch] = []
    for path, text in walk_arguments(arguments):
        if not text:
            continue
        matches.extend(_attribute_text(path, text, ledger, threshold, "ngram"))
        for decoded in decode_base64_blobs(text):
            matches.extend(_attribute_text(path, decoded, ledger, threshold, "base64"))

    for match in matches:
        for source in match.sources:
            ledger.touch(source)

    label = TaintLabel.join_all(
        [ledger.entries[s].label for s in _matched_sources(matches) if s in ledger.entries]
    )
    if not ledger.attribution_complete:
        # Sources have been evicted, so "no match" is no longer evidence of a
        # clean argument. Fold in the floor of everything forgotten.
        label = label.join(ledger.evicted_floor)
    return Attribution(matches=tuple(matches), label=label, complete=ledger.attribution_complete)


def _matched_sources(matches: Iterable[ArgumentMatch]) -> frozenset[SourceId]:
    out: set[SourceId] = set()
    for match in matches:
        out |= match.sources
    return frozenset(out)


def _attribute_text(
    path: str, text: str, ledger: SessionLedger, threshold: float, evidence: str
) -> list[ArgumentMatch]:
    """Match one string against every ledger entry."""
    grams = extract_ngrams(text, ledger.ngram_size)
    tokens = high_entropy_tokens(text)
    found: list[ArgumentMatch] = []
    for entry in ledger:
        exact = tokens & entry.exact_tokens
        if exact:
            found.append(
                ArgumentMatch(
                    path=path,
                    sources=frozenset({entry.source}),
                    evidence="exact-token" if evidence == "ngram" else f"{evidence}+exact-token",
                    strength=1.0,
                )
            )
            continue
        if not grams or not entry.ngrams:
            continue
        overlap = grams & entry.ngrams
        strength = len(overlap) / len(grams)
        if strength >= threshold:
            found.append(
                ArgumentMatch(
                    path=path,
                    sources=frozenset({entry.source}),
                    evidence=evidence,
                    strength=strength,
                )
            )
    return found
