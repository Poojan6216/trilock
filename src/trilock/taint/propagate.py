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

import hashlib
import re
from collections.abc import Iterable, Iterator
from typing import Final

DEFAULT_NGRAM_SIZE: Final[int] = 5
MIN_ENTROPY_TOKEN_LEN: Final[int] = 12

_WORD = re.compile(r"[0-9a-z]+", re.ASCII)

_HIGH_ENTROPY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),  # email addresses
    re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),  # URLs
    re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE),  # hex ids, hashes
    re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b"),  # base64-ish blobs
    re.compile(r"\b[A-Za-z0-9_-]{8,}(?:-[A-Za-z0-9_-]{4,}){2,}\b"),  # dashed key shapes
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


def high_entropy_tokens(text: str) -> frozenset[str]:
    """Identifier-shaped substrings worth matching exactly."""
    found: set[str] = set()
    for pattern in _HIGH_ENTROPY_PATTERNS:
        found.update(m.group(0) for m in pattern.finditer(text))
    return frozenset(t for t in found if len(t) >= MIN_ENTROPY_TOKEN_LEN)


def content_hash(text: str) -> str:
    """SHA-256 of the content, for the audit log. Never the content itself."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
