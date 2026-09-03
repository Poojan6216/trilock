"""Task 1.4 verification: table-driven attribution over 25+ cases.

The table includes the cases attribution is *expected to miss*. Recording them
as expected misses rather than leaving them out is the point: `dataflow` mode's
security depends on knowing exactly where its evidence runs out, and `strict`
mode is the answer to every row marked False.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest

from trilock.taint.labels import TaintLabel, TrustLevel, new_call_id
from trilock.taint.propagate import (
    attribute,
    decode_base64_blobs,
    high_entropy_tokens,
    ngram_hash,
    ngrams,
    tokenise,
    walk_arguments,
)
from trilock.taint.store import SessionKey, SessionLedger

UNTRUSTED = TaintLabel(trust=TrustLevel.UNTRUSTED)

SOURCE_TEXT = (
    "Re: Q3 credentials rotation. The staging database password is "
    "hunter2-STAGING-9f31 and the admin portal password is Troubadour3. "
    "Do not share these outside the team. Contact security@internal.example.com "
    "or see https://wiki.internal.example.com/runbooks/rotation for the full "
    "procedure and the escalation path if anything looks wrong."
)


def ledger_with_source(text: str = SOURCE_TEXT) -> SessionLedger:
    led = SessionLedger(key=SessionKey(kind="mcp-session", value="s"))
    led.record("mail", "search", new_call_id(), text, UNTRUSTED)
    return led


@dataclass(frozen=True)
class Case:
    name: str
    argument: object
    attributed: bool
    note: str = ""


CASES: list[Case] = [
    # -- verbatim and near-verbatim reuse ---------------------------------
    Case("verbatim whole", SOURCE_TEXT, True),
    Case("verbatim sentence", "The staging database password is hunter2-STAGING-9f31", True),
    Case("partial quote", "Do not share these outside the team. Contact", True),
    Case("quote with prefix", f"The user said: {SOURCE_TEXT[:120]}", True),
    Case("quote with suffix", f"{SOURCE_TEXT[:120]} -- end of quote", True),
    Case("reformatted list", "- Do not share these outside the team\n- Contact security", True),
    Case("case changed", SOURCE_TEXT[:100].upper(), True),
    Case("whitespace mangled", "  ".join(SOURCE_TEXT[:120].split()), True),
    Case("punctuation stripped", SOURCE_TEXT[:120].replace(".", "").replace(",", ""), True),
    Case("markdown wrapped", f"> {SOURCE_TEXT[:120]}", True),
    # -- high-entropy identifiers ----------------------------------------
    Case("email extracted", "security@internal.example.com", True, "short but identifier-shaped"),
    Case("url extracted", "https://wiki.internal.example.com/runbooks/rotation", True),
    Case("key-shaped token", "hunter2-STAGING-9f31", True),
    Case("email inside prose", "Please cc security@internal.example.com on the reply.", True),
    Case(
        "url as markdown image", "![x](https://wiki.internal.example.com/runbooks/rotation)", True
    ),
    # -- encoded --------------------------------------------------------
    Case(
        "base64 of untrusted content",
        base64.b64encode(SOURCE_TEXT[:150].encode()).decode(),
        True,
    ),
    Case(
        "base64 embedded in prose",
        f"payload={base64.b64encode(SOURCE_TEXT[:150].encode()).decode()}",
        True,
    ),
    # -- nested structures ------------------------------------------------
    Case("nested dict", {"body": SOURCE_TEXT[:150]}, True),
    Case("nested list", {"items": ["ok", {"text": SOURCE_TEXT[:150]}]}, True),
    Case("deeply nested", {"a": {"b": {"c": [SOURCE_TEXT[:150]]}}}, True),
    # -- genuinely clean --------------------------------------------------
    Case("unrelated prose", "Please schedule the retro for Thursday afternoon.", False),
    Case("empty string", "", False),
    Case("empty dict", {}, False),
    Case("numbers only", {"count": 3, "ratio": 0.5}, False),
    Case("unrelated email", "someone-else@other.example.org", False),
    Case("common phrase", "let me know if you have any questions", False, "must not over-match"),
    # -- known misses, documented rather than hidden ----------------------
    Case(
        "paraphrase",
        "The team rotated its credentials and asked that they stay internal.",
        False,
        "KNOWN MISS: no shared n-grams. strict mode covers this.",
    ),
    Case(
        "short non-identifier fragment",
        "rotation",
        False,
        "KNOWN MISS: fewer tokens than the n-gram window, no identifier shape.",
    ),
    Case(
        "double-encoded base64",
        base64.b64encode(base64.b64encode(SOURCE_TEXT[:150].encode())).decode(),
        False,
        "KNOWN MISS: only one layer of base64 is unwrapped. Phase 6 measures this.",
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_attribution_table(case: Case) -> None:
    result = attribute(case.argument, ledger_with_source())
    got = bool(result.matches)
    assert got is case.attributed, (
        f"{case.name}: expected attributed={case.attributed}, got {got}. "
        f"{case.note}\nmatches={result.to_json()['matches']}"
    )
    if case.attributed:
        assert result.label.is_untrusted
        assert result.tainted_paths


def test_the_table_covers_the_required_shapes() -> None:
    assert len(CASES) >= 25
    assert sum(1 for c in CASES if "KNOWN MISS" in c.note) >= 3


def test_strict_mode_catches_what_attribution_misses() -> None:
    """Every known miss is still caught by session-level accounting."""
    led = ledger_with_source()
    for case in (c for c in CASES if "KNOWN MISS" in c.note):
        result = attribute(case.argument, led)
        assert not result.matches
        # strict mode does not consult attribution at all: the session itself
        # holds untrusted content, and that is what it decides on.
        assert led.session_label().is_untrusted


def test_json_paths_identify_the_offending_argument() -> None:
    result = attribute({"to": "bob@example.com", "body": SOURCE_TEXT[:150]}, ledger_with_source())
    assert result.tainted_paths == ("$.body",)

    nested = attribute({"items": [{"text": SOURCE_TEXT[:150]}]}, ledger_with_source())
    assert nested.tainted_paths == ("$.items[0].text",)


def test_attribution_is_incomplete_after_eviction_and_widens() -> None:
    led = SessionLedger(key=SessionKey(kind="mcp-session", value="s"), max_sources=2)
    led.record("mail", "search", new_call_id(), SOURCE_TEXT, UNTRUSTED)
    for i in range(5):
        led.record("web", "fetch", new_call_id(), f"benign page {i}", TaintLabel())

    result = attribute("Please schedule the retro for Thursday.", led)
    assert not result.matches
    assert not result.complete
    # No match, but the forgotten source's label still applies.
    assert result.label.is_untrusted, "eviction must not turn an unmatched argument clean"


def test_matching_touches_sources_so_they_survive_eviction() -> None:
    led = SessionLedger(key=SessionKey(kind="mcp-session", value="s"), max_sources=3)
    led.record("mail", "search", new_call_id(), SOURCE_TEXT, UNTRUSTED)
    for i in range(2):
        led.record("web", "fetch", new_call_id(), f"page {i}", TaintLabel())
    attribute(SOURCE_TEXT[:150], led)  # re-reference the mail source
    led.record("web", "fetch", new_call_id(), "one more", TaintLabel())
    assert led.untrusted_sources(), "a source in active use was evicted before an idle one"


# -- primitives --------------------------------------------------------------


def test_tokenise_and_ngrams() -> None:
    assert tokenise("Hello, World! 42") == ["hello", "world", "42"]
    assert list(ngrams("a b c", 5)) == [("a", "b", "c")]  # shorter than the window
    assert len(list(ngrams("a b c d e f", 5))) == 2
    assert ngram_hash(("a", "b")) == ngram_hash(("a", "b"))
    assert ngram_hash(("a", "b")) != ngram_hash(("b", "a"))


def test_high_entropy_tokens() -> None:
    found = high_entropy_tokens("mail me at a@b.example.com or see https://x.example.com/y")
    assert "a@b.example.com" in found
    assert any(t.startswith("https://") for t in found)
    assert high_entropy_tokens("just some ordinary words here") == frozenset()


def test_walk_arguments_paths() -> None:
    paths = dict(walk_arguments({"a": "x", "b": [{"c": "y"}], "n": 1}))
    assert paths == {"$.a": "x", "$.b[0].c": "y"}


def test_decode_base64_blobs_ignores_noise() -> None:
    encoded = base64.b64encode(b"hello world this is a longer message").decode()
    assert "hello world this is a longer message" in decode_base64_blobs(encoded)
    assert decode_base64_blobs("no base64 here at all") == []


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("hunter2-STAGING-9f31", True),
        ("sk_live_FAKE_FIXTURE_KEY", True),
        ("AKIAIOSFODNN7EXAMPLE", True),
        ("2026-09-02T00:00:00", True),
        ("internationalization", False),  # long, but a word
        ("responsibilities", False),
        ("aaaaaaaaaaaaaaaaaaaa", True),  # 20 chars of hex: an identifier shape, not prose
        ("short-1a", False),  # under the length floor
    ],
)
def test_secret_shaped_heuristic(token: str, expected: bool) -> None:
    """A long ordinary word must not become a universal attribution key."""
    assert (token in high_entropy_tokens(f"value is {token} here")) is expected


def test_attribution_does_not_overmatch_across_unrelated_sources() -> None:
    """Two sources, one argument: only the source it came from is attributed."""
    led = SessionLedger(key=SessionKey(kind="mcp-session", value="s"))
    a = led.record("mail", "search", new_call_id(), SOURCE_TEXT, UNTRUSTED)
    led.record(
        "web",
        "fetch",
        new_call_id(),
        "Completely different content about railway timetables and platform changes.",
        UNTRUSTED,
    )
    result = attribute(SOURCE_TEXT[:150], led)
    assert result.sources == frozenset({a.source})
