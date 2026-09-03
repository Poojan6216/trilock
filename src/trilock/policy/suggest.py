"""Draft a policy classification from a tool's name and description.

`trilock check --suggest` connects to the configured upstreams and proposes a
starting `tools:` table. The proposal is **a draft a human edits, never
applied**: a wrong classification is a hole the author made, and this module's
whole job is to make the first draft cheap enough that people write one at all.

The heuristics are deliberately transparent - word lists, not a model - so a
reader can see *why* a tool was drafted as external, and so the draft is the
same every time. Every entry carries the reason it was chosen, as a YAML
comment, and unknown shapes are drafted as the conservative option: untrusted,
sensitive, and flagged for review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

import mcp_types as types


def _wordset(text: str) -> frozenset[str]:
    return frozenset(text.split())


EXTERNAL_VERBS: Final[frozenset[str]] = _wordset(
    """send post put patch write create make add insert append update edit modify rename move
    copy delete remove drop destroy truncate purge cancel reschedule reserve book order pay
    transfer schedule invite share publish deploy push commit merge upload export set enable
    disable execute run exec start stop restart kill submit approve reject notify email message
    tweet call dial forward reply checkout reset revert rebase stash tag init clone pull"""
)
READ_VERBS: Final[frozenset[str]] = _wordset(
    """get read list search find fetch query lookup show describe view browse load open
    retrieve download check inspect scan count summarize summarise log diff status branch
    blame grep cat head tail stat info tree ls dir"""
)
UNTRUSTED_NOUNS: Final[frozenset[str]] = _wordset(
    """web page webpage url http html site website fetch browse scrape search email emails mail
    inbox message messages chat channel slack discord comment comments review reviews post posts
    feed rss news ticket tickets issue issues pr pull document documents doc docs file files
    attachment attachments calendar event events transaction transactions statement invoice bill
    notification notifications sms unread received incoming internet"""
)
SENSITIVE_NOUNS: Final[frozenset[str]] = _wordset(
    """password passwords credential credentials secret secrets token tokens key keys api_key
    apikey ssh private personal user users account accounts balance iban card contact contacts
    address addresses phone salary payroll medical health record records customer customers
    employee employees email emails mail inbox message messages drive file files document
    documents calendar transaction transactions payment payments profile identity id"""
)
PUBLIC_HINTS: Final[frozenset[str]] = _wordset(
    """weather time date clock version ping health status public docs documentation
    wikipedia dictionary translate currency exchange rate stock quote"""
)

_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class Suggestion:
    tool: str
    reads: str | None
    sensitivity: str
    effect: str
    reason: str
    confident: bool

    def to_yaml_line(self) -> str:
        fields = []
        if self.reads:
            fields.append(f"reads: {self.reads}")
        fields.append(f"sensitivity: {self.sensitivity}")
        if self.effect == "external":
            fields.append("effect: external")
        flag = "" if self.confident else "  # REVIEW"
        return f'  "{self.tool}": {{ {", ".join(fields)} }}{flag}  # {self.reason}'


def _words(*texts: str) -> list[str]:
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        # split camelCase and snake_case, then lowercase tokens
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        out.extend(w for w in _SPLIT.split(spaced.lower()) if w)
    return out


def suggest(tool: types.Tool, server: str) -> Suggestion:
    """Draft a classification for one tool."""
    qualified = f"{server}.{tool.name}"
    name_words = _words(tool.name)
    desc_words = _words((tool.description or "")[:400])
    all_words = set(name_words) | set(desc_words)
    first_verb = next((w for w in name_words if w in EXTERNAL_VERBS | READ_VERBS), None)
    reasons: list[str] = []

    # effect: a name led by an external verb, or a description that says it acts.
    external = False
    if first_verb in EXTERNAL_VERBS:
        external = True
        reasons.append(f"name verb '{first_verb}' acts on the world")
    elif any(w in EXTERNAL_VERBS for w in name_words) and first_verb not in READ_VERBS:
        external = True
        reasons.append("name contains an acting verb")
    elif any(
        w in ("sends", "creates", "deletes", "updates", "writes", "posts", "modifies")
        for w in desc_words
    ):
        external = True
        reasons.append("description says it changes state")

    # reads: anything that returns content from a source someone else writes.
    # An egress is not an ingress: a tool drafted external gets no `reads`, even
    # when its description names the thing it acts on ("sends a transaction").
    # A tool that both acts and returns attacker-readable content is rare, and
    # the conservative default for it is still the external classification: the
    # session leg it would set is the one policy already refuses to complete.
    untrusted_hits = sorted(all_words & UNTRUSTED_NOUNS)
    reads: str | None
    if external:
        reads = None
    elif untrusted_hits:
        reads = "untrusted"
        reasons.append(f"returns content from {', '.join(untrusted_hits[:3])}")
    elif first_verb in READ_VERBS or any(w in READ_VERBS for w in name_words):
        reads = "trusted"
        reasons.append("reads local/system data with no external source named")
    else:
        reads = "untrusted"
        reasons.append("no read verb recognised; drafted untrusted to be safe")

    # sensitivity
    sensitive_hits = sorted(all_words & SENSITIVE_NOUNS)
    public_hits = sorted(all_words & PUBLIC_HINTS)
    if sensitive_hits:
        sensitivity = "sensitive"
        reasons.append(f"touches {', '.join(sensitive_hits[:3])}")
    elif public_hits and not external:
        sensitivity = "public"
        reasons.append(f"public data ({', '.join(public_hits[:2])})")
    elif external:
        sensitivity = "public"
    else:
        sensitivity = "sensitive"
        reasons.append("unknown data; drafted sensitive to be safe")

    confident = bool(first_verb) and (
        bool(untrusted_hits) or bool(sensitive_hits) or bool(public_hits) or external
    )
    return Suggestion(
        tool=qualified,
        reads=reads,
        sensitivity=sensitivity,
        effect="external" if external else "none",
        reason="; ".join(reasons) or "no signal",
        confident=confident,
    )


def render_draft(suggestions: list[Suggestion], mode: str = "dataflow") -> str:
    """A complete draft policy document, ready to save and edit."""
    lines = [
        "# DRAFT policy proposed by `trilock check --suggest`. Review every line before use.",
        "# Lines marked REVIEW had weak signal and were drafted conservatively.",
        "# An egress mistakenly drafted as a read is a hole; a read drafted as an egress",
        "# only costs a prompt. When unsure, keep the conservative choice.",
        "version: 1",
        f"mode: {mode}",
        "unclassified: escalate",
        "tools:",
        *(s.to_yaml_line() for s in sorted(suggestions, key=lambda s: s.tool)),
        "rules:",
        "  - { id: scope_violation, when: { scope_violation: true }, then: deny }",
        "  - id: tainted_egress",
        "    when: { effect: external, args_tainted_by: untrusted, session_touched: sensitive }",
        "    then: deny",
        "  - { id: rule_of_two, when: { trifecta_legs: 3 }, then: escalate }",
        "  - { id: unclassified_tool, when: { unclassified: true }, then: escalate }",
        "  - { id: fewer_than_three_legs, when: { trifecta_legs: 0 }, then: allow }",
    ]
    return "\n".join(lines) + "\n"
