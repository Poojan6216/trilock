"""Scope checking: where an external action is allowed to act.

A scope check that can be defeated by ``../`` is worse than no scope check,
because it produces a policy file that *looks* like a control. So this module
is deliberately paranoid, and its tests are a list of the ways people get it
wrong.

Three kinds of scope, inferred from the pattern or stated explicitly with a
``path:``/``host:``/``email:`` prefix:

* **path**  — a glob over the filesystem. Matched against a *resolved* absolute
  path, so ``..``, symlinks, percent-encoding and Unicode-confusable components
  cannot walk out of it.
* **host**  — a hostname allowlist for URLs. Matched against the parsed
  hostname, so userinfo (``https://allowed.com@evil.com``), fragments
  (``https://evil.com#@allowed.com``) and ports cannot fake membership, and a
  suffix match requires a real label boundary so ``allowed.com.evil.com`` is
  not inside ``allowed.com``.
* **email** — a recipient-domain allowlist, matched on the domain after the
  last ``@``.

Unlike the decision function, this module *may* touch the filesystem: symlinks
cannot be resolved without it. It is therefore called from the guard, before
the snapshot is frozen, and its single boolean output is what `decide` sees —
so `decide` stays pure (Hard Rule 4).

**Known limit, stated rather than papered over:** a URL is checked as written.
Trilock does not follow redirects, so an allowlisted host that redirects to an
attacker's is out of scope for this check. Phase 6 attacks exactly that.
"""

from __future__ import annotations

import os
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import unquote, urlsplit

from trilock import log
from trilock.policy.model import ToolClass
from trilock.taint.normalize import HOMOGLYPHS
from trilock.taint.propagate import walk_arguments

_log = log.get("policy.scope")

SAFE_URL_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
"""Schemes a host scope can meaningfully constrain.

Anything else — ``file:``, ``data:``, ``gopher:``, ``javascript:`` — either has
no host to check or reaches a resource the allowlist was never about, so it is
refused rather than waved through for lack of a hostname.
"""

_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s<>\"']+")
_BARE_SCHEME = re.compile(r"(?:data|javascript|file|blob):[^\s<>\"']+", re.IGNORECASE)
# Emails are found per whitespace-split token with an anchored match, never by
# scanning the whole text with an unbounded leading class: that shape is O(n^2)
# on a long run with no `@` (see the ReDoS note in taint/propagate.py).
_EMAIL_TOKEN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_TOKEN_SPLIT = re.compile(r"[\s\"'`<>()\[\]{}|,;]+")
_PATH_LIKE = re.compile(r"^[^\s]*(?:/|\\)[^\s]*$|^\.{1,2}$|^~[/\\]")
"""A value that is a path *in its entirety*.

NUL bytes are matched rather than excluded: an argument carrying one is a
truncation attack, and declining to classify it would mean declining to check
it, which is a bypass rather than a non-match. `normalise_path` refuses it.
"""


class ScopeKind(StrEnum):
    PATH = "path"
    HOST = "host"
    EMAIL = "email"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    kind: ScopeKind
    pattern: str


@dataclass(frozen=True, slots=True)
class ScopeViolation:
    """One argument that falls outside every scope of its kind."""

    path: str
    value: str
    kind: ScopeKind
    reason: str

    def to_json(self) -> dict[str, str]:
        # The value is included because the human approving or reading this
        # needs to see *where* the call was pointed. It is an argument the
        # agent chose, not private content the session ingested.
        return {
            "path": self.path,
            "value": self.value[:200],
            "kind": self.kind.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ScopeResult:
    violations: tuple[ScopeViolation, ...] = ()
    checked: int = 0

    @property
    def violated(self) -> bool:
        return bool(self.violations)

    def to_json(self) -> dict[str, object]:
        return {
            "violated": self.violated,
            "checked": self.checked,
            "violations": [v.to_json() for v in self.violations],
        }


def parse_scope(pattern: str) -> ScopeRule:
    """Classify a scope pattern, honouring an explicit prefix."""
    for kind in ScopeKind:
        prefix = f"{kind.value}:"
        if pattern.startswith(prefix):
            return ScopeRule(kind=kind, pattern=pattern[len(prefix) :])
    if pattern.startswith("@"):
        return ScopeRule(kind=ScopeKind.EMAIL, pattern=pattern[1:])
    if "/" in pattern or pattern.startswith((".", "~")) or "\\" in pattern:
        return ScopeRule(kind=ScopeKind.PATH, pattern=pattern)
    return ScopeRule(kind=ScopeKind.HOST, pattern=pattern)


# -- path --------------------------------------------------------------------


def normalise_path(value: str, root: Path) -> Path | None:
    """Resolve `value` to an absolute real path, or None if it is not a path.

    Every trick that turns a path into a different path is undone first:
    percent-encoding, Unicode compatibility forms and confusable characters,
    backslash separators, ``..`` segments, and finally symlinks. Symlinks are
    resolved on the *existing* prefix of the path, because the target of a
    write usually does not exist yet.
    """
    if "\x00" in value:
        return None
    decoded = unquote(value)
    decoded = unicodedata.normalize("NFKC", decoded)
    decoded = "".join(HOMOGLYPHS.get(c, c) for c in decoded)
    decoded = decoded.replace("\\", "/")
    if not decoded:
        return None
    candidate = Path(decoded).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    # Lexical collapse first, so `..` cannot escape even where nothing exists.
    collapsed = Path(posixpath.normpath(candidate.as_posix()))
    # Then resolve symlinks on the longest existing prefix.
    existing = collapsed
    tail: list[str] = []
    while not existing.exists() and existing != existing.parent:
        tail.append(existing.name)
        existing = existing.parent
    try:
        real = Path(os.path.realpath(existing))
    except OSError:  # pragma: no cover - unreadable path
        real = existing
    for part in reversed(tail):
        real = real / part
    return Path(posixpath.normpath(real.as_posix()))


def _path_in_scope(value: str, patterns: list[str], root: Path) -> tuple[bool, str]:
    resolved = normalise_path(value, root)
    if resolved is None:
        return False, "the path contains a NUL byte or is empty"
    for pattern in patterns:
        base = normalise_path(pattern.split("*", 1)[0] or ".", root)
        if base is None:
            continue
        if "*" in pattern:
            # A glob is anchored at its own non-glob prefix: matching the
            # pattern alone would let `/etc/passwd` satisfy `**` in a scope
            # rooted at ./workspace.
            if not _is_within(resolved, base):
                continue
            resolved_pattern = normalise_path(pattern.replace("*", "\x01"), root)
            if resolved_pattern is None:
                continue
            if fnmatchcase(resolved.as_posix(), resolved_pattern.as_posix().replace("\x01", "*")):
                return True, ""
        elif _is_within(resolved, base) or resolved == base:
            return True, ""
    return False, f"resolves to {resolved.as_posix()}, which is outside every declared scope"


def _is_within(candidate: Path, root: Path) -> bool:
    """True when `candidate` is `root` or below it, on resolved absolute paths."""
    return candidate == root or PurePosixPath(candidate.as_posix()).is_relative_to(
        PurePosixPath(root.as_posix())
    )


# -- host --------------------------------------------------------------------


def normalise_host(host: str) -> str | None:
    """Lower-case and IDNA-encode a hostname to its true identity.

    Homoglyphs are deliberately **not** folded here. Folding
    ``api.\u0430llowed.com`` (Cyrillic a) to ``api.allowed.com`` would make a
    spoofed host *match* an allowlist it has nothing to do with — DNS resolves
    the two to different machines, and the attacker owns one of them. Punycode
    is the real identity, so the comparison happens there and a confusable host
    simply fails to match.

    (`normalize.py` folds homoglyphs in the opposite direction and for the
    opposite reason: there the goal is to show a human what text is pretending
    to be. Here the goal is to decide what a name actually *is*.)
    """
    if not host:
        return None
    folded = unicodedata.normalize("NFKC", host).strip(".").lower()
    try:
        return folded.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return folded


def has_confusables(host: str) -> bool:
    """Whether a hostname mixes scripts in a way only a spoof does."""
    return any(c in HOMOGLYPHS for c in unicodedata.normalize("NFKC", host))


def host_matches(host: str, pattern: str) -> bool:
    """Exact host, or a subdomain of a pattern written with a leading dot or ``*.``.

    The label boundary is the whole point: ``allowed.com.evil.com`` ends with
    ``allowed.com`` as a string and must not match it as a domain.
    """
    if has_confusables(host):
        return False  # a mixed-script name is a spoof, never a match
    normalised = normalise_host(host)
    target = normalise_host(pattern.removeprefix("*."))
    if normalised is None or target is None:
        return False
    if pattern.startswith((".", "*.")):
        return normalised == target or normalised.endswith(f".{target}")
    return normalised == target


def _url_in_scope(value: str, patterns: list[str]) -> tuple[bool, str]:
    parts = urlsplit(value)
    if parts.scheme.lower() not in SAFE_URL_SCHEMES:
        return (
            False,
            f"scheme {parts.scheme or '<none>'!r} is not one a host allowlist can constrain",
        )
    try:
        host = parts.hostname
    except ValueError:
        return False, "the URL has a malformed authority"
    if not host:
        return False, "the URL has no host"
    if has_confusables(host):
        return False, f"host {host!r} mixes scripts; a confusable hostname is a spoof"
    if any(host_matches(host, p) for p in patterns):
        return True, ""
    return False, f"host {normalise_host(host)!r} is not in the allowlist"


# -- email -------------------------------------------------------------------


def _email_in_scope(value: str, patterns: list[str]) -> tuple[bool, str]:
    domain = value.rpartition("@")[2]
    if not domain:
        return False, "the address has no domain"
    if has_confusables(domain):
        return False, f"recipient domain {domain!r} mixes scripts; a confusable domain is a spoof"
    if any(host_matches(domain, p) for p in patterns):
        return True, ""
    return False, f"recipient domain {normalise_host(domain)!r} is not in the allowlist"


# -- the entry point ---------------------------------------------------------


def check(
    classification: ToolClass | None, arguments: object, *, root: Path | None = None
) -> ScopeResult:
    """Check every argument against the tool's declared scopes.

    Only kinds the policy actually declares are enforced: a tool scoped to a
    path glob is not also an email allowlist. Within a declared kind the rule
    is deny-by-default — an argument of that kind that matches nothing is a
    violation.
    """
    if classification is None or not classification.scope:
        return ScopeResult()
    rules = [parse_scope(p) for p in classification.scope]
    by_kind: dict[ScopeKind, list[str]] = {}
    for rule in rules:
        by_kind.setdefault(rule.kind, []).append(rule.pattern)
    base = root if root is not None else Path.cwd()

    violations: list[ScopeViolation] = []
    checked = 0
    for path, text in walk_arguments(arguments):
        if not text:
            continue
        for value, kind in _candidates(text, set(by_kind)):
            checked += 1
            ok, reason = _dispatch(kind, value, by_kind[kind], base)
            if not ok:
                violations.append(ScopeViolation(path=path, value=value, kind=kind, reason=reason))
    if violations:
        _log.warning(
            "call falls outside its declared scope",
            extra={"violations": [v.to_json() for v in violations]},
        )
    return ScopeResult(violations=tuple(violations), checked=checked)


def _dispatch(kind: ScopeKind, value: str, patterns: list[str], root: Path) -> tuple[bool, str]:
    if kind is ScopeKind.PATH:
        return _path_in_scope(value, patterns, root)
    if kind is ScopeKind.HOST:
        return _url_in_scope(value, patterns)
    return _email_in_scope(value, patterns)


def _candidates(text: str, kinds: set[ScopeKind]) -> list[tuple[str, ScopeKind]]:
    """Which parts of one argument string each declared scope kind should check."""
    found: list[tuple[str, ScopeKind]] = []
    if ScopeKind.HOST in kinds:
        found.extend((m.group(0).rstrip(".,);"), ScopeKind.HOST) for m in _URL.finditer(text))
        # Schemes with no host still have to be refused rather than ignored.
        found.extend((m.group(0), ScopeKind.HOST) for m in _BARE_SCHEME.finditer(text))
    if ScopeKind.EMAIL in kinds:
        for raw in _TOKEN_SPLIT.split(text):
            token = raw.strip(".,:;!?")
            if "@" in token and len(token) <= 320 and _EMAIL_TOKEN.fullmatch(token):
                found.append((token, ScopeKind.EMAIL))
    if ScopeKind.PATH in kinds and _PATH_LIKE.match(text.strip()):
        # Only a value that is a path *in its entirety*. Scanning prose for
        # path-shaped substrings would refuse an email that happens to mention
        # /etc/passwd, which costs utility and buys nothing: the argument that
        # names the write target is the whole value.
        found.append((text.strip(), ScopeKind.PATH))
    return found
