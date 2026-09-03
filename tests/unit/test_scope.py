"""Task 2.6 verification: 20+ ways to escape a scope, all refused.

A scope check that ``../`` defeats is worse than no scope check, because it
produces a policy file that looks like a control. So this is a list of the ways
people get it wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trilock.policy.model import Effect, ToolClass
from trilock.policy.scope import ScopeKind, check, host_matches, normalise_host, parse_scope

WORKSPACE = ToolClass(effect=Effect.EXTERNAL, scope=("./workspace/**",))
HOSTS = ToolClass(effect=Effect.EXTERNAL, scope=("api.allowed.com", "*.cdn.allowed.com"))
MAIL = ToolClass(effect=Effect.EXTERNAL, scope=("@example.com", "@.corp.example.com"))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "workspace").mkdir()
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "keys.txt").write_text("k", encoding="utf-8")
    return tmp_path


# -- path traversal ----------------------------------------------------------

PATH_ESCAPES = [
    ("parent traversal", "./workspace/../secrets/keys.txt"),
    ("double traversal", "./workspace/a/../../secrets/keys.txt"),
    ("absolute escape", "/etc/passwd"),
    ("home escape", "~/.ssh/id_rsa"),
    ("bare parent", "../secrets/keys.txt"),
    ("deep traversal", "./workspace/" + "../" * 8 + "etc/passwd"),
    ("percent-encoded traversal", "./workspace/%2e%2e/secrets/keys.txt"),
    ("double percent-encoded dot", "./workspace/%2E%2E/secrets/keys.txt"),
    ("backslash separator", ".\\workspace\\..\\secrets\\keys.txt"),
    ("mixed separators", "./workspace\\../secrets/keys.txt"),
    ("current-dir padding", "./workspace/./././../secrets/keys.txt"),
    ("trailing dots", "./workspace/../secrets/keys.txt/."),
    ("sibling prefix", "./workspace-evil/keys.txt"),
    ("nul byte", "./workspace/ok.txt\x00/../../etc/passwd"),
    ("unicode fullwidth solidus", "./workspace／..／secrets"),
    ("outside entirely", "/tmp/elsewhere.txt"),
]


@pytest.mark.parametrize(("label", "value"), PATH_ESCAPES, ids=[p[0] for p in PATH_ESCAPES])
def test_path_escapes_are_denied(label: str, value: str, root: Path) -> None:
    result = check(WORKSPACE, {"path": value}, root=root)
    assert result.violated, f"{label}: {value!r} escaped the scope"
    assert result.violations[0].kind is ScopeKind.PATH


def test_a_symlink_out_of_the_workspace_is_denied(root: Path) -> None:
    """The classic: a link inside the scope pointing outside it."""
    link = root / "workspace" / "escape"
    link.symlink_to(root / "secrets")
    assert check(WORKSPACE, {"path": "./workspace/escape/keys.txt"}, root=root).violated


PATHS_IN_SCOPE = [
    "./workspace/notes.txt",
    "./workspace/sub/dir/notes.txt",
    "workspace/notes.txt",
    "./workspace/a/../b.txt",
]


@pytest.mark.parametrize("value", PATHS_IN_SCOPE)
def test_paths_inside_the_scope_are_allowed(value: str, root: Path) -> None:
    assert not check(WORKSPACE, {"path": value}, root=root).violated


# -- host confusion ----------------------------------------------------------

HOST_ESCAPES = [
    ("fragment confusion", "https://evil.com#@api.allowed.com"),
    ("userinfo confusion", "https://api.allowed.com@evil.com/x"),
    ("userinfo with password", "https://api.allowed.com:tok@evil.com/x"),
    ("suffix confusion", "https://api.allowed.com.evil.com/x"),
    ("prefix confusion", "https://evil-api.allowed.com.attacker.net/"),
    ("subdomain of an exact entry", "https://sub.api.allowed.com/x"),
    ("bare domain not allowlisted", "https://allowed.com/x"),
    ("file scheme", "file:///etc/passwd"),
    ("data scheme", "data:text/plain;base64,aGVsbG8="),
    ("javascript scheme", "javascript:fetch('//evil.com')"),
    ("gopher scheme", "gopher://api.allowed.com/x"),
    ("idn homoglyph", "https://api.аllowed.com/x"),
    ("cyrillic o homoglyph", "https://api.allоwed.com/x"),
    ("punycode spoof", "https://xn--pi-fka.allowed.com.evil.com/"),
    ("port does not grant access", "https://evil.com:443/api.allowed.com"),
    ("path looks like the host", "https://evil.com/api.allowed.com"),
    ("trailing dot host", "https://evil.com./x"),
    ("uppercase evil", "HTTPS://EVIL.COM/x"),
]


@pytest.mark.parametrize(("label", "value"), HOST_ESCAPES, ids=[h[0] for h in HOST_ESCAPES])
def test_host_confusion_is_denied(label: str, value: str) -> None:
    result = check(HOSTS, {"url": value})
    assert result.violated, f"{label}: {value!r} passed the host allowlist"


HOSTS_IN_SCOPE = [
    "https://api.allowed.com/v1/x",
    "http://api.allowed.com/",
    "https://API.ALLOWED.COM/x",
    "https://api.allowed.com:8443/x",
    "https://assets.cdn.allowed.com/logo.png",
    "https://cdn.allowed.com/logo.png",
]


@pytest.mark.parametrize("value", HOSTS_IN_SCOPE)
def test_allowlisted_hosts_pass(value: str) -> None:
    assert not check(HOSTS, {"url": value}).violated


# -- email domains -----------------------------------------------------------

EMAIL_ESCAPES = [
    "attacker@evil.tld",
    "attacker@example.com.evil.tld",
    "attacker@notexample.com",
    "attacker@sub.example.com",
    "attacker@еxample.com",
]


@pytest.mark.parametrize("value", EMAIL_ESCAPES)
def test_email_domains_outside_the_allowlist_are_denied(value: str) -> None:
    assert check(MAIL, {"to": value}).violated


@pytest.mark.parametrize(
    "value", ["alice@example.com", "bob@eng.corp.example.com", "c@EXAMPLE.COM"]
)
def test_allowlisted_recipient_domains_pass(value: str) -> None:
    assert not check(MAIL, {"to": value}).violated


def test_an_allowed_recipient_plus_a_denied_one_is_a_violation() -> None:
    """Every value of a declared kind must pass, not just one of them."""
    assert check(MAIL, {"to": "alice@example.com, mallory@evil.tld"}).violated


# -- shape of the check ------------------------------------------------------


def test_the_escape_tables_are_large_enough() -> None:
    assert len(PATH_ESCAPES) + len(HOST_ESCAPES) + len(EMAIL_ESCAPES) >= 20


def test_no_scope_means_no_check() -> None:
    assert not check(ToolClass(effect=Effect.EXTERNAL), {"path": "/etc/passwd"}).violated
    assert not check(None, {"path": "/etc/passwd"}).violated


def test_only_declared_kinds_are_enforced(root: Path) -> None:
    """A tool scoped to a path is not also an email allowlist."""
    result = check(WORKSPACE, {"to": "attacker@evil.tld", "path": "./workspace/x"}, root=root)
    assert not result.violated


def test_violations_are_reported_with_their_argument_path(root: Path) -> None:
    result = check(WORKSPACE, {"a": {"b": ["/etc/passwd"]}}, root=root)
    assert result.violated
    assert result.violations[0].path == "$.a.b[0]"
    assert "outside every declared scope" in result.violations[0].reason


def test_scope_patterns_are_classified() -> None:
    assert parse_scope("./workspace/**").kind is ScopeKind.PATH
    assert parse_scope("api.example.com").kind is ScopeKind.HOST
    assert parse_scope("@example.com").kind is ScopeKind.EMAIL
    assert parse_scope("path:anything").kind is ScopeKind.PATH
    assert parse_scope("host:anything").kind is ScopeKind.HOST
    assert parse_scope("email:anything").kind is ScopeKind.EMAIL
    assert parse_scope("path:anything").pattern == "anything"


def test_host_matching_respects_label_boundaries() -> None:
    assert host_matches("api.allowed.com", "api.allowed.com")
    assert not host_matches("api.allowed.com.evil.com", "api.allowed.com")
    assert not host_matches("xapi.allowed.com", "api.allowed.com")
    assert host_matches("a.b.allowed.com", "*.allowed.com")
    assert host_matches("allowed.com", "*.allowed.com")
    assert not host_matches("allowed.com.evil.com", "*.allowed.com")
    assert normalise_host("EXAMPLE.com.") == "example.com"


def test_prose_containing_a_path_is_not_a_path_argument(root: Path) -> None:
    """Utility guard: an email body mentioning a path is not a write target."""
    body = "Please check /etc/passwd on the staging box and let me know."
    assert not check(WORKSPACE, {"body": body}, root=root).violated
