"""Hard Rule 7: with no policy, an agent must not be able to tell Trilock is there.

This module is the *executable definition* of that rule rather than a separate
code path. Trilock has one pipeline; "passthrough" is what that pipeline does
when the policy is empty. Two things live here:

* `is_passthrough` — whether a configuration has any policy at all. When it
  does not, the proxy forwards and never decides.
* `canonicalise` — the normal form a response takes for the differential test.
  It removes exactly the two differences a proxy is *allowed* to introduce
  (namespacing and routing `_meta`), so anything else that differs is a
  fidelity bug, and the test that compares direct against proxied responses is
  checking a property this module states rather than one it re-invents.
"""

from __future__ import annotations

from typing import Any, Final

from trilock.config import TrilockConfig
from trilock.proxy.router import NAMESPACE_SEP

PEER_IDENTITY_META_KEY: Final[str] = "io.modelcontextprotocol/serverInfo"
"""The 2026-07-28 stamp naming the peer that answered.

This is the one `_meta` entry whose *value* legitimately differs through the
proxy: the client's peer really is Trilock, and stamping the upstream's name
here would be an impersonation — a client that decides anything on peer
identity would be deciding on a lie. `canonicalise` therefore normalises the
value to a marker rather than deleting the key, so the differential test still
compares the stamp's presence and shape.
"""

PEER_MARKER: Final[str] = "<peer>"

ROUTING_META_KEYS: Final[frozenset[str]] = frozenset(
    {
        "io.trilock/server",
        "io.trilock/rule_id",
        "io.trilock/decision",
        "io.trilock/taint",
    }
)
"""`_meta` keys Trilock is permitted to add. Anything else must survive untouched."""


def is_passthrough(config: TrilockConfig) -> bool:
    """True when no policy is configured, so no decision can be taken."""
    return config.policy is None


def strip_namespace(name: str, server: str) -> str:
    """Undo `<server>.` namespacing on a tool or prompt name."""
    prefix = f"{server}{NAMESPACE_SEP}"
    return name[len(prefix) :] if name.startswith(prefix) else name


def canonicalise(value: Any, server: str) -> Any:
    """The normal form in which a direct and a proxied response must be equal.

    Removes the two permitted differences and nothing else:

    1. `name` fields are de-namespaced.
    2. Trilock's own `_meta` keys are dropped, and the peer-identity stamp's
       value is replaced by a marker. Every other `_meta` key and value stays,
       because dropping one would hide a fidelity bug rather than fix it.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key == "_meta" and isinstance(item, dict):
                remaining = {
                    k: (PEER_MARKER if k == PEER_IDENTITY_META_KEY else v)
                    for k, v in item.items()
                    if k not in ROUTING_META_KEYS
                }
                if remaining:
                    out[key] = canonicalise(remaining, server)
                continue
            if key == "name" and isinstance(item, str):
                out[key] = strip_namespace(item, server)
                continue
            out[key] = canonicalise(item, server)
        return out
    if isinstance(value, list):
        return [canonicalise(item, server) for item in value]
    return value
