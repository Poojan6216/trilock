"""Trilock — an MCP proxy that makes the lethal trifecta structurally impossible.

Trilock does not detect prompt injection. It assumes injection succeeds and bounds
what a hijacked agent can do, by tracking provenance on ingress and refusing any
tool call that would complete the trifecta of
{untrusted input, sensitive access, external action} within one session.
"""

from __future__ import annotations

__version__ = "0.2.1"
__all__ = ["__version__"]
