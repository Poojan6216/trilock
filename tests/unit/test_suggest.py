"""Task 7.4: the draft classifier proposes sensible starting points and never applies them."""

from __future__ import annotations

import mcp_types as types
import yaml

from trilock.policy.model import parse_policy
from trilock.policy.suggest import render_draft, suggest


def tool(name: str, description: str = "") -> types.Tool:
    return types.Tool(name=name, description=description, inputSchema={"type": "object"})


def test_agentdojo_shapes_are_drafted_sensibly() -> None:
    cases = {
        ("send_money", "Sends a transaction to the recipient."): ("external", None),
        ("get_webpage", "Returns the content of the webpage at a given URL."): (
            "none",
            "untrusted",
        ),
        ("read_file", "Reads the contents of the file at the given path."): ("none", "untrusted"),
        ("update_password", "Update the user password."): ("external", None),
        ("get_balance", "Get the balance of the account."): ("none", "trusted"),
        ("invite_user_to_slack", "Invites a user to the Slack workspace."): ("external", None),
        ("get_current_day", "Returns the current day in ISO format."): ("none", "trusted"),
    }
    for (name, desc), (effect, reads) in cases.items():
        s = suggest(tool(name, desc), "s")
        assert s.effect == effect, f"{name}: effect {s.effect} != {effect} ({s.reason})"
        assert s.reads == reads, f"{name}: reads {s.reads} != {reads} ({s.reason})"


def test_sensitivity_follows_the_nouns() -> None:
    assert (
        suggest(tool("update_password", "Update the user password."), "s").sensitivity
        == "sensitive"
    )
    assert (
        suggest(tool("get_balance", "Get the balance of the account."), "s").sensitivity
        == "sensitive"
    )
    assert suggest(tool("get_weather", "Current weather for a city."), "s").sensitivity == "public"


def test_unknown_shapes_are_drafted_conservatively_and_flagged() -> None:
    s = suggest(tool("frobnicate", "Does the thing."), "s")
    assert s.reads == "untrusted" and s.sensitivity == "sensitive"
    assert not s.confident
    assert "REVIEW" in s.to_yaml_line()


def test_the_draft_is_a_loadable_policy() -> None:
    drafts = [
        suggest(tool("send_money", "Sends a transaction."), "banking"),
        suggest(tool("read_file", "Reads a file."), "banking"),
        suggest(tool("frobnicate", ""), "banking"),
    ]
    text = render_draft(drafts)
    policy = parse_policy(yaml.safe_load(text))
    assert set(policy.tools) == {"banking.send_money", "banking.read_file", "banking.frobnicate"}
    assert policy.classify("banking.send_money").is_external
    assert policy.unclassified_verdict.value != "allow"
    assert "DRAFT" in text.splitlines()[0]


def test_every_line_says_why() -> None:
    s = suggest(
        tool("send_email", "Sends an email with the given body to the given address."), "ws"
    )
    assert s.reason and "send" in s.reason
    assert s.to_yaml_line().endswith(s.reason)


def test_drafting_is_deterministic() -> None:
    a = suggest(tool("search_emails", "Searches for emails in the inbox."), "ws")
    assert a == suggest(tool("search_emails", "Searches for emails in the inbox."), "ws")
