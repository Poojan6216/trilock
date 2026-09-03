"""Task 5.1 verification: the audit chain is tamper-evident and replayable."""

from __future__ import annotations

import json
from pathlib import Path

from trilock.audit.log import GENESIS, AuditLog, argument_shapes, snapshot_to_json, verify_chain
from trilock.audit.replay import replay, snapshot_from_json
from trilock.policy.decision import ToolCall, TrifectaState
from trilock.policy.engine import SessionSnapshot, decide
from trilock.policy.model import Effect, ToolClass, load_policy
from trilock.proxy.guard import policy_digest
from trilock.taint.labels import SourceId, TaintLabel, TrustLevel
from trilock.taint.propagate import ArgumentMatch, Attribution

POLICIES = Path(__file__).resolve().parents[2] / "policies"
SOURCE = SourceId(server="mail", tool="search", call_id="", seq=0)


def _snapshot(*, legs: int = 3, tainted: bool = True) -> SessionSnapshot:
    attribution = Attribution(
        matches=(ArgumentMatch("$.body", frozenset({SOURCE}), "ngram", 0.8),) if tainted else (),
        label=TaintLabel(trust=TrustLevel.UNTRUSTED, sources=frozenset({SOURCE}))
        if tainted
        else TaintLabel(),
        complete=True,
    )
    return SessionSnapshot(
        trifecta=TrifectaState(legs >= 1, legs >= 2, legs >= 3),
        attribution=attribution,
        classification=ToolClass(effect=Effect.EXTERNAL),
        session_label=TaintLabel(trust=TrustLevel.UNTRUSTED),
        detector_scores={"heuristics": 0.42},
    )


def _write(path: Path, policy_name: str, n: int = 6) -> AuditLog:
    policy = load_policy(POLICIES / f"{policy_name}.yaml")
    audit = AuditLog(path)
    for i in range(n):
        snap = _snapshot(legs=i % 4, tainted=bool(i % 2))
        call = ToolCall(
            tool="mail.send",
            arguments={"to": f"u{i}@x.example", "body": "secret-value-" * 3},
            call_id=f"c{i}",
        )
        audit.record_decision(
            session="stdio-process:pid-1",
            call=call,
            snapshot=snap,
            decision=decide(call, snap, policy),
            policy_mode=policy.mode.value,
            policy_hash=policy_digest(policy),
            latency_ms=1.5,
        )
    return audit


def test_the_chain_links_from_genesis(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=4)
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines[0]["prev"] == GENESIS
    assert [r["seq"] for r in lines] == [0, 1, 2, 3]
    assert verify_chain(path) == []


def test_flipping_one_byte_breaks_the_chain(tmp_path: Path) -> None:
    """The tamper test the spec requires."""
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=5)
    raw = bytearray(path.read_bytes())
    # Find a byte inside the third record's verdict and flip it.
    third_start = [i for i, b in enumerate(raw) if b == ord("\n")][1] + 1
    target = raw.index(b'"verdict":"', third_start) + len(b'"verdict":"')
    raw[target] = ord("X") if raw[target] != ord("X") else ord("Y")
    path.write_bytes(bytes(raw))
    breaks = verify_chain(path)
    assert breaks, "a flipped byte went undetected"
    assert breaks[0].line == 4  # the record *after* the altered one no longer links


def test_deleting_a_record_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=5)
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")
    assert verify_chain(path)


def test_the_chain_resumes_across_restarts(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=3)
    _write(path, "default", n=3)  # a second writer continues the chain
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["seq"] for r in lines] == [0, 1, 2, 3, 4, 5]
    assert verify_chain(path) == []


def test_replay_reproduces_every_decision(tmp_path: Path) -> None:
    for name in ("default", "strict", "monitor"):
        path = tmp_path / f"{name}.jsonl"
        _write(path, name, n=8)
        policy = load_policy(POLICIES / f"{name}.yaml")
        report = replay(path, policy, policy_hash=policy_digest(policy))
        assert report.ok, f"{name}: {report.mismatches} {report.chain_breaks}"
        assert report.decisions == 8


def test_replay_detects_a_policy_change(tmp_path: Path) -> None:
    """A log recorded under one policy does not silently 'replay' under another."""
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=8)
    strict = load_policy(POLICIES / "strict.yaml")
    report = replay(path, strict, policy_hash=policy_digest(strict))
    assert report.policy_hash_mismatches == 8
    assert not report.ok


def test_replay_detects_an_altered_verdict(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=4)
    lines = path.read_text().splitlines()
    record = json.loads(lines[3])
    record["decision"]["verdict"] = "allow" if record["decision"]["verdict"] != "allow" else "deny"
    lines[3] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    policy = load_policy(POLICIES / "default.yaml")
    report = replay(path, policy)
    assert report.chain_breaks or report.mismatches


def test_snapshot_round_trips_through_json() -> None:
    snap = _snapshot()
    again = snapshot_from_json(snapshot_to_json(snap))
    assert again.trifecta == snap.trifecta
    assert again.scope_violation == snap.scope_violation
    assert again.attribution.tainted_paths == snap.attribution.tainted_paths
    assert again.attribution.label.is_untrusted == snap.attribution.label.is_untrusted
    assert dict(again.detector_scores) == dict(snap.detector_scores)
    policy = load_policy(POLICIES / "default.yaml")
    call = ToolCall(tool="mail.send")
    assert decide(call, again, policy) == decide(call, snap, policy)


def test_argument_shapes_carry_no_values() -> None:
    shapes = argument_shapes(
        {"to": "attacker@evil.tld", "n": 3, "body": {"text": "hunter2-STAGING-9f31"}}
    )
    rendered = json.dumps(shapes)
    assert "attacker" not in rendered and "hunter2" not in rendered
    by_path = {s["path"]: s for s in shapes}
    assert by_path["$.to"]["length"] == len("attacker@evil.tld")
    assert len(by_path["$.to"]["sha256"]) == 64
    assert by_path["$.n"]["type"] == "int"
    assert by_path["$.body.text"]["type"] == "string"


def test_the_log_carries_no_argument_values(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, "default", n=3)
    text = path.read_text()
    assert "secret-value" not in text
    assert "@x.example" not in text
