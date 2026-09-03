"""Unit tests for the structured logger and the stdout guard."""

from __future__ import annotations

import io
import json
import sys

from trilock import log


def test_json_formatter_emits_extra_fields() -> None:
    stream = io.StringIO()
    logger = log.configure("INFO", stream=stream)
    logger.info("decided", extra={"verdict": "deny", "rule_id": "tainted_egress"})
    record = json.loads(stream.getvalue())
    assert record["msg"] == "decided"
    assert record["verdict"] == "deny"
    assert record["rule_id"] == "tainted_egress"
    assert record["level"] == "info"


def test_configure_is_idempotent() -> None:
    stream = io.StringIO()
    for _ in range(3):
        logger = log.configure("INFO", stream=stream)
    logger.info("once")
    assert len(stream.getvalue().splitlines()) == 1


def test_guard_diverts_stray_stdout_writes_to_stderr() -> None:
    stream = io.StringIO()
    log.configure("WARNING", stream=stream)
    real_stdout = sys.stdout
    with log.guard_stdout() as guard:
        print("a library helpfully printed a banner")
        assert sys.stdout is not real_stdout
        assert guard.diverted_chars > 0
    assert sys.stdout is real_stdout
    record = json.loads(stream.getvalue().splitlines()[0])
    assert "diverted" in record["msg"]
    assert "banner" in record["preview"]


def test_coerce_handles_unserialisable_values() -> None:
    stream = io.StringIO()
    logger = log.configure("INFO", stream=stream)
    logger.info(
        "shapes",
        extra={
            "s": {
                frozenset({1}),
            },
            "m": {"k": object()},
        },
    )
    record = json.loads(stream.getvalue())
    assert isinstance(record["s"], list)
    assert isinstance(record["m"]["k"], str)


def test_safe_extra_renames_reserved_logrecord_keys() -> None:
    import logging

    stream = io.StringIO()
    logger = log.configure("INFO", stream=stream)
    data = {"created": "2026", "name": "x", "filename": "f", "ok": 1}
    logger.info("record", extra=log.safe_extra(data))  # must not raise
    record = json.loads(stream.getvalue())
    assert record["created_"] == "2026" and record["name_"] == "x" and record["ok"] == 1
    with __import__("pytest").raises(KeyError):
        logging.getLogger("trilock").info("boom", extra={"created": "collides"})
