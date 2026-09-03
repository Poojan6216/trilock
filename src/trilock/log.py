"""Structured JSON logging for Trilock.

Every log record is one JSON object on **stderr**. Nothing in this package may
write to stdout: under the stdio MCP transport, stdout *is* the protocol
channel, and a stray print corrupts the JSON-RPC framing (Hard Rule 7).

The stdout guard below makes that failure mode loud instead of silent.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from typing import IO, Any, Final, TextIO, cast

_RESERVED: Final[frozenset[str]] = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime", "taskName"}

LOGGER_NAME: Final[str] = "trilock"


class JsonFormatter(logging.Formatter):
    """Render a `LogRecord` as a single-line JSON object.

    Extra keyword fields passed via ``logger.info("...", extra={...})`` are
    merged into the object, so call sites stay greppable and machine-readable
    at once.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED:
                payload[key] = _coerce(value)
        if record.exc_info is not None:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def _coerce(value: object) -> Any:
    """Make `value` JSON-safe without losing its shape."""
    if isinstance(value, str | int | float | bool | type(None)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _coerce(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_coerce(v) for v in value]
    return str(value)


def configure(level: str | int | None = None, *, stream: IO[str] | None = None) -> logging.Logger:
    """Install the JSON handler on the ``trilock`` logger and return it.

    Idempotent: repeated calls replace the handler rather than stacking them,
    which matters because the CLI and the test-suite both configure logging.
    """
    resolved = level if level is not None else os.environ.get("TRILOCK_LOG_LEVEL", "INFO")
    logger = logging.getLogger(LOGGER_NAME)
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(resolved if isinstance(resolved, int) else resolved.upper())
    # Never let records escape to the root logger, whose default handler
    # (lastResort) writes to stderr unformatted — or, if an embedding app has
    # configured one, possibly to stdout.
    logger.propagate = False
    return logger


def safe_extra(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Rename any key that would collide with a LogRecord attribute.

    `logging` raises KeyError for `extra` keys such as `created`, `name`,
    `module` or `filename`. Call this when the extra comes from data rather
    than from literals in the call site.
    """
    return {(f"{k}_" if k in _RESERVED else k): v for k, v in fields.items()}


def get(name: str = "") -> logging.Logger:
    """Return the ``trilock`` logger, or a child of it."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


class StdoutGuard:
    """A stdout replacement that routes stray writes to stderr and logs them.

    Installed by ``trilock serve`` on the stdio transport *after* the MCP SDK
    has captured the real stdout. Any library that prints — a model loader's
    progress bar, a deprecation banner — would otherwise inject bytes into the
    JSON-RPC stream. Rather than crash the session, we divert and record.
    """

    def __init__(self, real_stderr: IO[str]) -> None:
        self._stderr = real_stderr
        self.diverted_chars = 0

    def write(self, s: str) -> int:
        if s.strip():
            self.diverted_chars += len(s)
            get("stdout_guard").warning(
                "diverted a write to stdout; stdout is the MCP transport",
                extra={"chars": len(s), "preview": s[:200]},
            )
        return self._stderr.write(s)

    def flush(self) -> None:
        self._stderr.flush()

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._stderr.fileno()

    def writelines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.write(line)


@contextlib.contextmanager
def guard_stdout() -> Iterator[StdoutGuard]:
    """Replace ``sys.stdout`` with a `StdoutGuard` for the duration of the block."""
    real_stdout, real_stderr = sys.stdout, sys.stderr
    guard = StdoutGuard(real_stderr)
    sys.stdout = cast("TextIO", guard)
    try:
        yield guard
    finally:
        sys.stdout = real_stdout
