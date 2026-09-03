"""Session identity — the weakest structural link, so it gets its own tests.

The bug these exist to prevent: on a 2026-07-28 connection the SDK builds a
fresh ServerSession *and* Connection for every request, and `session_id` is
None. Identifying a session by its connection object therefore produced one
session per call, taint never accumulated across a session, and Trilock
silently protected nothing while all its logs looked healthy.
"""

from __future__ import annotations

from trilock.proxy.guard import SessionResolver
from trilock.taint.store import SessionKey


class FakeConnection:
    def __init__(self, session_id: str | None = None, **extra: object) -> None:
        self.session_id = session_id
        self.state: dict[str, object] = {}
        for key, value in extra.items():
            setattr(self, key, value)


class FakeSession:
    def __init__(self, connection: FakeConnection | None) -> None:
        self._connection = connection


def test_a_protocol_session_id_wins() -> None:
    resolver = SessionResolver("http")
    key = resolver.key_for(FakeSession(FakeConnection(session_id="abc-123")))
    assert key == SessionKey(kind="mcp-session", value="abc-123")
    assert not resolver.is_degraded(key)


def test_stdio_uses_the_process_because_it_serves_one_client() -> None:
    """The regression that matters: a fresh connection per request must not
    produce a fresh session per request."""
    resolver = SessionResolver("stdio")
    keys = {resolver.key_for(FakeSession(FakeConnection())) for _ in range(10)}
    assert len(keys) == 1, "stdio produced more than one session for one client"
    key = next(iter(keys))
    assert key.kind == "stdio-process"
    assert not resolver.is_degraded(key)


def test_stdio_identity_survives_a_session_object_with_no_connection() -> None:
    resolver = SessionResolver("stdio")
    assert resolver.key_for(FakeSession(None)) == resolver.key_for(object())


def test_an_authenticated_principal_is_used_before_falling_back() -> None:
    class User:
        subject = "user-7"

    resolver = SessionResolver("http")
    key = resolver.key_for(FakeSession(FakeConnection(user=User())))
    assert key == SessionKey(kind="principal", value="user:user-7")
    assert not resolver.is_degraded(key)


def test_a_principal_can_come_from_connection_state() -> None:
    resolver = SessionResolver("http")
    connection = FakeConnection()
    connection.state["trilock.principal"] = "svc-a"
    key = resolver.key_for(FakeSession(connection))
    assert key == SessionKey(kind="principal", value="state:svc-a")


def test_the_last_resort_is_marked_degraded() -> None:
    """With nothing stable to key on, Trilock must say so rather than pretend."""
    resolver = SessionResolver("http")
    connections = [FakeConnection() for _ in range(3)]  # held, so none is collected
    keys = [resolver.key_for(FakeSession(c)) for c in connections]
    assert all(k.kind == "connection" for k in keys)
    assert all(resolver.is_degraded(k) for k in keys)
    # Distinct connection objects give distinct keys - which is precisely the
    # failure mode, hence `degraded`.
    assert len(set(keys)) == 3
    # The same connection keeps its key, rather than drifting per lookup.
    assert resolver.key_for(FakeSession(connections[0])) == keys[0]


def test_identity_tokens_are_not_addresses() -> None:
    """CPython reuses the address of a collected object; a session key must not.

    Without this, a connection created after another was collected could land
    on the same address, be handed the same key, and share a ledger with an
    unrelated client.
    """
    resolver = SessionResolver("http")
    first = resolver.key_for(FakeSession(FakeConnection()))  # collected immediately
    second = resolver.key_for(FakeSession(FakeConnection()))
    assert first != second


def test_the_degraded_warning_is_emitted_once() -> None:
    import io
    import json

    from trilock import log

    stream = io.StringIO()
    log.configure("ERROR", stream=stream)
    resolver = SessionResolver("http")
    for _ in range(5):
        resolver.key_for(FakeSession(FakeConnection()))
    records = [json.loads(line) for line in stream.getvalue().splitlines() if line.startswith("{")]
    degraded = [r for r in records if "degraded" in r["msg"]]
    assert len(degraded) == 1
    assert "enforcement is disabled" in degraded[0]["consequence"]
