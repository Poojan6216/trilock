"""Unit tests for the pin digest and store."""

from __future__ import annotations

from pathlib import Path

import mcp_types as types

from trilock.proxy.pins import PinStore, digest_tool


def tool(**overrides: object) -> types.Tool:
    base: dict[str, object] = {
        "name": "fetch",
        "description": "Fetch a page.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
    }
    base.update(overrides)
    return types.Tool.model_validate(base)


def test_digest_is_stable_and_field_sensitive() -> None:
    assert digest_tool(tool()) == digest_tool(tool())
    assert digest_tool(tool()) != digest_tool(tool(description="Fetch a page!"))
    assert digest_tool(tool()) != digest_tool(tool(inputSchema={"type": "object"}))
    assert digest_tool(tool()) != digest_tool(tool(name="fetch2"))
    # Beyond the three obvious fields: these also change what a tool claims.
    assert digest_tool(tool()) != digest_tool(tool(title="Fetcher"))
    assert digest_tool(tool()) != digest_tool(
        tool(outputSchema={"type": "object", "properties": {}})
    )
    assert digest_tool(tool()) != digest_tool(tool(annotations={"readOnlyHint": True}))


def test_digest_ignores_key_order_in_the_schema() -> None:
    a = tool(inputSchema={"type": "object", "properties": {"url": {"type": "string"}}})
    b = tool(inputSchema={"properties": {"url": {"type": "string"}}, "type": "object"})
    assert digest_tool(a) == digest_tool(b)


def test_store_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    store = PinStore(path)
    assert store.check("s", [tool()]) == []
    store.save()
    assert path.is_file()

    reloaded = PinStore.load(path)
    assert len(reloaded) == 1
    assert reloaded.check("s", [tool()]) == []
    violations = reloaded.check("s", [tool(description="changed")])
    assert len(violations) == 1
    assert violations[0].server == "s"
    assert violations[0].tool == "fetch"


def test_a_corrupt_pin_file_does_not_stop_startup(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    path.write_text("{not json", encoding="utf-8")
    store = PinStore.load(path)
    assert len(store) == 0
    # Everything looks new, which re-pins rather than crashing or silently trusting.
    assert store.check("s", [tool()]) == []


def test_a_vanished_tool_is_not_a_violation_but_keeps_its_pin(tmp_path: Path) -> None:
    store = PinStore(tmp_path / "pins.json")
    store.check("s", [tool()])
    assert store.check("s", []) == []
    assert len(store) == 1
    # Returning with a different definition is still caught.
    assert len(store.check("s", [tool(description="changed")])) == 1


def test_forget_drops_one_server(tmp_path: Path) -> None:
    store = PinStore(tmp_path / "pins.json")
    store.check("a", [tool()])
    store.check("b", [tool()])
    store.forget("a")
    assert set(store.pins) == {"b/fetch"}


def test_filter_only_withholds_in_strict_mode(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    lenient = PinStore(path, strict=False)
    lenient.check("s", [tool()])
    assert len(lenient.filter("s", [tool(description="changed")])) == 1

    strict = PinStore(path, strict=True)
    strict.check("s", [tool()])
    assert strict.filter("s", [tool(description="changed")]) == []


def test_exception_group_descriptions_name_the_real_cause() -> None:
    """anyio wraps connect failures in a TaskGroup group; the cause must survive."""
    from trilock.proxy.upstream import describe_exception

    inner = ModuleNotFoundError("No module named 'mcp'")
    group = BaseExceptionGroup("unhandled errors in a TaskGroup", [inner])
    described = describe_exception(group)
    assert "ModuleNotFoundError" in described
    assert "No module named 'mcp'" in described
    assert "TaskGroup" not in described

    chained = RuntimeError("connect failed")
    chained.__cause__ = OSError("permission denied")
    assert (
        describe_exception(chained) == "RuntimeError: connect failed <- OSError: permission denied"
    )

    many = BaseExceptionGroup("g", [ValueError(str(i)) for i in range(5)])
    assert "+2 more" in describe_exception(many)
