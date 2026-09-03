# ruff: noqa: E501 - the fixtures below are byte-exact client configs and must not be re-wrapped
"""Task 7.1: `trilock init` wraps a client config and `trilock uninstall` restores it byte for byte.

Five real-world config shapes, including the two that are not strict JSON
(Cursor and VS Code tolerate `//` comments and trailing commas). The restore
assertion is on *bytes*: a re-serialised file that merely parses the same is
not restored.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest as _pytest
import yaml

from trilock import log
from trilock.integrations import claude_code, generic


@_pytest.fixture(autouse=True)
def _verbose_logging() -> None:
    """INFO records must be *built*, not skipped, or the LogRecord-key collision
    that once broke `init()` only shows up when another test has enabled logging."""
    log.configure("DEBUG")


from trilock.integrations.claude_code import IntegrationError, init, load_client_config, uninstall

SHAPES: dict[str, bytes] = {
    "claude_code_mcp_json": b"""{
  "mcpServers": {
    "mail": { "command": "python", "args": ["-m", "mail_server"], "env": { "MAIL_TOKEN": "x" } },
    "notes": { "command": "npx", "args": ["-y", "@example/notes-mcp"] }
  }
}
""",
    "claude_desktop": b"""{
    "globalShortcut": "Cmd+Shift+Space",
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/Documents"]
        },
        "remote": { "url": "https://mcp.example.com/mcp", "headers": { "Authorization": "Bearer t" } }
    }
}""",
    "cursor_with_comments": b"""{
  // Cursor tolerates comments and trailing commas.
  "mcpServers": {
    "git": { "command": "uvx", "args": ["mcp-server-git"], },
  },
}
""",
    "vscode_servers_key": b"""{
\t"servers": {
\t\t"fetch": { "type": "stdio", "command": "uvx", "args": ["mcp-server-fetch"] }
\t},
\t"inputs": []
}
""",
    "zed_context_servers": b"""{"context_servers":{"docs":{"command":{"path":"python","args":["docs.py"]}},"web":{"url":"https://w.example/mcp"}},"theme":"One Dark"}""",
}


def _write(tmp_path: Path, name: str) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_bytes(SHAPES[name])
    return path


@pytest.mark.parametrize("name", list(SHAPES))
def test_init_then_uninstall_restores_the_exact_bytes(tmp_path: Path, name: str) -> None:
    client = _write(tmp_path, name)
    original = client.read_bytes()
    state = tmp_path / ".trilock"
    trilock_yaml = tmp_path / "trilock.yaml"

    manifest = init(client, trilock_config_path=trilock_yaml, state_dir=state)
    assert client.read_bytes() != original, "init must actually rewrite the client config"
    rewritten = json.loads(client.read_text())
    servers = rewritten[manifest["servers_key"]]
    assert list(servers) == ["trilock"], "the client must see exactly one server: trilock"
    assert "serve" in servers["trilock"]["args"]
    assert Path(manifest["backup"]).read_bytes() == original

    doc = yaml.safe_load(trilock_yaml.read_text())
    assert set(doc["servers"]) == set(manifest["wrapped"])
    for upstream in doc["servers"].values():
        assert upstream["transport"] in ("stdio", "http")

    uninstall(state)
    assert client.read_bytes() == original, f"{name}: uninstall did not restore byte for byte"
    assert not (state / claude_code.MANIFEST_NAME).exists()


def test_zed_command_object_is_translated(tmp_path: Path) -> None:
    """Zed nests the executable under `command: {path, args}`; it is flattened, not refused."""
    client = _write(tmp_path, "zed_context_servers")
    assert load_client_config(client).servers_key == "context_servers"
    init(client, trilock_config_path=tmp_path / "t.yaml", state_dir=tmp_path / ".trilock")
    doc = yaml.safe_load((tmp_path / "t.yaml").read_text())
    assert doc["servers"]["docs"] == {
        "transport": "stdio",
        "command": "python",
        "args": ["docs.py"],
    }
    assert doc["servers"]["web"] == {"transport": "http", "url": "https://w.example/mcp"}


def test_upstream_translation_preserves_env_headers_and_urls(tmp_path: Path) -> None:
    client = _write(tmp_path, "claude_desktop")
    init(client, trilock_config_path=tmp_path / "trilock.yaml", state_dir=tmp_path / ".trilock")
    doc = yaml.safe_load((tmp_path / "trilock.yaml").read_text())
    assert doc["servers"]["remote"] == {
        "transport": "http",
        "url": "https://mcp.example.com/mcp",
        "headers": {"Authorization": "Bearer t"},
    }
    assert doc["servers"]["filesystem"]["args"][-1] == "/Users/me/Documents"


def test_init_refuses_to_wrap_trilock_behind_trilock(tmp_path: Path) -> None:
    client = _write(tmp_path, "claude_code_mcp_json")
    init(client, trilock_config_path=tmp_path / "trilock.yaml", state_dir=tmp_path / ".trilock")
    with pytest.raises(IntegrationError, match="already points at Trilock"):
        init(client, trilock_config_path=tmp_path / "trilock.yaml", state_dir=tmp_path / ".trilock")


def test_uninstall_refuses_a_corrupted_backup(tmp_path: Path) -> None:
    client = _write(tmp_path, "claude_code_mcp_json")
    state = tmp_path / ".trilock"
    manifest = init(client, trilock_config_path=tmp_path / "trilock.yaml", state_dir=state)
    Path(manifest["backup"]).write_bytes(b"{}")
    with pytest.raises(IntegrationError, match="does not match its recorded digest"):
        uninstall(state)


def test_uninstall_without_init_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(IntegrationError, match="nothing to uninstall"):
        uninstall(tmp_path / ".trilock")


def test_dotted_server_names_are_refused_before_anything_changes(tmp_path: Path) -> None:
    client = tmp_path / "c.json"
    client.write_bytes(b'{"mcpServers": {"my.server": {"command": "x"}}}')
    with pytest.raises(IntegrationError, match="namespace separator"):
        init(client, trilock_config_path=tmp_path / "t.yaml", state_dir=tmp_path / ".trilock")
    assert client.read_bytes() == b'{"mcpServers": {"my.server": {"command": "x"}}}'
    assert not (tmp_path / "t.yaml").exists()


def test_a_config_with_no_server_map_is_rejected(tmp_path: Path) -> None:
    client = tmp_path / "c.json"
    client.write_bytes(b'{"theme": "dark"}')
    with pytest.raises(IntegrationError, match="no server map"):
        load_client_config(client)


def test_print_snippet_is_valid_json_pointing_at_trilock(tmp_path: Path) -> None:
    snippet = json.loads(generic.client_snippet(tmp_path / "trilock.yaml"))
    entry = snippet["mcpServers"]["trilock"]
    assert "serve" in entry["args"] and str(tmp_path / "trilock.yaml") in entry["args"]
    vscode = json.loads(generic.client_snippet(tmp_path / "trilock.yaml", flavour="servers"))
    assert vscode["servers"]["trilock"]["type"] == "stdio"


def test_discovery_only_returns_existing_files(tmp_path: Path) -> None:
    assert claude_code.discover_client_configs(tmp_path) == [] or all(
        p.is_file() for p in claude_code.discover_client_configs(tmp_path)
    )
    (tmp_path / ".mcp.json").write_bytes(b'{"mcpServers": {}}')
    assert tmp_path / ".mcp.json" in claude_code.discover_client_configs(tmp_path)
