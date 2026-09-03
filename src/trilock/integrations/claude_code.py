"""Wrap an existing MCP client configuration behind Trilock, reversibly.

`trilock init` reads a client's MCP config, moves every configured server into
``trilock.yaml`` as an upstream, and rewrites the client config so its only
server is Trilock. `trilock uninstall` puts the original back **byte for byte**.

Two things this is careful about:

* **The backup is the original file's bytes, not a re-serialisation.** A JSON
  file re-dumped by Python loses key order, indentation, trailing newlines and
  comments (Cursor and VS Code tolerate `//` comments). Restoring a re-dump
  would be "close enough", which is not the same as restored. So the backup is
  a byte copy and `uninstall` writes those bytes back.
* **Nothing is overwritten before its backup exists and verifies.** The backup
  is written, read back, compared to the source, and only then is the client
  config replaced. A crash between the two leaves the backup and the original.

Supported shapes — the same `mcpServers` object under different roofs:

| client | file | where the servers live |
|---|---|---|
| Claude Code | `.mcp.json` (project) | top-level `mcpServers` |
| Claude Desktop | `claude_desktop_config.json` | top-level `mcpServers` |
| Cursor | `.cursor/mcp.json` / `~/.cursor/mcp.json` | top-level `mcpServers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | top-level `mcpServers` |
| VS Code | `.vscode/mcp.json` | top-level `servers` |
| Zed | `settings.json` | `context_servers` |
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from trilock import log

_log = log.get("integrations.claude_code")

BACKUP_DIRNAME: Final[str] = "backups"
MANIFEST_NAME: Final[str] = "init-manifest.json"
SERVER_KEYS: Final[tuple[str, ...]] = ("mcpServers", "servers", "context_servers")
"""Where each supported client keeps its server map, in the order tried."""

_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


class IntegrationError(RuntimeError):
    """The client config could not be wrapped or restored safely."""


@dataclass(frozen=True, slots=True)
class ClientConfig:
    path: Path
    raw: bytes
    document: dict[str, Any]
    servers_key: str

    @property
    def servers(self) -> dict[str, Any]:
        found = self.document.get(self.servers_key)
        return found if isinstance(found, dict) else {}

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def _parse_lenient_json(raw: bytes) -> dict[str, Any]:
    """JSON, tolerating the `//` comments and trailing commas some clients allow.

    Only for *reading*. Nothing here ever writes the lenient form back — the
    original bytes are what get restored.
    """
    text = raw.decode("utf-8")
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        stripped = _TRAILING_COMMA.sub(r"\1", _LINE_COMMENT.sub("", text))
        parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise IntegrationError("client config is not a JSON object")
    return parsed


def load_client_config(path: Path) -> ClientConfig:
    if not path.is_file():
        raise IntegrationError(f"client config not found: {path}")
    raw = path.read_bytes()
    document = _parse_lenient_json(raw)
    key = next((k for k in SERVER_KEYS if isinstance(document.get(k), dict)), None)
    if key is None:
        raise IntegrationError(
            f"{path}: no server map found (looked for {', '.join(SERVER_KEYS)}). "
            "Is this an MCP client config?"
        )
    return ClientConfig(path=path, raw=raw, document=document, servers_key=key)


def to_upstream(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Translate one client server entry into a Trilock upstream."""
    if "url" in entry:
        upstream: dict[str, Any] = {"transport": "http", "url": entry["url"]}
        if isinstance(entry.get("headers"), dict):
            upstream["headers"] = dict(entry["headers"])
        return upstream
    if "command" in entry:
        command = entry["command"]
        args = entry.get("args")
        if isinstance(command, dict):  # Zed: {"command": {"path": ..., "args": [...]}}
            args = command.get("args", args)
            command = command.get("path")
        if not isinstance(command, str) or not command:
            raise IntegrationError(
                f"server {name!r} has a command that is not a string; cannot wrap it"
            )
        upstream = {"transport": "stdio", "command": command}
        if args:
            upstream["args"] = list(args)
        if isinstance(entry.get("env"), dict):
            upstream["env"] = dict(entry["env"])
        if entry.get("cwd"):
            upstream["cwd"] = entry["cwd"]
        return upstream
    raise IntegrationError(f"server {name!r} has neither 'command' nor 'url'; cannot wrap it")


def trilock_server_entry(config_path: Path, *, servers_key: str) -> dict[str, Any]:
    """The client-side entry that points at Trilock instead of the real servers."""
    entry: dict[str, Any] = {
        "command": _trilock_command(),
        "args": ["serve", "--config", str(config_path)],
    }
    if servers_key == "servers":  # VS Code wants an explicit type
        entry["type"] = "stdio"
    return entry


def _trilock_command() -> str:
    """Prefer the installed console script; fall back to `python -m trilock.cli`."""
    found = shutil.which("trilock")
    return found if found else sys.executable


def _trilock_args(entry: dict[str, Any]) -> list[str]:
    if entry["command"] == sys.executable and shutil.which("trilock") is None:
        return ["-m", "trilock.cli", *entry["args"]]
    return list(entry["args"])


def backup_dir(state_dir: Path) -> Path:
    return state_dir / BACKUP_DIRNAME


def init(
    client_config_path: Path,
    *,
    trilock_config_path: Path,
    state_dir: Path,
    policy_path: Path | None = None,
    server_name: str = "trilock",
) -> dict[str, Any]:
    """Wrap every server in the client config behind Trilock.

    Returns the manifest that `uninstall` will use. Refuses to run twice on the
    same file without an uninstall in between: the second run would wrap Trilock
    behind Trilock.
    """
    client = load_client_config(client_config_path)
    if list(client.servers) == [server_name] and "serve" in json.dumps(
        client.servers.get(server_name, {})
    ):
        raise IntegrationError(
            f"{client_config_path} already points at Trilock; run 'trilock uninstall' first"
        )
    if not client.servers:
        raise IntegrationError(f"{client_config_path} has no servers to wrap")

    upstreams = {name: to_upstream(name, entry) for name, entry in client.servers.items()}
    for name in upstreams:
        if "." in name or "/" in name:
            raise IntegrationError(
                f"server name {name!r} contains '.' or '/', which Trilock uses as a "
                "namespace separator; rename it first"
            )

    # 1. Back up the original bytes, and verify the backup before touching anything.
    backups = backup_dir(state_dir)
    backups.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_path = backups / f"{client_config_path.name}.{stamp}.bak"
    backup_path.write_bytes(client.raw)
    if backup_path.read_bytes() != client.raw:
        backup_path.unlink(missing_ok=True)
        raise IntegrationError("backup did not verify; nothing was changed")

    # 2. Write trilock.yaml with the upstreams.
    trilock_doc: dict[str, Any] = {"version": 1, "servers": upstreams}
    if policy_path is not None:
        trilock_doc["policy"] = str(policy_path)
    trilock_config_path.parent.mkdir(parents=True, exist_ok=True)
    trilock_config_path.write_text(
        "# Generated by `trilock init`. Your original client config is backed up at\n"
        f"# {backup_path}\n# and `trilock uninstall` restores it byte for byte.\n"
        + yaml.safe_dump(trilock_doc, sort_keys=False),
        encoding="utf-8",
    )

    # 3. Rewrite the client config so its only server is Trilock.
    entry = trilock_server_entry(trilock_config_path, servers_key=client.servers_key)
    entry["args"] = _trilock_args(entry)
    new_document = dict(client.document)
    new_document[client.servers_key] = {server_name: entry}
    client_config_path.write_text(json.dumps(new_document, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "client_config": str(client_config_path),
        "backup": str(backup_path),
        "backup_sha256": client.digest,
        "trilock_config": str(trilock_config_path),
        "servers_key": client.servers_key,
        "wrapped": sorted(upstreams),
        "created": stamp,
    }
    (state_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    _log.info("client wrapped behind trilock", extra=manifest)
    return manifest


def uninstall(state_dir: Path, *, remove_trilock_config: bool = False) -> dict[str, Any]:
    """Restore the client config from its backup, byte for byte."""
    manifest_path = state_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise IntegrationError(f"no init manifest at {manifest_path}; nothing to uninstall")
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    backup = Path(manifest["backup"])
    if not backup.is_file():
        raise IntegrationError(f"backup missing: {backup}; refusing to guess at the original")
    raw = backup.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["backup_sha256"]:
        raise IntegrationError(
            f"backup {backup} does not match its recorded digest; "
            "refusing to restore a corrupted file"
        )
    target = Path(manifest["client_config"])
    target.write_bytes(raw)
    if target.read_bytes() != raw:
        raise IntegrationError("restore did not verify")
    if remove_trilock_config:
        Path(manifest["trilock_config"]).unlink(missing_ok=True)
    manifest_path.unlink()
    _log.info("client config restored", extra={"client_config": str(target), "backup": str(backup)})
    return manifest


def discover_client_configs(root: Path | None = None) -> list[Path]:
    """Well-known client config locations that exist on this machine."""
    home = Path.home()
    cwd = root if root is not None else Path.cwd()
    candidates = [
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".config" / "Claude" / "claude_desktop_config.json",
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ]
    return [p for p in candidates if p.is_file()]
