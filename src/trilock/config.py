"""Runtime configuration: which upstream servers to proxy, and with what policy.

Two files, two jobs:

* ``trilock.yaml`` — this module. Upstream MCP servers, audit sink, detector
  budget, and a pointer to the policy document.
* ``policies/*.yaml`` — `trilock.policy.model`. The security policy itself,
  loaded separately so a policy can be reviewed, diffed and shipped on its own.

Resolution order for the runtime config is ``./trilock.yaml``, then
``$XDG_CONFIG_HOME/trilock/config.yaml`` (falling back to
``~/.config/trilock/config.yaml``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

CONFIG_BASENAME: Final[str] = "trilock.yaml"
XDG_RELATIVE: Final[str] = "trilock/config.yaml"
STATE_DIRNAME: Final[str] = ".trilock"


class ConfigError(ValueError):
    """A configuration file is missing, unparseable, or internally inconsistent."""


class _Strict(BaseModel):
    """Base for every config model: unknown keys are an error, not a shrug.

    A typo in a security tool's config must never silently disable a control.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class StdioUpstream(_Strict):
    """An upstream MCP server launched as a subprocess and spoken to over stdio."""

    transport: Literal["stdio"] = "stdio"
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)
    cwd: Path | None = None
    """Extra environment variables. The SDK merges these over a filtered
    inherited environment (PATH, HOME and friends); there is no way to launch a
    fully hermetic child through it, so no config knob pretends otherwise."""


class HttpUpstream(_Strict):
    """An upstream MCP server reached over Streamable HTTP."""

    transport: Literal["http"] = "http"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


Upstream = Annotated[StdioUpstream | HttpUpstream, Field(discriminator="transport")]


class AuditConfig(_Strict):
    """Where the hash-chained decision log is written."""

    path: Path = Path(STATE_DIRNAME) / "audit.jsonl"
    enabled: bool = True


class DetectorConfig(_Strict):
    """Advisory detectors. Never a control (Hard Rule 1); always killable (Hard Rule 2)."""

    enabled: bool = True
    timeout_ms: int = Field(default=150, gt=0, le=10_000)
    heuristics: bool = True
    promptguard: bool = False
    """Off by default, and not only until the model is downloaded: on the
    hardware it was measured on, a 4 KB document costs 250-500 ms against a
    150 ms budget (see bench/results/detector_latency.json). Enable it knowing
    that long inputs will time out and contribute nothing, which is safe."""
    model_dir: Path = Path(STATE_DIRNAME) / "models" / "promptguard-22m"


class PinConfig(_Strict):
    """Tool definition pinning (rug-pull detection)."""

    enabled: bool = True
    path: Path = Path(STATE_DIRNAME) / "pins.json"
    strict: bool = False
    """Withhold and refuse a tool whose definition changed, rather than warn.

    Set from the policy's mode when a policy is loaded: `strict` mode implies
    strict pinning.
    """


class LedgerConfig(_Strict):
    """Bounds on the per-session provenance ledger."""

    max_sources: int = Field(default=500, gt=0)
    ngram_size: int = Field(default=5, ge=2, le=16)
    max_ngrams_per_source: int = Field(default=4096, gt=0)


class TrilockConfig(_Strict):
    """The whole runtime configuration."""

    version: Literal[1] = 1
    servers: dict[str, Upstream] = Field(default_factory=dict)
    policy: Path | None = None
    """Path to the policy document. Relative paths resolve against the config file."""
    audit: AuditConfig = Field(default_factory=AuditConfig)
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    ledger: LedgerConfig = Field(default_factory=LedgerConfig)
    pins: PinConfig = Field(default_factory=PinConfig)
    state_dir: Path = Path(STATE_DIRNAME)
    source_path: Path | None = None
    """Where this config was loaded from. Set by the loader, never by the file."""

    @property
    def base_dir(self) -> Path:
        """Directory relative scope patterns resolve against.

        The config file's own directory when there is one, so a policy that
        says ``./workspace/**`` means the workspace beside the config rather
        than beside whatever directory the agent happened to launch from.
        """
        return self.source_path.parent if self.source_path is not None else Path.cwd()

    @model_validator(mode="after")
    def _check_server_names(self) -> TrilockConfig:
        for name in self.servers:
            if not name or "." in name or "/" in name or name.isspace():
                raise ValueError(
                    f"upstream server name {name!r} is invalid: names must be non-empty "
                    "and contain no '.' or '/' (the dot is the namespace separator "
                    "in '<server>.<tool>')"
                )
        return self


def default_config_paths() -> tuple[Path, ...]:
    """The search path for ``trilock.yaml``, in priority order."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    xdg_root = Path(xdg) if xdg else Path.home() / ".config"
    return (Path.cwd() / CONFIG_BASENAME, xdg_root / XDG_RELATIVE)


def find_config() -> Path | None:
    """Return the first existing config path, or ``None`` if there is none."""
    return next((p for p in default_config_paths() if p.is_file()), None)


def load_config(path: Path | None = None) -> TrilockConfig:
    """Load and validate the runtime config.

    With no ``path`` and no file on the search path, returns defaults with no
    upstreams — which is a valid, if useless, proxy. Refusing to start here
    would make ``trilock check`` unable to explain the problem.
    """
    resolved = path if path is not None else find_config()
    if resolved is None:
        return TrilockConfig()
    if not resolved.is_file():
        raise ConfigError(f"config file not found: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{resolved}: invalid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{resolved}: top level must be a mapping, got {type(raw).__name__}")
    raw.pop("source_path", None)
    try:
        config = TrilockConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"{resolved}: {exc}") from exc
    base = resolved.parent
    return config.model_copy(
        update={
            "source_path": resolved,
            "policy": (base / config.policy) if config.policy is not None else None,
            "state_dir": base / config.state_dir,
            "audit": config.audit.model_copy(update={"path": base / config.audit.path}),
            "detectors": config.detectors.model_copy(
                update={"model_dir": base / config.detectors.model_dir}
            ),
            "pins": config.pins.model_copy(update={"path": base / config.pins.path}),
        }
    )
