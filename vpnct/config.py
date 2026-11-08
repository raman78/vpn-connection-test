"""User settings for starts without command-line options (the menu entry).

`$XDG_CONFIG_HOME/vpn-connection-test/config.toml`, all keys optional:

    programs = ["AION2.exe"]     # watch every connection of these programs
    ports = [13328]              # and/or connections to these remote ports
    targets = ["8.8.8.8"]        # extra ping targets (default 8.8.8.8, 1.1.1.1)

Nothing pinned means automatic selection (the busiest connections). A file
that cannot be read is reported to the caller, never silently ignored.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "vpn-connection-test" / "config.toml"


@dataclass
class Config:
    programs: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    targets: list[str] | None = None
    source: str = "defaults"


class ConfigError(Exception):
    pass


def load(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        return Config(source=f"defaults ({path} not present)")
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    unknown = set(data) - {"programs", "ports", "targets"}
    if unknown:
        raise ConfigError(f"{path}: unknown setting(s) {', '.join(sorted(unknown))}; "
                          f"known: programs, ports, targets")
    try:
        programs = [str(p) for p in data.get("programs", [])]
        ports = [int(p) for p in data.get("ports", [])]
        targets = [str(t) for t in data["targets"]] if "targets" in data else None
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return Config(programs, ports, targets, source=str(path))
