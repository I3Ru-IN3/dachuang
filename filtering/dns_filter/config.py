"""Typed application configuration.

Configuration parsing is kept out of the runtime objects.  The rest of the
application receives small, validated dataclasses through constructor
injection, which makes both configuration and tests explicit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

FILTERING_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = FILTERING_DIR.parent
DEFAULT_CONFIG_PATH = FILTERING_DIR / "config.yaml"
CONFIG_ENV_VAR = "DNS_FILTER_CONFIG"

_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}


class ConfigError(ValueError):
    """Raised when configuration is missing, malformed or inconsistent."""


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """Settings for the packet source."""

    offline_mode: bool = False
    pcap_file: Path | None = None
    interface_index: int | None = None
    timeout: float = 0.0
    packet_count: int = 0
    bpf_filter: str = ""

    def validate(self) -> None:
        if self.offline_mode:
            if self.pcap_file is None:
                raise ConfigError("离线模式必须配置 capture.pcap_file")
            if not self.pcap_file.exists():
                raise ConfigError(f"离线抓包文件不存在: {self.pcap_file}")
        elif self.interface_index is None:
            raise ConfigError("在线模式必须配置 capture.interface_index")

        if self.timeout < 0:
            raise ConfigError("capture.timeout 不能为负数")
        if self.packet_count < 0:
            raise ConfigError("capture.packet_count 不能为负数")


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Settings for the application logger."""

    enabled: bool = True
    level: str = "INFO"
    file: Path | None = None
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5

    def validate(self) -> None:
        if self.level.upper() not in _LOG_LEVELS:
            raise ConfigError(
                f"logging.level 必须是 {sorted(_LOG_LEVELS)} 之一，当前为 {self.level!r}"
            )
        if self.max_bytes <= 0:
            raise ConfigError("logging.max_bytes 必须为正数")
        if self.backup_count < 0:
            raise ConfigError("logging.backup_count 不能为负数")


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated configuration for a filtering run."""

    capture: CaptureConfig
    logging: LoggingConfig
    source_path: Path | None = None

    def validate(self) -> None:
        self.capture.validate()
        self.logging.validate()

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "AppConfig":
        """Load and validate configuration from *path*."""

        config_path = resolve_config_path(path)
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                raw = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise ConfigError(f"配置文件解析失败: {config_path}: {exc}") from exc

        config = cls.from_mapping(raw, source_path=config_path)
        config.validate()
        return config

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any] | None,
        *,
        source_path: Path | None = None,
        base_dir: Path | None = None,
    ) -> "AppConfig":
        """Build a configuration object from an already-parsed mapping.

        ``base_dir`` controls how relative paths are resolved.  By default it is
        the directory containing the configuration file.
        """

        values = {} if raw is None else raw
        if not isinstance(values, Mapping):
            raise ConfigError("配置文件根节点必须是映射")

        capture_raw = _section(values, "capture")
        logging_raw = _section(values, "logging")
        base = base_dir or (source_path.parent if source_path is not None else FILTERING_DIR)

        capture = CaptureConfig(
            offline_mode=_as_bool(capture_raw.get("offline_mode", False), "capture.offline_mode"),
            pcap_file=_resolve_optional_path(capture_raw.get("pcap_file"), base),
            interface_index=_as_optional_int(
                capture_raw.get("interface_index"), "capture.interface_index"
            ),
            timeout=_as_float(capture_raw.get("timeout", 0.0), "capture.timeout"),
            packet_count=_as_int(capture_raw.get("packet_count", 0), "capture.packet_count"),
            bpf_filter=str(capture_raw.get("filter") or "").strip(),
        )
        logging_config = LoggingConfig(
            enabled=_as_bool(logging_raw.get("enabled", True), "logging.enabled"),
            level=str(logging_raw.get("level", "INFO") or "INFO").upper(),
            file=_resolve_optional_path(logging_raw.get("file"), base),
            max_bytes=_as_int(
                logging_raw.get("max_bytes", 10 * 1024 * 1024), "logging.max_bytes"
            ),
            backup_count=_as_int(logging_raw.get("backup_count", 5), "logging.backup_count"),
        )

        return cls(capture=capture, logging=logging_config, source_path=source_path)


def resolve_config_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the configuration path with explicit/env/default precedence."""

    if path is not None:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if not candidate.exists():
            raise ConfigError(f"配置文件不存在: {candidate}")
        return candidate.resolve()

    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        candidate = Path(env_path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if not candidate.exists():
            raise ConfigError(f"环境变量 {CONFIG_ENV_VAR} 指向的配置文件不存在: {candidate}")
        return candidate.resolve()

    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH

    raise ConfigError(
        f"找不到配置文件，请使用 --config 指定，或设置 {CONFIG_ENV_VAR}；"
        f"默认路径为 {DEFAULT_CONFIG_PATH}"
    )


def _section(values: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = values.get(name)
    if section is None:
        return {}
    if not isinstance(section, Mapping):
        raise ConfigError(f"配置项 {name} 必须是映射")
    return section


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ConfigError(f"配置项 {name} 必须是布尔值，当前为 {value!r}")
    return bool(value)


def _as_optional_int(value: Any, name: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"配置项 {name} 必须是整数，当前为 {value!r}") from exc


def _as_int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"配置项 {name} 必须是整数，当前为 {value!r}") from exc


def _as_float(value: Any, name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"配置项 {name} 必须是数字，当前为 {value!r}") from exc


def _resolve_optional_path(value: Any, base_dir: Path) -> Path | None:
    """Resolve a relative path using the config directory, cwd and project root.

    The fallback list preserves the original project's behaviour (paths such as
    ``filtering/noise.pcapng`` were relative to the repository root) while also
    allowing the program to be started from the ``filtering`` directory.
    """

    if value is None or str(value).strip() == "":
        return None

    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return path

    candidates = [
        base_dir / path,
        Path.cwd() / path,
        FILTERING_DIR / path,
        PROJECT_DIR / path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    # For not-yet-created outputs (for example a log file), a path beginning
    # with the subsystem directory is almost certainly project-root relative.
    if path.parts and path.parts[0] == FILTERING_DIR.name:
        return (PROJECT_DIR / path).resolve()
    return (base_dir / path).resolve()
