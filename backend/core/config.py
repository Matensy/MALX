"""MALX configuration.

Values come from (lowest to highest precedence): built-in defaults, ``malx.yaml``
(or the file named by ``MALX_CONFIG``), and ``MALX_*`` environment variables.
Sizes accept human units ("500MB", "2GiB") and durations accept "90s", "10m", "1h".
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

_SIZE_UNITS = {
    "": 1, "b": 1,
    "k": 1000, "kb": 1000, "kib": 1024,
    "m": 1000**2, "mb": 1000**2, "mib": 1024**2,
    "g": 1000**3, "gb": 1000**3, "gib": 1024**3,
    "t": 1000**4, "tb": 1000**4, "tib": 1024**4,
}
_TIME_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600}


def parse_size(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid size")
    if isinstance(value, (int, float)):
        return int(value)
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)\s*", str(value))
    if not match or match.group(2).lower() not in _SIZE_UNITS:
        raise ValueError(f"invalid size: {value!r}")
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2).lower()])


def parse_duration(value: Any) -> int:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([smhSMH]?)\s*", str(value))
    if not match:
        raise ValueError(f"invalid duration: {value!r}")
    return int(float(match.group(1)) * _TIME_UNITS[match.group(2).lower()])


class Limits(BaseModel):
    max_upload_size: int = parse_size("500MB")
    max_files_per_upload: int = 50
    max_archive_size: int = parse_size("1GB")
    max_files_per_archive: int = 10_000
    max_archive_depth: int = 10
    max_extracted_size: int = parse_size("2GB")
    max_entry_size: int = parse_size("1GB")
    max_compression_ratio: float = 250.0
    max_total_artifacts: int = 10_000
    max_analysis_time: int = parse_duration("10m")
    max_memory_per_worker: int = parse_size("2GB")
    max_filename_length: int = 255
    max_deep_scan_size: int = parse_size("256MB")
    max_strings_per_artifact: int = 5000
    max_fuzzy_hash_size: int = parse_size("64MB")
    max_reverse_functions: int = 400

    @field_validator(
        "max_upload_size", "max_archive_size", "max_extracted_size", "max_entry_size",
        "max_memory_per_worker", "max_deep_scan_size", "max_fuzzy_hash_size", mode="before",
    )
    @classmethod
    def _sizes(cls, v: Any) -> int:
        return parse_size(v)

    @field_validator("max_analysis_time", mode="before")
    @classmethod
    def _durations(cls, v: Any) -> int:
        return parse_duration(v)


class ServerSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:5173", "http://localhost:5173"]
    )


class WorkerSettings(BaseModel):
    max_concurrent_analyses: int = 2
    retain_extracted: bool = True
    # "process" isolates every analysis in a child process with resource limits.
    # "inline" runs in-process and exists only for tests/debugging.
    mode: str = "process"


class IntegrationSettings(BaseModel):
    local_tools_enabled: bool = True
    tool_timeout: int = 120
    ghidra_home: str = ""
    external_enabled: bool = False

    @field_validator("tool_timeout", mode="before")
    @classmethod
    def _timeout(cls, v: Any) -> int:
        return parse_duration(v)


class _YamlSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: type[BaseSettings]):
        super().__init__(settings_cls)
        path = os.environ.get("MALX_CONFIG") or str(PROJECT_ROOT / "malx.yaml")
        self._data: dict[str, Any] = {}
        p = Path(path)
        if p.is_file():
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                self._data = loaded

    def get_field_value(self, field, field_name):  # pragma: no cover - required by ABC
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._data)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MALX_", env_nested_delimiter="__", extra="ignore")

    storage_dir: Path = Path("storage")
    rules_dir: Path = Path("rules")
    database_url: str = ""
    frontend_dist: Path = Path("frontend/dist")
    server: ServerSettings = Field(default_factory=ServerSettings)
    limits: Limits = Field(default_factory=Limits)
    workers: WorkerSettings = Field(default_factory=WorkerSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        return (init_settings, env_settings, _YamlSource(settings_cls))

    def model_post_init(self, __context: Any) -> None:
        for name in ("storage_dir", "rules_dir", "frontend_dist"):
            value: Path = getattr(self, name)
            if not value.is_absolute():
                object.__setattr__(self, name, (PROJECT_ROOT / value).resolve())
        if not self.database_url:
            object.__setattr__(self, "database_url", f"sqlite:///{self.storage_dir / 'malx.db'}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
