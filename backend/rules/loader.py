"""Loads declarative rule packs from the ``rules/`` directory.

Rules are data: they are parsed with ``yaml.safe_load`` and validated, never executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _yaml(text: str) -> Any:
    return yaml.load(text, Loader=_Loader)  # noqa: S506 - SafeLoader (C or Python)


class RuleError(Exception):
    pass


def _load_yaml_dir(directory: Path) -> list[tuple[Path, Any]]:
    out = []
    if not directory.is_dir():
        return out
    for path in sorted(directory.rglob("*.y*ml")):
        out.append((path, _yaml(path.read_text(encoding="utf-8"))))
    return out


@dataclass
class StringPattern:
    tag: str
    klass: str
    category: str
    regex: re.Pattern
    description: str


@dataclass
class ApiInfo:
    name: str
    category: str
    severity: str
    description: str
    legit: str


@dataclass
class RulePack:
    root: Path
    string_patterns: list[StringPattern] = field(default_factory=list)
    apis: dict[str, ApiInfo] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    packers: list[dict[str, Any]] = field(default_factory=list)
    heuristics: list[dict[str, Any]] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    mitre: dict[str, dict[str, Any]] = field(default_factory=dict)
    appsec: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # derived lookups -------------------------------------------------------------
    @property
    def common_domains(self) -> set[str]:
        return set(self.network.get("common_domains", []))

    @property
    def suspicious_services(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in (self.network.get("suspicious_services") or {}).items()}

    @property
    def suspicious_tlds(self) -> set[str]:
        return set(self.network.get("suspicious_tlds", []))

    @property
    def unusual_ports(self) -> set[int]:
        return set(int(p) for p in self.network.get("unusual_ports", []))

    def counts(self) -> dict[str, int]:
        return {
            "string_signatures": len(self.string_patterns),
            "api_signatures": len(self.apis),
            "packer_signatures": len(self.packers),
            "heuristic_rules": len(self.heuristics),
            "correlation_rules": len(self.correlations),
            "mitre_techniques": len(self.mitre),
            "appsec_rules": len(self.appsec),
        }


REQUIRED_HEURISTIC_KEYS = {"id", "name", "severity", "conditions", "explanation"}


def load_rule_pack(root: Path) -> RulePack:
    pack = RulePack(root=root)
    sig = root / "signatures"
    strings_file = sig / "strings.yaml"
    if strings_file.is_file():
        data = _yaml(strings_file.read_text(encoding="utf-8")) or {}
        for entry in data.get("patterns", []):
            try:
                pack.string_patterns.append(StringPattern(
                    tag=entry["tag"], klass=entry["class"], category=entry.get("category", "info"),
                    regex=re.compile(entry["regex"], re.I), description=entry.get("description", ""),
                ))
            except (KeyError, re.error) as exc:
                pack.errors.append(f"strings.yaml: {entry.get('tag')}: {exc}")
    apis_file = sig / "apis.yaml"
    if apis_file.is_file():
        data = _yaml(apis_file.read_text(encoding="utf-8")) or {}
        for entry in data.get("apis", []):
            for name in entry.get("names", []):
                pack.apis[name.lower()] = ApiInfo(
                    name=name, category=entry.get("category", "info"), severity=entry.get("severity", "info"),
                    description=entry.get("description", ""), legit=entry.get("legit", ""),
                )
    packers_file = sig / "packers.yaml"
    if packers_file.is_file():
        data = _yaml(packers_file.read_text(encoding="utf-8")) or {}
        pack.packers = [p for p in data.get("packers", []) if isinstance(p, dict) and not p.get("disabled")]
    net_file = sig / "network.yaml"
    if net_file.is_file():
        pack.network = _yaml(net_file.read_text(encoding="utf-8")) or {}

    for path, data in _load_yaml_dir(root / "heuristics"):
        for rule in _as_rule_list(data):
            missing = REQUIRED_HEURISTIC_KEYS - set(rule)
            if missing:
                pack.errors.append(f"{path.name}: rule {rule.get('id')} missing {sorted(missing)}")
                continue
            rule.setdefault("category", "info")
            rule.setdefault("confidence", 0.5)
            rule.setdefault("reliability", "medium")
            rule.setdefault("mitre", [])
            rule["_file"] = path.name
            pack.heuristics.append(rule)
    for path, data in _load_yaml_dir(root / "correlation"):
        for rule in _as_rule_list(data):
            if "id" not in rule or "requires" not in rule:
                pack.errors.append(f"{path.name}: correlation rule missing id/requires")
                continue
            rule["_file"] = path.name
            pack.correlations.append(rule)
    for path, data in _load_yaml_dir(root / "mitre"):
        for tech in (data or {}).get("techniques", []):
            pack.mitre[tech["id"]] = tech
    for path, data in _load_yaml_dir(root / "appsec"):
        for rule in _as_rule_list(data):
            try:
                rule["_regex"] = re.compile(rule["pattern"], re.I if rule.get("ignore_case") else 0)
            except (KeyError, re.error) as exc:
                pack.errors.append(f"{path.name}: {rule.get('id')}: {exc}")
                continue
            if rule.get("exclude"):
                rule["_exclude"] = re.compile(rule["exclude"], re.I if rule.get("ignore_case") else 0)
            pack.appsec.append(rule)
    ids = [r["id"] for r in pack.heuristics]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        pack.errors.append(f"duplicate heuristic ids: {sorted(dupes)}")
    return pack


def _as_rule_list(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        if "rules" in data and isinstance(data["rules"], list):
            return [d for d in data["rules"] if isinstance(d, dict)]
        return [data]
    return []


@lru_cache(maxsize=4)
def get_rule_pack(root: str) -> RulePack:
    return load_rule_pack(Path(root))
