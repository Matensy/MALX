"""Integration with locally installed reverse-engineering tools.

MALX acts as an orchestrator: capa, FLOSS, radare2 and Ghidra (headless) are used
when installed and enabled. These tools *analyse* the file statically — the sample
path is passed to them as data. The sample itself is never executed.

Safety rules for every invocation:
* allow-listed binaries only, resolved with ``shutil.which`` (or GHIDRA_HOME);
* argument lists only (``shell=False``), stdin closed, minimal environment;
* hard timeout, output size cap, scratch working directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.analyzers.base import AnalysisContext, ArtifactContext, ExtractedString

MAX_OUTPUT = 64 * 1024 * 1024

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "capa": {"binary": "capa", "version": ["--version"], "purpose": "Capability detection (Mandiant FLARE capa)"},
    "floss": {"binary": "floss", "version": ["--version"], "purpose": "Obfuscated/stack string recovery (FLARE FLOSS)"},
    "radare2": {"binary": "r2", "version": ["-v"], "purpose": "Disassembly / decompilation (radare2, r2ghidra, r2dec)"},
    "ghidra": {"binary": "analyzeHeadless", "version": None, "purpose": "Ghidra headless analysis and decompilation"},
    "objdump": {"binary": "objdump", "version": ["--version"], "purpose": "GNU binutils disassembler"},
    "readelf": {"binary": "readelf", "version": ["--version"], "purpose": "GNU binutils ELF reader"},
    "strings": {"binary": "strings", "version": ["--version"], "purpose": "GNU strings"},
    "binwalk": {"binary": "binwalk", "version": ["--help"], "purpose": "Embedded file signature scanning"},
}


@dataclass
class ToolInfo:
    name: str
    path: str | None
    version: str | None
    purpose: str
    enabled: bool

    @property
    def available(self) -> bool:
        return self.path is not None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "path": self.path, "version": self.version, "purpose": self.purpose,
                "available": self.available, "enabled": self.enabled and self.available}


def _minimal_env() -> dict[str, str]:
    keep = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "JAVA_HOME", "GHIDRA_HOME") if k in os.environ}
    keep["HOME"] = tempfile.gettempdir()
    return keep


def run_tool(args: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run an allow-listed analysis tool. ``args[0]`` must be a resolved tool path."""
    allowed = {info.path for info in detect_tools_cached().values() if info.path}
    if args[0] not in allowed:
        raise PermissionError(f"tool not allow-listed: {args[0]}")
    return subprocess.run(  # noqa: S603 - allow-listed analysis tool, argument list, no shell
        args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, cwd=cwd or tempfile.gettempdir(),
        env=_minimal_env(), check=False, shell=False,
    )


def detect_tools(ghidra_home: str = "", enabled: bool = True) -> dict[str, ToolInfo]:
    out: dict[str, ToolInfo] = {}
    for name, spec in TOOL_SPECS.items():
        path = shutil.which(spec["binary"])
        if name == "ghidra":
            home = ghidra_home or os.environ.get("GHIDRA_HOME", "")
            cand = Path(home) / "support" / "analyzeHeadless" if home else None
            path = str(cand) if cand and cand.is_file() else path
        version = None
        if path and spec["version"]:
            try:
                proc = subprocess.run([path, *spec["version"]], stdin=subprocess.DEVNULL, capture_output=True,  # noqa: S603
                                      timeout=15, env=_minimal_env(), check=False)
                text = (proc.stdout or proc.stderr).decode("utf-8", "replace").strip().splitlines()
                version = text[0][:120] if text else None
            except Exception:
                version = None
        out[name] = ToolInfo(name=name, path=path, version=version, purpose=spec["purpose"], enabled=enabled)
    return out


_cache: dict[str, ToolInfo] | None = None


def detect_tools_cached(ghidra_home: str = "", enabled: bool = True) -> dict[str, ToolInfo]:
    global _cache
    if _cache is None:
        _cache = detect_tools(ghidra_home, enabled)
    return _cache


# ---------------------------------------------------------------------------- parsers
CAPA_CATEGORY = [
    ("host-interaction/process/inject", "injection"), ("load-code", "injection"), ("persistence", "persistence"),
    ("anti-analysis", "anti_analysis"), ("communication", "network"), ("collection", "collection"),
    ("host-interaction/process/create", "execution"), ("host-interaction/registry", "persistence"),
    ("host-interaction/file-system", "file_manipulation"), ("data-manipulation/encryption", "impact"),
    ("linking/runtime-linking", "packing"), ("executable", "structure"), ("targeting", "discovery"),
    ("host-interaction/credentials", "credential_access"), ("impact", "impact"), ("host-interaction", "discovery"),
]


def parse_capa(doc: dict[str, Any]) -> list[dict[str, Any]]:
    caps = []
    for name, rule in (doc.get("rules") or {}).items():
        meta = rule.get("meta", {}) if isinstance(rule, dict) else {}
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        ns = meta.get("namespace") or ""
        category = next((c for prefix, c in CAPA_CATEGORY if ns.startswith(prefix)), "info")
        attack = []
        for a in meta.get("attack", []) or []:
            if isinstance(a, dict) and a.get("id"):
                attack.append(a["id"])
            elif isinstance(a, str):
                tid = a.rsplit("[", 1)[-1].rstrip("]") if "[" in a else None
                if tid:
                    attack.append(tid)
        matches = rule.get("matches") if isinstance(rule, dict) else None
        caps.append({"name": meta.get("name", name), "namespace": ns, "category": category, "attack": attack,
                     "matches": len(matches) if isinstance(matches, (list, dict)) else None})
    return caps


def parse_floss(doc: dict[str, Any]) -> list[tuple[str, str]]:
    out = []
    strings = doc.get("strings") or {}
    for key in ("decoded_strings", "stack_strings", "tight_strings"):
        for item in strings.get(key, []) or []:
            s = item.get("string") if isinstance(item, dict) else item
            if isinstance(s, str) and len(s) >= 4:
                out.append((key, s))
    return out


# ---------------------------------------------------------------------------- runners
def run_capa(ctx: AnalysisContext, art: ArtifactContext, info: ToolInfo, timeout: int) -> None:
    with tempfile.TemporaryDirectory(prefix="malx-capa-") as tmp:
        try:
            proc = run_tool([info.path, "-j", str(art.path)], timeout=timeout, cwd=tmp)
        except subprocess.TimeoutExpired:
            ctx.limitation(f"capa timed out on {art.display_name}.")
            return
    if proc.returncode != 0 or not proc.stdout:
        ctx.limitation(f"capa failed on {art.display_name} (exit {proc.returncode}).")
        return
    try:
        doc = json.loads(proc.stdout[:MAX_OUTPUT])
    except json.JSONDecodeError:
        return
    caps = parse_capa(doc)
    art.metadata["capa"] = caps[:500]
    for c in caps[:200]:
        sev = "medium" if c["category"] in ("injection", "anti_analysis", "credential_access", "persistence") else "low"
        ctx.add_evidence(
            type="capa_capability", category=c["category"], source="capa", artifact=art,
            title=f"capa: {c['name']}", description=f"Capability identified by capa (namespace {c['namespace'] or 'n/a'}). "
            "Capabilities describe what code can do; legitimate software has many of them.",
            severity=sev, confidence=0.7, reliability="high", value=c["name"], mitre=c["attack"], details=c,
            rule_id=f"capa:{c['name']}",
        )


def run_floss(ctx: AnalysisContext, art: ArtifactContext, info: ToolInfo, timeout: int) -> None:
    with tempfile.TemporaryDirectory(prefix="malx-floss-") as tmp:
        try:
            proc = run_tool([info.path, "-j", "-q", str(art.path)], timeout=timeout, cwd=tmp)
        except subprocess.TimeoutExpired:
            ctx.limitation(f"FLOSS timed out on {art.display_name}.")
            return
    try:
        doc = json.loads(proc.stdout[:MAX_OUTPUT]) if proc.stdout else {}
    except json.JSONDecodeError:
        doc = {}
    found = parse_floss(doc)
    art.metadata["floss"] = {"decoded": len([f for f in found if f[0] == "decoded_strings"]),
                             "stack": len([f for f in found if f[0] == "stack_strings"]),
                             "tight": len([f for f in found if f[0] == "tight_strings"])}
    art.strings.extend(ExtractedString(0, f"floss-{k.split('_')[0]}", s[:4096], origin="floss") for k, s in found[:20000])
    art.invalidate_strings()
    if found:
        ctx.event(f"FLOSS recovered {len(found)} obfuscated strings", engine="floss", artifact_id=art.id)


def run_r2_decompile(ctx: AnalysisContext, art: ArtifactContext, info: ToolInfo, timeout: int, addresses: list[str]) -> dict[str, str]:
    """Best-effort pseudo-code via radare2 (requires r2ghidra 'pdg' or r2dec 'pdd')."""
    out: dict[str, str] = {}
    if not addresses:
        return out
    cmds = ["aaa"]
    for a in addresses[:20]:
        cmds.append(f"s {a}")
        cmds.append("pdg")
    with tempfile.TemporaryDirectory(prefix="malx-r2-") as tmp:
        try:
            proc = run_tool([info.path, "-q", "-2", "-e", "scr.color=0", "-e", "bin.cache=true", "-c", ";".join(cmds), str(art.path)],
                            timeout=timeout, cwd=tmp)
        except subprocess.TimeoutExpired:
            ctx.limitation("radare2 decompilation timed out.")
            return out
    text = proc.stdout.decode("utf-8", "replace")
    if "Unknown command" in text or not text.strip():
        return out
    chunks = text.split("\n// ")
    for a, chunk in zip(addresses, chunks):
        out[a] = chunk[:20000]
    return out


@lru_cache(maxsize=1)
def tools_summary(ghidra_home: str, enabled: bool) -> list[dict[str, Any]]:
    return [t.to_dict() for t in detect_tools(ghidra_home, enabled).values()]
