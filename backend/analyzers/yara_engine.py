"""YARA engine. Rules come from ``rules/yara/**/*.yar``; matches become evidence."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .base import AnalysisContext, ArtifactContext

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None

MAX_INSTANCES = 16


class YaraEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.available = yara is not None
        self.errors: list[str] = []
        self.rule_count = 0
        self.rules = None
        if not self.available:
            return
        files = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")]) if rules_dir.is_dir() else []
        good: dict[str, str] = {}
        for f in files:
            ns = f.relative_to(rules_dir).as_posix().rsplit(".", 1)[0].replace("/", "_")
            try:
                compiled = yara.compile(filepath=str(f))
                good[ns] = str(f)
                self.rule_count += sum(1 for _ in compiled)
            except yara.Error as exc:
                self.errors.append(f"{f.name}: {exc}")
        if good:
            self.rules = yara.compile(filepaths=good)

    @property
    def version(self) -> str | None:
        return getattr(yara, "__version__", None) if yara else None

    def scan(self, ctx: AnalysisContext, art: ArtifactContext, timeout: int = 60) -> list[dict[str, Any]]:
        if not self.rules or art.size == 0:
            return []
        if art.size > ctx.limits.max_deep_scan_size:
            ctx.limitation(f"{art.display_name}: YARA scan limited — file larger than max_deep_scan_size.")
            with open(art.path, "rb") as fh:
                data = fh.read(ctx.limits.max_deep_scan_size)
            matches = self.rules.match(data=data, timeout=timeout)
        else:
            matches = self.rules.match(str(art.path), timeout=timeout)
        out = []
        for m in matches:
            meta = dict(m.meta)
            strings = []
            for s in m.strings:
                instances = getattr(s, "instances", None)
                if instances is None:  # yara-python < 4.3 tuple format
                    off, ident, data = s
                    strings.append({"identifier": ident, "offset": off, "data": data[:64].hex()})
                    continue
                for inst in instances[:MAX_INSTANCES]:
                    strings.append({
                        "identifier": s.identifier, "offset": inst.offset,
                        "data": bytes(inst.matched_data[:64]).decode("latin-1").encode("unicode_escape").decode("ascii")[:160],
                    })
                if len(strings) >= MAX_INSTANCES * 4:
                    break
            sev = str(meta.get("severity", "medium")).lower()
            mitre = [t.strip() for t in str(meta.get("mitre", "")).split(",") if t.strip()]
            try:
                conf = float(meta.get("confidence", 0.7))
            except (TypeError, ValueError):
                conf = 0.7
            ev = ctx.add_evidence(
                type="yara_match", category=str(meta.get("category", "yara")), source="yara_engine", artifact=art,
                title=f"YARA rule {m.rule} matched",
                description=str(meta.get("description", "YARA rule matched")) + ". A YARA match is one observation; it is weighed with other evidence.",
                severity=sev, confidence=conf, reliability=str(meta.get("reliability", "medium")),
                value=m.rule, rule_id=f"yara:{m.namespace}:{m.rule}", mitre=mitre,
                offset=strings[0]["offset"] if strings else None,
                details={"namespace": m.namespace, "tags": list(m.tags), "meta": {k: str(v)[:300] for k, v in meta.items()},
                         "strings": strings[:24]},
            )
            rec = {
                "artifact_id": art.id, "rule": m.rule, "namespace": m.namespace,
                "description": str(meta.get("description", ""))[:500], "author": str(meta.get("author", ""))[:200],
                "reference": str(meta.get("reference", ""))[:500], "severity": sev, "tags": list(m.tags),
                "strings": strings[:48], "evidence_ref": ev.ref,
            }
            ctx.yara_matches.append(rec)
            out.append(rec)
            ctx.event(f"YARA match {m.rule}", engine="yara_engine", artifact_id=art.id, evidence_ref=ev.ref)
        return out


@lru_cache(maxsize=2)
def get_yara_engine(rules_dir: str) -> YaraEngine:
    return YaraEngine(Path(rules_dir))
