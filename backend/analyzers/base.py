"""Worker-side domain model: the analysis context every engine reads and writes.

Everything an engine concludes is recorded as structured :class:`EvidenceItem`
objects. Nothing downstream (findings, risk, MITRE, reports) is allowed to
invent conclusions that are not backed by evidence references.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.core.config import Limits
from backend.core.enums import Reliability, Severity, StringClass


class AnalysisTimeout(Exception):
    pass


class AnalysisCancelled(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Identification:
    detected_type: str
    label: str
    category: str
    mime: str
    confidence: float
    parser: str
    magic_hex: str
    extension: str
    extension_mismatch: bool = False
    mismatch_reason: str | None = None
    architecture: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedString:
    offset: int
    encoding: str
    value: str
    classification: StringClass = StringClass.NORMAL
    tags: list[str] = field(default_factory=list)
    origin: str = "file"  # file | decoded | floss | resource


@dataclass
class EvidenceItem:
    ref: str
    type: str
    category: str
    source: str
    artifact_id: str | None
    value: str | None
    severity: Severity
    confidence: float
    reliability: Reliability
    title: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    rule_id: str | None = None
    mitre: list[str] = field(default_factory=list)
    offset: int | None = None
    observed_at: str = field(default_factory=now_iso)

    @property
    def weight(self) -> float:
        return self.severity.weight * self.confidence * self.reliability.factor

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["reliability"] = self.reliability.value
        return d


@dataclass
class IOCItem:
    type: str
    value: str
    normalized: str
    artifact_id: str | None
    source: str
    offset: int | None = None
    occurrences: int = 1
    common: bool = False
    evidence_ref: str | None = None
    context: str | None = None
    enrich: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArtifactContext:
    id: str
    path: Path
    storage_rel: str
    display_name: str
    size: int
    parent_id: str | None = None
    depth: int = 0
    path_in_archive: str | None = None
    name_issues: list[str] = field(default_factory=list)
    ident: Identification | None = None
    hashes: dict[str, str | None] = field(default_factory=dict)
    imphash: str | None = None
    entropy: float | None = None
    entropy_profile: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    strings: list[ExtractedString] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)        # lower-case API names
    import_dlls: set[str] = field(default_factory=set)    # lower-case library names
    exports: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    reverse_path: str | None = None
    children: list[str] = field(default_factory=list)
    _lower_strings: list[str] | None = None

    @property
    def category(self) -> str:
        return self.ident.category if self.ident else "unknown"

    @property
    def detected_type(self) -> str:
        return self.ident.detected_type if self.ident else "unknown"

    def lower_strings(self) -> list[str]:
        if self._lower_strings is None:
            self._lower_strings = [s.value.lower() for s in self.strings]
        return self._lower_strings

    def invalidate_strings(self) -> None:
        self._lower_strings = None


ProgressFn = Callable[[str, int, str | None], None]


class AnalysisContext:
    """State of one analysis inside the isolated worker."""

    def __init__(
        self,
        analysis_id: str,
        limits: Limits,
        storage_root: Path,
        mode: str = "auto",
        password: str | None = None,
        progress: ProgressFn | None = None,
        cancel_check: Callable[[], bool] | None = None,
        tools: Any = None,
    ):
        self.analysis_id = analysis_id
        self.limits = limits
        self.storage_root = storage_root
        self.mode = mode
        self._password = password  # in memory only, never serialised
        self._progress = progress
        self._cancel_check = cancel_check
        self.tools = tools
        self.started = time.monotonic()
        self.deadline = self.started + limits.max_analysis_time
        self.artifacts: list[ArtifactContext] = []
        self.by_id: dict[str, ArtifactContext] = {}
        self.evidence: list[EvidenceItem] = []
        self._evidence_keys: dict[tuple, EvidenceItem] = {}
        self.iocs: dict[tuple[str, str], IOCItem] = {}
        self.yara_matches: list[dict[str, Any]] = []
        self.dependencies: list[dict[str, Any]] = []
        self.vulnerabilities: list[dict[str, Any]] = []
        self.appsec: dict[str, Any] = {}
        self.timeline: list[dict[str, Any]] = []
        self.engines: dict[str, dict[str, Any]] = {}
        self.limitations: list[str] = []
        self.extracted_bytes = 0
        self.findings: list[dict[str, Any]] = []
        self.risk: dict[str, Any] = {}
        self.mitre: list[dict[str, Any]] = []
        self.summary: dict[str, Any] = {}
        self.classification: str = "UNKNOWN"

    # ---- control -------------------------------------------------------------------
    @property
    def password(self) -> str | None:
        return self._password

    def check(self) -> None:
        if self._cancel_check and self._cancel_check():
            raise AnalysisCancelled()
        if time.monotonic() > self.deadline:
            raise AnalysisTimeout(f"analysis exceeded max_analysis_time ({self.limits.max_analysis_time}s)")

    def progress(self, stage: str, percent: int, detail: str | None = None) -> None:
        if self._progress:
            self._progress(stage, percent, detail)

    def event(self, event: str, engine: str | None = None, artifact_id: str | None = None,
              evidence_ref: str | None = None, detail: str | None = None, lane: str = "pipeline",
              ts: str | None = None) -> None:
        self.timeline.append({
            "ts": ts or now_iso(), "lane": lane, "event": event, "engine": engine,
            "artifact_id": artifact_id, "evidence_ref": evidence_ref, "detail": detail,
        })

    def engine_status(self, name: str, status: str, **info: Any) -> None:
        entry = self.engines.setdefault(name, {})
        entry.update({"status": status, **info})

    def limitation(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    # ---- artifacts -----------------------------------------------------------------
    def add_artifact(self, art: ArtifactContext) -> ArtifactContext:
        self.artifacts.append(art)
        self.by_id[art.id] = art
        if art.parent_id and art.parent_id in self.by_id:
            self.by_id[art.parent_id].children.append(art.id)
        return art

    @property
    def roots(self) -> list[ArtifactContext]:
        return [a for a in self.artifacts if a.parent_id is None]

    # ---- evidence ------------------------------------------------------------------
    def add_evidence(
        self,
        *,
        type: str,
        category: str,
        source: str,
        title: str,
        description: str,
        artifact: ArtifactContext | None = None,
        value: Any = None,
        severity: Severity | str = Severity.INFO,
        confidence: float = 0.5,
        reliability: Reliability | str = Reliability.MEDIUM,
        details: dict[str, Any] | None = None,
        rule_id: str | None = None,
        mitre: list[str] | None = None,
        offset: int | None = None,
        dedupe_key: tuple | None = None,
    ) -> EvidenceItem:
        key = dedupe_key or (type, artifact.id if artifact else None, str(value)[:500], rule_id)
        if key in self._evidence_keys:
            existing = self._evidence_keys[key]
            existing.confidence = max(existing.confidence, float(confidence))
            return existing
        item = EvidenceItem(
            ref=f"EV-{len(self.evidence) + 1:04d}",
            type=type,
            category=category,
            source=source,
            artifact_id=artifact.id if artifact else None,
            value=None if value is None else str(value)[:2000],
            severity=Severity.parse(severity),
            confidence=round(max(0.0, min(1.0, float(confidence))), 3),
            reliability=Reliability.parse(reliability),
            title=title[:300],
            description=description,
            details=details or {},
            rule_id=rule_id,
            mitre=list(mitre or []),
            offset=offset,
        )
        self.evidence.append(item)
        self._evidence_keys[key] = item
        return item

    def evidence_for(self, artifact_id: str) -> list[EvidenceItem]:
        return [e for e in self.evidence if e.artifact_id == artifact_id]

    def add_ioc(self, item: IOCItem) -> IOCItem:
        key = (item.type, item.normalized)
        existing = self.iocs.get(key)
        if existing:
            existing.occurrences += item.occurrences
            return existing
        self.iocs[key] = item
        return item
