"""Database entities.

Mapping to the specification's entity list:

* Analysis, Report, Finding, Evidence, IOC, YaraMatch, Dependency, Vulnerability,
  MITRETechnique (``MitreMapping``) — dedicated tables.
* Sample / Artifact / File / Hash — ``Artifact`` (root samples have ``parent_id`` NULL;
  hashes are columns because SHA-256 is the primary identifier).
* String — ``StringRecord``.
* PEMetadata / ELFMetadata — structured JSON in ``Artifact.metadata_json``.
* NetworkIndicator / RegistryIndicator / ProcessIndicator — ``IOC`` rows by type and
  ``Evidence`` rows by category.
* RuleMatch — ``Evidence`` rows with ``rule_id`` set (heuristic engine).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    mode: Mapped[str] = mapped_column(String(16), default="auto")
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    stage_detail: Mapped[str | None] = mapped_column(String(300))
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    classification: Mapped[str | None] = mapped_column(String(32))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    main_type: Mapped[str | None] = mapped_column(String(120))
    root_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    artifact_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)

    risk_json: Mapped[dict | None] = mapped_column(JSON)
    summary_json: Mapped[dict | None] = mapped_column(JSON)
    appsec_json: Mapped[dict | None] = mapped_column(JSON)
    engines_json: Mapped[dict | None] = mapped_column(JSON)
    limitations_json: Mapped[list | None] = mapped_column(JSON)
    options_json: Mapped[dict | None] = mapped_column(JSON)  # never contains the archive password
    board_json: Mapped[dict | None] = mapped_column(JSON)

    artifacts: Mapped[list["Artifact"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[str | None] = mapped_column(String(32), index=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    display_name: Mapped[str] = mapped_column(String(300))
    path_in_archive: Mapped[str | None] = mapped_column(Text)
    storage_path: Mapped[str | None] = mapped_column(Text)  # relative to storage root; never served
    size: Mapped[int] = mapped_column(Integer, default=0)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    sha512: Mapped[str | None] = mapped_column(String(128))
    ssdeep: Mapped[str | None] = mapped_column(String(200))
    tlsh: Mapped[str | None] = mapped_column(String(80))
    imphash: Mapped[str | None] = mapped_column(String(32))
    detected_type: Mapped[str | None] = mapped_column(String(64))
    type_label: Mapped[str | None] = mapped_column(String(200))
    category: Mapped[str | None] = mapped_column(String(32))
    mime: Mapped[str | None] = mapped_column(String(100))
    confidence: Mapped[float | None] = mapped_column(Float)
    parser_used: Mapped[str | None] = mapped_column(String(100))
    extension: Mapped[str | None] = mapped_column(String(32))
    magic_hex: Mapped[str | None] = mapped_column(String(64))
    extension_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    entropy: Mapped[float | None] = mapped_column(Float)
    architecture: Mapped[str | None] = mapped_column(String(64))
    tags_json: Mapped[list | None] = mapped_column(JSON)
    metadata_json: Mapped[dict | None] = mapped_column(JSON)
    string_count: Mapped[int] = mapped_column(Integer, default=0)
    has_reverse: Mapped[bool] = mapped_column(Boolean, default=False)
    errors_json: Mapped[list | None] = mapped_column(JSON)

    analysis: Mapped[Analysis] = relationship(back_populates="artifacts")


class StringRecord(Base):
    __tablename__ = "strings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str] = mapped_column(String(32), index=True)
    offset: Mapped[int] = mapped_column(Integer)
    encoding: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(16), index=True)
    tags: Mapped[str | None] = mapped_column(String(200))


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ref: Mapped[str] = mapped_column(String(16))  # EV-0001, unique per analysis
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(32), index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(64))
    value: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    reliability: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    details_json: Mapped[dict | None] = mapped_column(JSON)
    rule_id: Mapped[str | None] = mapped_column(String(120))
    mitre_json: Mapped[list | None] = mapped_column(JSON)
    offset: Mapped[int | None] = mapped_column(Integer)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analyst_state: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    analyst_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_evidence_analysis_ref", "analysis_id", "ref", unique=True),)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(16), default="supporting")  # required|supporting|context


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ref: Mapped[str] = mapped_column(String(16))  # F-001
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(16))  # correlated|indicator|appsec|analyst
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    strength: Mapped[str] = mapped_column(String(16))
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    what: Mapped[str] = mapped_column(Text)
    where_json: Mapped[list | None] = mapped_column(JSON)
    why: Mapped[str] = mapped_column(Text)
    limitations_json: Mapped[list | None] = mapped_column(JSON)
    recommendation: Mapped[str | None] = mapped_column(Text)
    hypothesis: Mapped[str | None] = mapped_column(String(120))
    rule_id: Mapped[str | None] = mapped_column(String(120))
    mitre_json: Mapped[list | None] = mapped_column(JSON)
    cwe: Mapped[str | None] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    analyst_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(32))
    type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text, index=True)
    common: Mapped[bool] = mapped_column(Boolean, default=False)  # well-known/benign reference
    source: Mapped[str] = mapped_column(String(64))
    offset: Mapped[int | None] = mapped_column(Integer)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    evidence_ref: Mapped[str | None] = mapped_column(String(16))
    context: Mapped[str | None] = mapped_column(Text)


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(200))
    tactics_json: Mapped[list | None] = mapped_column(JSON)
    evidence_refs_json: Mapped[list | None] = mapped_column(JSON)
    finding_refs_json: Mapped[list | None] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    sources_json: Mapped[list | None] = mapped_column(JSON)


class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str] = mapped_column(String(32))
    rule: Mapped[str] = mapped_column(String(200))
    namespace: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(200))
    reference: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    tags_json: Mapped[list | None] = mapped_column(JSON)
    strings_json: Mapped[list | None] = mapped_column(JSON)
    evidence_ref: Mapped[str | None] = mapped_column(String(16))


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(32))
    ecosystem: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(300), index=True)
    version: Mapped[str | None] = mapped_column(String(120))
    version_spec: Mapped[str | None] = mapped_column(String(200))
    manifest: Mapped[str] = mapped_column(Text)
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    dev: Mapped[bool] = mapped_column(Boolean, default=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    dependency_id: Mapped[str] = mapped_column(String(32))
    advisory_id: Mapped[str] = mapped_column(String(120))
    aliases_json: Mapped[list | None] = mapped_column(JSON)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    affected_range: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(200))
    evidence_ref: Mapped[str | None] = mapped_column(String(16))


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    lane: Mapped[str] = mapped_column(String(16))  # pipeline|artifact
    event: Mapped[str] = mapped_column(String(300))
    engine: Mapped[str | None] = mapped_column(String(64))
    artifact_id: Mapped[str | None] = mapped_column(String(32))
    evidence_ref: Mapped[str | None] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(16))
    storage_path: Mapped[str] = mapped_column(Text)
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
