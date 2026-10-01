"""Ingest a worker ``result.json`` into the database (runs in the API process)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.core.security import new_id
from backend.models.entities import (
    IOC,
    Analysis,
    Artifact,
    Dependency,
    Evidence,
    Finding,
    FindingEvidence,
    MitreMapping,
    StringRecord,
    TimelineEvent,
    Vulnerability,
    YaraMatch,
)


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def clear_results(s: Session, analysis_id: str) -> None:
    for model in (FindingEvidence,):
        s.execute(delete(model).where(model.finding_id.in_(
            s.query(Finding.id).filter(Finding.analysis_id == analysis_id).scalar_subquery())))
    for model in (Finding, Evidence, IOC, MitreMapping, YaraMatch, Dependency, Vulnerability, TimelineEvent, StringRecord, Artifact):
        s.execute(delete(model).where(model.analysis_id == analysis_id))


def ingest(s: Session, analysis: Analysis, result: dict[str, Any], extra_timeline: list[dict[str, Any]] | None = None) -> None:
    aid = analysis.id
    clear_results(s, aid)
    root = None
    for a in result["artifacts"]:
        h = a.get("hashes") or {}
        art = Artifact(
            id=a["id"], analysis_id=aid, parent_id=a["parent_id"], depth=a["depth"], display_name=a["display_name"][:300],
            path_in_archive=a["path_in_archive"], storage_path=a["storage_rel"], size=a["size"],
            md5=h.get("md5"), sha1=h.get("sha1"), sha256=h.get("sha256"), sha512=h.get("sha512"),
            ssdeep=h.get("ssdeep"), tlsh=h.get("tlsh"), imphash=a.get("imphash"),
            detected_type=a["detected_type"], type_label=(a["type_label"] or "")[:200], category=a["category"], mime=a["mime"],
            confidence=a["confidence"], parser_used=a["parser"], extension=a["extension"], magic_hex=a["magic_hex"],
            extension_mismatch=a["extension_mismatch"], entropy=a["entropy"], architecture=a["architecture"],
            tags_json=a["tags"], string_count=a["string_count"], has_reverse=bool(a.get("reverse_path")),
            errors_json=a["errors"],
            metadata_json={**a["metadata"], "_identification": {"details": a["identification_details"],
                                                               "mismatch_reason": a["mismatch_reason"]},
                           "_entropy_profile": a["entropy_profile"], "_name_issues": a["name_issues"],
                           "_limitations": a["limitations"], "_reverse_path": a.get("reverse_path")},
        )
        s.add(art)
        if a["parent_id"] is None and root is None:
            root = a
        s.add_all(StringRecord(analysis_id=aid, artifact_id=a["id"], offset=x["offset"], encoding=x["encoding"],
                               value=x["value"], classification=x["classification"], tags=",".join(x["tags"])[:200] or None)
                  for x in a["strings"])
    ev_ids: dict[str, str] = {}
    for e in result["evidence"]:
        eid = new_id()
        ev_ids[e["ref"]] = eid
        s.add(Evidence(
            id=eid, ref=e["ref"], analysis_id=aid, artifact_id=e["artifact_id"], type=e["type"], category=e["category"],
            source=e["source"], value=e["value"], severity=e["severity"], confidence=e["confidence"], reliability=e["reliability"],
            title=e["title"], description=e["description"], details_json=e["details"], rule_id=e["rule_id"], mitre_json=e["mitre"],
            offset=e["offset"], observed_at=_dt(e["observed_at"]),
        ))
    s.flush()
    for f in result["findings"]:
        fid = new_id()
        s.add(Finding(
            id=fid, ref=f["ref"], analysis_id=aid, title=f["title"][:300], kind=f["kind"], category=f["category"],
            severity=f["severity"], confidence=f["confidence"], strength=f["strength"], needs_review=f["needs_review"],
            what=f["what"], where_json=f["where"], why=f["why"], limitations_json=f["limitations"],
            recommendation=f.get("recommendation"), hypothesis=f.get("hypothesis"), rule_id=f.get("rule_id"),
            mitre_json=f.get("mitre"), cwe=f.get("cwe"), score=f.get("score", 0.0),
        ))
        s.flush()
        seen = set()
        for link in f["evidence"]:
            eid = ev_ids.get(link["ref"])
            if eid and eid not in seen:
                seen.add(eid)
                s.add(FindingEvidence(finding_id=fid, evidence_id=eid, role=link["role"]))
    for i in result["iocs"]:
        s.add(IOC(analysis_id=aid, artifact_id=i["artifact_id"], type=i["type"], value=i["value"], normalized=i["normalized"],
                  common=i["common"], source=i["source"], offset=i["offset"], occurrences=i["occurrences"],
                  evidence_ref=i["evidence_ref"], context=i["context"]))
    for m in result["mitre"]:
        s.add(MitreMapping(analysis_id=aid, technique_id=m["technique_id"], name=m["name"], tactics_json=m["tactics"],
                           evidence_refs_json=m["evidence"], finding_refs_json=m["findings"], reason=m["reason"],
                           confidence=m["confidence"], sources_json=m["sources"]))
    for y in result["yara"]:
        s.add(YaraMatch(analysis_id=aid, artifact_id=y["artifact_id"], rule=y["rule"], namespace=y["namespace"],
                        description=y["description"], author=y["author"], reference=y["reference"], severity=y["severity"],
                        tags_json=y["tags"], strings_json=y["strings"], evidence_ref=y["evidence_ref"]))
    for d in result.get("dependencies") or []:
        s.add(Dependency(id=d["id"], analysis_id=aid, artifact_id=d["artifact_id"], ecosystem=d["ecosystem"], name=d["name"],
                         version=d["version"], version_spec=d["version_spec"], manifest=d["manifest"], direct=d["direct"], dev=d["dev"]))
    for v in result.get("vulnerabilities") or []:
        s.add(Vulnerability(analysis_id=aid, dependency_id=v["dependency_id"], advisory_id=v["advisory_id"], aliases_json=v["aliases"],
                            summary=v["summary"], severity=v["severity"], affected_range=v["affected_range"],
                            fixed_version=v["fixed_version"], source=v["source"], evidence_ref=v["evidence_ref"]))
    for t in (extra_timeline or []) + result["timeline"]:
        ts = _dt(t["ts"])
        if ts is None:
            continue
        s.add(TimelineEvent(analysis_id=aid, ts=ts, lane=t.get("lane", "pipeline"), event=t["event"][:300], engine=t.get("engine"),
                            artifact_id=t.get("artifact_id"), evidence_ref=t.get("evidence_ref"), detail=t.get("detail")))
    summary = result["summary"]
    analysis.classification = result["classification"]
    analysis.risk_score = result["risk"]["overall"]
    analysis.risk_json = result["risk"]
    analysis.summary_json = summary
    analysis.appsec_json = result.get("appsec") or None
    analysis.engines_json = {**result["engines"], "worker_hardening": result.get("worker_hardening"), "engine_version": result["engine_version"]}
    analysis.limitations_json = result["limitations"]
    analysis.artifact_count = len(result["artifacts"])
    analysis.finding_count = len(result["findings"])
    analysis.evidence_count = len(result["evidence"])
    analysis.ioc_count = sum(1 for i in result["iocs"] if not i["common"])
    if root:
        analysis.root_sha256 = (root.get("hashes") or {}).get("sha256")
        analysis.main_type = (root.get("type_label") or "")[:120]
