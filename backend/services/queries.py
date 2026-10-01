"""Read-side models shared by the API and the report engine."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.core.storage import Storage
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

ENGINE_LABELS = {
    "identification": "Identification", "archive_analyzer": "Archive Analyzer", "pe_analyzer": "PE Analyzer",
    "elf_analyzer": "ELF Analyzer", "macho_analyzer": "Mach-O Analyzer", "pdf_analyzer": "PDF Analyzer",
    "ooxml_analyzer": "OOXML Analyzer", "ole_analyzer": "OLE/VBA Analyzer", "rtf_analyzer": "RTF Analyzer",
    "lnk_analyzer": "LNK Analyzer", "apk_analyzer": "APK Analyzer", "dex_analyzer": "DEX Analyzer",
    "java_analyzer": "Java Analyzer", "script_analyzer": "Script Analyzer", "string_analyzer": "String Analyzer",
    "ioc_engine": "IOC Engine", "yara_engine": "YARA", "heuristic_engine": "Heuristic Engine",
    "reverse_engine": "Reverse Engine", "capa": "capa", "appsec_engine": "AppSec Engine",
    "secret_scanner": "Secret Scanner", "dependency_scanner": "Dependency Scanner",
}
RELATIONSHIPS = {
    "suspicious_import": "imports", "yara_match": "matches", "string_signature": "strings", "network_indicator": "references",
    "heuristic_match": "triggers", "reverse_api_sequence": "calls", "capa_capability": "capability",
    "exposed_secret": "contains", "code_weakness": "contains", "vulnerable_dependency": "depends_on",
}


def iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def analysis_summary(a: Analysis) -> dict[str, Any]:
    return {
        "id": a.id, "name": a.name, "mode": a.mode, "status": a.status, "progress": a.progress, "stage_detail": a.stage_detail,
        "error": a.error, "created_at": iso(a.created_at), "started_at": iso(a.started_at), "completed_at": iso(a.completed_at),
        "duration_ms": a.duration_ms, "classification": a.classification, "risk_score": a.risk_score, "main_type": a.main_type,
        "sha256": a.root_sha256, "artifact_count": a.artifact_count, "finding_count": a.finding_count,
        "evidence_count": a.evidence_count, "ioc_count": a.ioc_count, "notes": a.notes,
    }


def analysis_detail(s: Session, a: Analysis) -> dict[str, Any]:
    d = analysis_summary(a)
    d.update({
        "risk": a.risk_json, "summary": a.summary_json, "engines": a.engines_json, "limitations": a.limitations_json or [],
        "files": [{"name": f.get("display_name"), "size": f.get("size")} for f in (a.options_json or {}).get("files", [])],
        "has_appsec": bool(a.appsec_json and a.appsec_json.get("enabled")),
    })
    d["artifacts"] = [artifact_brief(x) for x in s.query(Artifact).filter(Artifact.analysis_id == a.id).order_by(Artifact.depth, Artifact.display_name)]
    d["severity_counts"] = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for sev, n in s.query(Finding.severity, func.count()).filter(Finding.analysis_id == a.id).group_by(Finding.severity):
        d["severity_counts"][sev] = n
    return d


def artifact_brief(x: Artifact) -> dict[str, Any]:
    return {
        "id": x.id, "parent_id": x.parent_id, "depth": x.depth, "name": x.display_name, "path_in_archive": x.path_in_archive,
        "size": x.size, "sha256": x.sha256, "detected_type": x.detected_type, "type_label": x.type_label, "category": x.category,
        "extension_mismatch": x.extension_mismatch, "entropy": x.entropy, "architecture": x.architecture,
        "tags": x.tags_json or [], "has_reverse": x.has_reverse, "string_count": x.string_count,
    }


def artifact_detail(x: Artifact) -> dict[str, Any]:
    meta = dict(x.metadata_json or {})
    ident = meta.pop("_identification", {})
    d = artifact_brief(x)
    d.update({
        "hashes": {"md5": x.md5, "sha1": x.sha1, "sha256": x.sha256, "sha512": x.sha512, "ssdeep": x.ssdeep, "tlsh": x.tlsh,
                   "imphash": x.imphash},
        "identification": {"detected_type": x.detected_type, "label": x.type_label, "category": x.category, "mime": x.mime,
                           "confidence": x.confidence, "parser": x.parser_used, "extension": x.extension, "magic_hex": x.magic_hex,
                           "size": x.size, "sha256": x.sha256, "extension_mismatch": x.extension_mismatch,
                           "mismatch_reason": ident.get("mismatch_reason"), "details": ident.get("details", {})},
        "entropy_profile": meta.pop("_entropy_profile", []), "name_issues": meta.pop("_name_issues", []),
        "limitations": meta.pop("_limitations", []), "errors": x.errors_json or [],
        "metadata": {k: v for k, v in meta.items() if not k.startswith("_")},
    })
    return d


def evidence_dict(e: Evidence, finding_refs: list[str] | None = None, artifact_names: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "id": e.ref, "uid": e.id, "type": e.type, "category": e.category, "source": e.source,
        "source_label": ENGINE_LABELS.get(e.source, e.source), "artifact_id": e.artifact_id,
        "artifact": (artifact_names or {}).get(e.artifact_id or "", None), "value": e.value, "severity": e.severity,
        "confidence": e.confidence, "reliability": e.reliability, "title": e.title, "description": e.description,
        "details": e.details_json or {}, "rule_id": e.rule_id, "mitre": e.mitre_json or [], "offset": e.offset,
        "observed_at": iso(e.observed_at), "analyst_state": e.analyst_state, "analyst_note": e.analyst_note,
        "related_findings": finding_refs or [],
    }


def evidence_list(s: Session, analysis_id: str) -> list[dict[str, Any]]:
    names = {a.id: a.display_name for a in s.query(Artifact.id, Artifact.display_name).filter(Artifact.analysis_id == analysis_id)}
    links: dict[str, list[str]] = defaultdict(list)
    for fe, fref in s.query(FindingEvidence, Finding.ref).join(Finding, Finding.id == FindingEvidence.finding_id).filter(Finding.analysis_id == analysis_id):
        links[fe.evidence_id].append(fref)
    rows = s.query(Evidence).filter(Evidence.analysis_id == analysis_id).order_by(Evidence.ref).all()
    return [evidence_dict(e, sorted(links.get(e.id, [])), names) for e in rows]


def findings_list(s: Session, analysis_id: str) -> list[dict[str, Any]]:
    ev = {e.id: e for e in s.query(Evidence).filter(Evidence.analysis_id == analysis_id)}
    links: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for fe in s.query(FindingEvidence).join(Finding, Finding.id == FindingEvidence.finding_id).filter(Finding.analysis_id == analysis_id):
        links[fe.finding_id].append((fe.evidence_id, fe.role))
    out = []
    for f in s.query(Finding).filter(Finding.analysis_id == analysis_id).order_by(Finding.score.desc(), Finding.ref):
        items = []
        for eid, role in links.get(f.id, []):
            e = ev.get(eid)
            if e:
                items.append({"id": e.ref, "role": role, "title": e.title, "severity": e.severity, "source": e.source,
                              "source_label": ENGINE_LABELS.get(e.source, e.source), "confidence": e.confidence,
                              "value": e.value, "type": e.type, "category": e.category})
        items.sort(key=lambda i: ({"required": 0, "supporting": 1, "context": 2}.get(i["role"], 3), i["id"]))
        out.append({
            "id": f.ref, "uid": f.id, "title": f.title, "kind": f.kind, "category": f.category, "severity": f.severity,
            "confidence": f.confidence, "strength": f.strength, "needs_review": f.needs_review, "what": f.what,
            "where": f.where_json or [], "why": f.why, "limitations": f.limitations_json or [], "recommendation": f.recommendation,
            "hypothesis": f.hypothesis, "rule_id": f.rule_id, "mitre": f.mitre_json or [], "cwe": f.cwe, "score": f.score,
            "status": f.status, "analyst_note": f.analyst_note, "evidence": items,
            "sources": sorted({i["source_label"] for i in items}),
        })
    return out


def iocs_list(s: Session, analysis_id: str | None = None, types: list[str] | None = None, q: str | None = None,
              include_common: bool = True, limit: int = 5000) -> list[dict[str, Any]]:
    query = s.query(IOC, Analysis.name).join(Analysis, Analysis.id == IOC.analysis_id)
    if analysis_id:
        query = query.filter(IOC.analysis_id == analysis_id)
    if types:
        query = query.filter(IOC.type.in_(types))
    if q:
        query = query.filter(IOC.normalized.like(f"%{q.lower()}%"))
    if not include_common:
        query = query.filter(IOC.common.is_(False))
    out = []
    for i, aname in query.order_by(IOC.type, IOC.normalized).limit(limit):
        out.append({"type": i.type, "value": i.value, "normalized": i.normalized, "common": i.common, "source": i.source,
                    "artifact_id": i.artifact_id, "offset": i.offset, "occurrences": i.occurrences,
                    "evidence_ref": i.evidence_ref, "context": i.context, "analysis_id": i.analysis_id, "analysis_name": aname})
    return out


def mitre_list(s: Session, analysis_id: str) -> list[dict[str, Any]]:
    return [{"technique_id": m.technique_id, "name": m.name, "tactics": m.tactics_json or [], "evidence": m.evidence_refs_json or [],
             "findings": m.finding_refs_json or [], "reason": m.reason, "confidence": m.confidence, "sources": m.sources_json or [],
             "url": f"https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}/"}
            for m in s.query(MitreMapping).filter(MitreMapping.analysis_id == analysis_id).order_by(MitreMapping.confidence.desc())]


def yara_list(s: Session, analysis_id: str) -> list[dict[str, Any]]:
    return [{"artifact_id": y.artifact_id, "rule": y.rule, "namespace": y.namespace, "description": y.description,
             "author": y.author, "reference": y.reference, "severity": y.severity, "tags": y.tags_json or [],
             "strings": y.strings_json or [], "evidence_ref": y.evidence_ref}
            for y in s.query(YaraMatch).filter(YaraMatch.analysis_id == analysis_id)]


def timeline_list(s: Session, analysis_id: str) -> list[dict[str, Any]]:
    return [{"ts": iso(t.ts), "lane": t.lane, "event": t.event, "engine": t.engine, "artifact_id": t.artifact_id,
             "evidence_ref": t.evidence_ref, "detail": t.detail}
            for t in s.query(TimelineEvent).filter(TimelineEvent.analysis_id == analysis_id).order_by(TimelineEvent.ts, TimelineEvent.id)]


def strings_page(s: Session, analysis_id: str, artifact_id: str, classification: str | None, q: str | None,
                 offset: int, limit: int) -> dict[str, Any]:
    query = s.query(StringRecord).filter(StringRecord.analysis_id == analysis_id, StringRecord.artifact_id == artifact_id)
    if classification:
        query = query.filter(StringRecord.classification == classification)
    if q:
        query = query.filter(StringRecord.value.like(f"%{q}%"))
    total = query.count()
    rows = query.order_by(StringRecord.id).offset(offset).limit(limit).all()
    counts = dict(s.query(StringRecord.classification, func.count()).filter(
        StringRecord.analysis_id == analysis_id, StringRecord.artifact_id == artifact_id).group_by(StringRecord.classification))
    return {"total": total, "counts": counts, "items": [{"offset": r.offset, "encoding": r.encoding, "value": r.value,
                                                         "classification": r.classification, "tags": (r.tags or "").split(",") if r.tags else []} for r in rows]}


def appsec_view(s: Session, a: Analysis) -> dict[str, Any]:
    data = dict(a.appsec_json or {})
    data["dependencies"] = [{"id": d.id, "ecosystem": d.ecosystem, "name": d.name, "version": d.version, "version_spec": d.version_spec,
                             "manifest": d.manifest, "direct": d.direct, "dev": d.dev}
                            for d in s.query(Dependency).filter(Dependency.analysis_id == a.id).order_by(Dependency.name)]
    data["vulnerabilities"] = [{"dependency_id": v.dependency_id, "advisory_id": v.advisory_id, "aliases": v.aliases_json or [],
                                "summary": v.summary, "severity": v.severity, "affected_range": v.affected_range,
                                "fixed_version": v.fixed_version, "source": v.source, "evidence_ref": v.evidence_ref}
                               for v in s.query(Vulnerability).filter(Vulnerability.analysis_id == a.id)]
    data["code_findings"] = [f for f in findings_list(s, a.id) if f["kind"] == "appsec"]
    return data


# --------------------------------------------------------------------------- graph
def build_graph(s: Session, a: Analysis, include_weak: bool = False) -> dict[str, Any]:
    arts = s.query(Artifact).filter(Artifact.analysis_id == a.id).all()
    evs = s.query(Evidence).filter(Evidence.analysis_id == a.id).all()
    finds = s.query(Finding).filter(Finding.analysis_id == a.id).all()
    links = s.query(FindingEvidence).join(Finding, Finding.id == FindingEvidence.finding_id).filter(Finding.analysis_id == a.id).all()
    linked_ev = {l.evidence_id for l in links}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for x in arts:
        nodes.append({"id": f"art:{x.id}", "type": "sample" if x.parent_id is None else "artifact", "layer": 0 if x.parent_id is None else 1,
                      "label": x.display_name, "sublabel": x.type_label, "ref": x.id, "severity": None})
        if x.parent_id:
            edges.append({"source": f"art:{x.parent_id}", "target": f"art:{x.id}", "relationship": "contains", "evidence_id": None, "confidence": 1.0})
    engines: set[str] = set()
    for e in evs:
        if not include_weak and e.id not in linked_ev and e.severity in ("info",):
            continue
        if not include_weak and e.id not in linked_ev and e.severity == "low" and e.source not in ("yara_engine", "heuristic_engine"):
            continue
        art_node = f"art:{e.artifact_id}" if e.artifact_id else None
        eng = f"eng:{e.artifact_id}:{e.source}"
        if eng not in engines:
            engines.add(eng)
            nodes.append({"id": eng, "type": "engine", "layer": 2, "label": ENGINE_LABELS.get(e.source, e.source), "ref": e.source, "severity": None})
            if art_node:
                edges.append({"source": art_node, "target": eng, "relationship": "analyzed_by", "evidence_id": None, "confidence": 1.0})
        nodes.append({"id": f"ev:{e.ref}", "type": "evidence", "layer": 3, "label": e.title[:80], "sublabel": (e.value or "")[:80],
                      "ref": e.ref, "severity": e.severity, "category": e.category})
        edges.append({"source": eng, "target": f"ev:{e.ref}", "relationship": RELATIONSHIPS.get(e.type, "observed"),
                      "evidence_id": e.ref, "confidence": e.confidence})
    present = {n["id"] for n in nodes}
    ev_by_id = {e.id: e for e in evs}
    techniques: dict[str, str] = {}
    for m in s.query(MitreMapping).filter(MitreMapping.analysis_id == a.id):
        techniques[m.technique_id] = m.name
    for f in finds:
        if not include_weak and f.strength == "weak" and f.kind != "correlated":
            continue
        fid = f"f:{f.ref}"
        nodes.append({"id": fid, "type": "finding", "layer": 4, "label": f.title[:90], "sublabel": f"{f.strength} · {f.confidence:.0%}",
                      "ref": f.ref, "severity": f.severity})
        for l in links:
            if l.finding_id != f.id:
                continue
            e = ev_by_id.get(l.evidence_id)
            if e and f"ev:{e.ref}" in present:
                edges.append({"source": f"ev:{e.ref}", "target": fid, "relationship": "supports" if l.role != "context" else "context",
                              "evidence_id": e.ref, "confidence": e.confidence})
        for t in (f.mitre_json or []):
            if t in techniques:
                tid = f"t:{t}"
                if tid not in present:
                    present.add(tid)
                    nodes.append({"id": tid, "type": "mitre", "layer": 5, "label": t, "sublabel": techniques[t][:60], "ref": t, "severity": None})
                edges.append({"source": fid, "target": tid, "relationship": "maps_to", "evidence_id": None, "confidence": f.confidence})
    if a.classification:
        nodes.append({"id": "classification", "type": "classification", "layer": 6, "label": a.classification.replace("_", " "),
                      "sublabel": f"risk {a.risk_score}", "ref": a.classification, "severity": None})
        for f in finds:
            if f.kind == "correlated" and f"f:{f.ref}" in {n["id"] for n in nodes}:
                edges.append({"source": f"f:{f.ref}", "target": "classification", "relationship": "concludes", "evidence_id": None,
                              "confidence": f.confidence})
    return {"nodes": nodes, "edges": edges}


def chain_for_finding(s: Session, a: Analysis, ref: str) -> dict[str, Any] | None:
    """Sample → Parser → Observation → Heuristic → Correlation → Finding → Classification."""
    f = s.query(Finding).filter(Finding.analysis_id == a.id, Finding.ref == ref).one_or_none()
    if f is None:
        return None
    links = s.query(FindingEvidence, Evidence).join(Evidence, Evidence.id == FindingEvidence.evidence_id).filter(FindingEvidence.finding_id == f.id).all()
    names = {x.id: x.display_name for x in s.query(Artifact).filter(Artifact.analysis_id == a.id)}
    observations = [e for _, e in links if e.source != "heuristic_engine"]
    heuristics_ = [e for _, e in links if e.source == "heuristic_engine"]
    return {
        "finding": {"id": f.ref, "title": f.title, "severity": f.severity, "confidence": f.confidence},
        "stages": [
            {"stage": "Sample", "items": sorted({names.get(e.artifact_id, "?") for _, e in links})},
            {"stage": "Parser", "items": sorted({ENGINE_LABELS.get(e.source, e.source) for e in observations})},
            {"stage": "Observation", "items": [{"id": e.ref, "title": e.title} for e in observations]},
            {"stage": "Heuristic", "items": [{"id": e.ref, "title": e.title, "rule": e.rule_id} for e in heuristics_]},
            {"stage": "Correlation", "items": [f.rule_id or f.kind]},
            {"stage": "Finding", "items": [{"id": f.ref, "title": f.title}]},
            {"stage": "Classification", "items": [a.classification]},
        ],
    }


def reverse_data(storage: Storage, x: Artifact) -> dict[str, Any] | None:
    rel = (x.metadata_json or {}).get("_reverse_path")
    if not rel:
        return None
    path = storage.resolve_relative(rel)
    if not path.is_file():
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def search(s: Session, q: str, limit: int = 30) -> dict[str, list[dict[str, Any]]]:
    like = f"%{q}%"
    low = f"%{q.lower()}%"
    res: dict[str, list[dict[str, Any]]] = {}
    res["analyses"] = [{"id": a.id, "name": a.name, "classification": a.classification, "sha256": a.root_sha256}
                       for a in s.query(Analysis).filter(or_(Analysis.name.like(like), Analysis.root_sha256.like(low))).limit(limit)]
    res["artifacts"] = [{"analysis_id": x.analysis_id, "id": x.id, "name": x.display_name, "sha256": x.sha256, "type": x.type_label}
                        for x in s.query(Artifact).filter(or_(Artifact.display_name.like(like), Artifact.sha256.like(low),
                                                              Artifact.md5.like(low), Artifact.sha1.like(low), Artifact.imphash.like(low))).limit(limit)]
    res["iocs"] = [{"analysis_id": i.analysis_id, "type": i.type, "value": i.value}
                   for i in s.query(IOC).filter(IOC.normalized.like(low)).limit(limit)]
    res["findings"] = [{"analysis_id": f.analysis_id, "id": f.ref, "title": f.title, "severity": f.severity}
                       for f in s.query(Finding).filter(Finding.title.like(like)).limit(limit)]
    res["evidence"] = [{"analysis_id": e.analysis_id, "id": e.ref, "title": e.title, "severity": e.severity, "value": (e.value or "")[:120]}
                       for e in s.query(Evidence).filter(or_(Evidence.title.like(like), Evidence.value.like(like))).limit(limit)]
    res["mitre"] = [{"analysis_id": m.analysis_id, "technique_id": m.technique_id, "name": m.name}
                    for m in s.query(MitreMapping).filter(or_(MitreMapping.technique_id.like(like), MitreMapping.name.like(like))).limit(limit)]
    res["strings"] = [{"analysis_id": r.analysis_id, "artifact_id": r.artifact_id, "value": r.value[:200], "classification": r.classification}
                      for r in s.query(StringRecord).filter(StringRecord.value.like(like)).limit(limit)]
    return res
