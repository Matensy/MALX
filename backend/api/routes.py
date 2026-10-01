"""REST API (``/api``)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.core.database import get_session
from backend.core.enums import AnalysisMode, AnalysisStatus, AnalystState
from backend.core.logging import get_logger, log_event
from backend.core.security import is_valid_id, new_id
from backend.core.storage import read_range
from backend.models.entities import Analysis, Artifact, Evidence, Finding, FindingEvidence, Report
from backend.services import queries

from .upload import receive_upload

router = APIRouter(prefix="/api")
log = get_logger("api")


def _state(request: Request):
    return request.app.state.malx


def _analysis(s: Session, analysis_id: str) -> Analysis:
    if not is_valid_id(analysis_id):
        raise HTTPException(404, "analysis not found")
    a = s.get(Analysis, analysis_id)
    if a is None:
        raise HTTPException(404, "analysis not found")
    return a


def _artifact(s: Session, a: Analysis, artifact_id: str) -> Artifact:
    if not is_valid_id(artifact_id):
        raise HTTPException(404, "artifact not found")
    x = s.get(Artifact, artifact_id)
    if x is None or x.analysis_id != a.id:
        raise HTTPException(404, "artifact not found")
    return x


# --------------------------------------------------------------------------- system
@router.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@router.get("/system")
def system(request: Request):
    st = _state(request)
    return st.system_info()


@router.get("/rules")
def rules(request: Request):
    pack = _state(request).rule_pack()
    return {
        "counts": pack.counts(), "errors": pack.errors,
        "heuristics": [{"id": r["id"], "name": r["name"], "category": r.get("category"), "severity": r["severity"],
                        "mitre": r.get("mitre", []), "file": r.get("_file")} for r in pack.heuristics],
        "correlations": [{"id": r["id"], "title": r["title"], "severity": r.get("severity"), "hypothesis": r.get("hypothesis")}
                         for r in pack.correlations],
    }


@router.get("/stats")
def stats(s: Session = Depends(get_session)):
    by_status = dict(s.query(Analysis.status, func.count()).group_by(Analysis.status))
    by_class = dict(s.query(Analysis.classification, func.count()).filter(Analysis.classification.isnot(None)).group_by(Analysis.classification))
    by_sev = dict(s.query(Finding.severity, func.count()).group_by(Finding.severity))
    return {"analyses": sum(by_status.values()), "by_status": by_status, "by_classification": by_class,
            "findings_by_severity": by_sev, "evidence": s.query(func.count(Evidence.id)).scalar()}


# --------------------------------------------------------------------------- analyses
@router.post("/analyses", status_code=201)
async def create_analysis(request: Request):
    st = _state(request)
    aid = new_id()
    upload = await receive_upload(request, st.storage, aid, st.settings)
    fields = upload.fields
    mode = fields.get("mode", "auto").strip().lower() or "auto"
    if mode not in {m.value for m in AnalysisMode}:
        st.storage.purge_analysis(aid)
        raise HTTPException(400, "mode must be auto, malware or appsec")
    password = fields.get("password") or None
    files = upload.files
    name = (fields.get("name") or "").strip()[:200] or (files[0]["display_name"] if len(files) == 1 else f"{files[0]['display_name']} +{len(files) - 1} file(s)")
    from backend.core.database import session_scope

    with session_scope() as s:
        s.add(Analysis(
            id=aid, name=name, mode=mode, status=AnalysisStatus.QUEUED.value, notes=(fields.get("notes") or None),
            options_json={"files": files, "has_password": bool(password)},
        ))
    st.manager.submit(aid, password)
    password = None
    log_event(log, "analysis_queued", analysis_id=aid, status="QUEUED", detail=f"{len(files)} file(s)")
    return {"id": aid, "status": "QUEUED", "files": [{"name": f["display_name"], "size": f["size"]} for f in files]}


@router.get("/analyses")
def list_analyses(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), q: str | None = None,
                  status: str | None = None, s: Session = Depends(get_session)):
    query = s.query(Analysis)
    if q:
        query = query.filter((Analysis.name.like(f"%{q}%")) | (Analysis.root_sha256.like(f"%{q.lower()}%")))
    if status:
        query = query.filter(Analysis.status == status)
    total = query.count()
    rows = query.order_by(Analysis.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [queries.analysis_summary(a) for a in rows]}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, s: Session = Depends(get_session)):
    return queries.analysis_detail(s, _analysis(s, analysis_id))


@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    st = _state(request)
    if a.status not in ("COMPLETED", "FAILED", "CANCELLED"):
        st.manager.cancel(a.id)
    s.delete(a)
    s.flush()
    st.storage.purge_analysis(analysis_id)
    log_event(log, "analysis_deleted", analysis_id=analysis_id, status="deleted")
    return {"deleted": analysis_id}


@router.post("/analyses/{analysis_id}/cancel")
def cancel_analysis(analysis_id: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    if a.status in ("COMPLETED", "FAILED", "CANCELLED"):
        raise HTTPException(409, f"analysis already {a.status}")
    s.commit()
    ok = _state(request).manager.cancel(analysis_id)
    return {"id": analysis_id, "cancel_requested": ok}


@router.post("/analyses/{analysis_id}/reanalyze")
def reanalyze(analysis_id: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    if a.status not in ("COMPLETED", "FAILED", "CANCELLED"):
        raise HTTPException(409, "analysis is still running")
    st = _state(request)
    st.storage.purge_area(analysis_id, ("extracted", "evidence", "reports", "tmp"))
    a.status = AnalysisStatus.QUEUED.value
    a.progress = 0
    a.error = None
    a.started_at = a.completed_at = None
    opts = dict(a.options_json or {})
    opts["password_dropped"] = bool(opts.get("has_password"))
    a.options_json = opts
    s.commit()
    st.manager.submit(analysis_id, None)
    return {"id": analysis_id, "status": "QUEUED"}


# --------------------------------------------------------------------------- artifacts
@router.get("/analyses/{analysis_id}/artifacts")
def list_artifacts(analysis_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return [queries.artifact_brief(x) for x in s.query(Artifact).filter(Artifact.analysis_id == a.id).order_by(Artifact.depth)]


@router.get("/analyses/{analysis_id}/artifacts/{artifact_id}")
def get_artifact(analysis_id: str, artifact_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return queries.artifact_detail(_artifact(s, a, artifact_id))


@router.get("/analyses/{analysis_id}/artifacts/{artifact_id}/strings")
def get_strings(analysis_id: str, artifact_id: str, classification: str | None = None, q: str | None = None,
                offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=2000), s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    x = _artifact(s, a, artifact_id)
    return queries.strings_page(s, a.id, x.id, classification, q, offset, limit)


@router.get("/analyses/{analysis_id}/artifacts/{artifact_id}/hex")
def get_hex(analysis_id: str, artifact_id: str, request: Request, offset: int = Query(0, ge=0),
            length: int = Query(512, ge=1, le=4096), s: Session = Depends(get_session)):
    """Read-only hex view. Returns hex text in JSON — the sample itself is never served."""
    a = _analysis(s, analysis_id)
    x = _artifact(s, a, artifact_id)
    path = _state(request).storage.resolve_relative(x.storage_path)
    data = read_range(path, offset, length)
    return {"offset": offset, "length": len(data), "size": x.size, "hex": data.hex()}


@router.get("/analyses/{analysis_id}/artifacts/{artifact_id}/functions")
def get_functions(analysis_id: str, artifact_id: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    x = _artifact(s, a, artifact_id)
    data = queries.reverse_data(_state(request).storage, x)
    if data is None:
        return {"available": False, "functions": [], "reason": "No native code disassembly for this artifact."}
    funcs = [{k: v for k, v in f.items() if k not in ("assembly", "pseudocode")} | {"has_pseudocode": bool(f.get("pseudocode"))}
             for f in data["functions"]]
    return {"available": True, **{k: v for k, v in data.items() if k != "functions"}, "functions": funcs}


@router.get("/analyses/{analysis_id}/artifacts/{artifact_id}/functions/{address}")
def get_function(analysis_id: str, artifact_id: str, address: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    x = _artifact(s, a, artifact_id)
    data = queries.reverse_data(_state(request).storage, x)
    if data is None:
        raise HTTPException(404, "no disassembly")
    fn = next((f for f in data["functions"] if f["address"] == address or f["name"] == address), None)
    if fn is None:
        raise HTTPException(404, "function not found")
    seg = next((g for g in data.get("segments", []) if g["name"] == fn.get("segment")), None)
    related = []
    needles = {i.split("!")[-1].lower() for i in fn.get("imports", [])} | {st["value"].lower()[:60] for st in fn.get("strings", [])}
    if needles:
        for e in s.query(Evidence).filter(Evidence.analysis_id == a.id, Evidence.artifact_id == x.id):
            val = (e.value or "").lower()
            if any(n and (n == val or n in val) for n in needles):
                refs = [r for (r,) in s.query(Finding.ref).join(FindingEvidence, FindingEvidence.finding_id == Finding.id)
                        .filter(FindingEvidence.evidence_id == e.id)]
                related.append({"evidence": e.ref, "title": e.title, "severity": e.severity, "findings": refs})
    return {**fn, "segment_info": seg, "related": related[:50],
            "pseudocode_note": None if fn.get("pseudocode") else
            "Pseudo-code requires an external decompiler (Ghidra headless or radare2 with r2ghidra/r2dec) to be installed and enabled."}


# --------------------------------------------------------------------------- findings & evidence
@router.get("/analyses/{analysis_id}/findings")
def get_findings(analysis_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return queries.findings_list(s, a.id)


class AnalystFinding(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    what: str = Field(default="", max_length=4000)
    why: str = Field(default="", max_length=4000)
    evidence: list[str] = Field(default_factory=list, max_length=200)
    status: Literal["UNKNOWN", "INVESTIGATING", "SUPPORTED", "CONFIRMED", "DISMISSED"] = "SUPPORTED"


@router.post("/analyses/{analysis_id}/findings", status_code=201)
def create_finding(analysis_id: str, body: AnalystFinding, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    n = s.query(func.count(Finding.id)).filter(Finding.analysis_id == a.id).scalar() or 0
    ref = f"F-A{n + 1:02d}"
    evs = s.query(Evidence).filter(Evidence.analysis_id == a.id, Evidence.ref.in_(body.evidence)).all() if body.evidence else []
    f = Finding(id=new_id(), ref=ref, analysis_id=a.id, title=body.title, kind="analyst", category="info", severity=body.severity,
                confidence=1.0 if body.status == "CONFIRMED" else 0.7, strength="moderate", needs_review=False,
                what=body.what or body.title, where_json=sorted({e.artifact_id for e in evs if e.artifact_id}), why=body.why,
                limitations_json=["Analyst-created finding from the investigation board."], status=body.status,
                mitre_json=sorted({t for e in evs for t in (e.mitre_json or [])}), score=0.0)
    s.add(f)
    s.flush()
    for e in evs:
        s.add(FindingEvidence(finding_id=f.id, evidence_id=e.id, role="supporting"))
    a.finding_count = (a.finding_count or 0) + 1
    return {"id": ref}


class StatePatch(BaseModel):
    status: Literal["UNKNOWN", "INVESTIGATING", "SUPPORTED", "CONFIRMED", "DISMISSED"] | None = None
    note: str | None = Field(default=None, max_length=8000)


@router.patch("/analyses/{analysis_id}/findings/{ref}")
def patch_finding(analysis_id: str, ref: str, body: StatePatch, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    f = s.query(Finding).filter(Finding.analysis_id == a.id, Finding.ref == ref).one_or_none()
    if f is None:
        raise HTTPException(404, "finding not found")
    if body.status:
        f.status = body.status
    if body.note is not None:
        f.analyst_note = body.note
    return {"id": ref, "status": f.status}


@router.get("/analyses/{analysis_id}/findings/{ref}/chain")
def finding_chain(analysis_id: str, ref: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    chain = queries.chain_for_finding(s, a, ref)
    if chain is None:
        raise HTTPException(404, "finding not found")
    return chain


@router.get("/analyses/{analysis_id}/evidence")
def get_evidence(analysis_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return queries.evidence_list(s, a.id)


@router.patch("/analyses/{analysis_id}/evidence/{ref}")
def patch_evidence(analysis_id: str, ref: str, body: StatePatch, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    e = s.query(Evidence).filter(Evidence.analysis_id == a.id, Evidence.ref == ref).one_or_none()
    if e is None:
        raise HTTPException(404, "evidence not found")
    if body.status:
        e.analyst_state = AnalystState(body.status).value
    if body.note is not None:
        e.analyst_note = body.note
    return {"id": ref, "analyst_state": e.analyst_state}


# --------------------------------------------------------------------------- IOCs
def _defang(v: str) -> str:
    return v.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")


def _csv_safe(v: Any) -> str:
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


def _ioc_response(items: list[dict[str, Any]], fmt: str, defang: bool, filename: str):
    if defang:
        for i in items:
            i["value"] = _defang(i["value"])
    if fmt == "txt":
        return PlainTextResponse("\n".join(f"{i['type']}\t{i['value']}" for i in items) + "\n",
                                 headers={"Content-Disposition": f'attachment; filename="{filename}.txt"'})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "common", "source", "evidence_ref", "analysis_id"])
        for i in items:
            w.writerow([_csv_safe(i["type"]), _csv_safe(i["value"]), i["common"], _csv_safe(i["source"]), i["evidence_ref"] or "", i["analysis_id"]])
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'})
    if fmt == "stix":
        raise HTTPException(501, "STIX export is on the roadmap")
    return JSONResponse(items, headers={"Content-Disposition": f'attachment; filename="{filename}.json"'} if fmt == "json-download" else None)


@router.get("/analyses/{analysis_id}/iocs")
def get_iocs(analysis_id: str, format: str = Query("json", pattern="^(json|json-download|csv|txt|stix)$"),
             defang: bool = False, include_common: bool = True, type: list[str] | None = Query(None),
             s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    items = queries.iocs_list(s, a.id, types=type, include_common=include_common)
    return _ioc_response(items, format, defang, f"malx-iocs-{a.id[:8]}")


@router.get("/iocs")
def global_iocs(format: str = Query("json", pattern="^(json|json-download|csv|txt|stix)$"), defang: bool = False,
                include_common: bool = False, q: str | None = None, type: list[str] | None = Query(None),
                limit: int = Query(5000, ge=1, le=50000), s: Session = Depends(get_session)):
    items = queries.iocs_list(s, None, types=type, q=q, include_common=include_common, limit=limit)
    return _ioc_response(items, format, defang, "malx-iocs")


# --------------------------------------------------------------------------- views
@router.get("/analyses/{analysis_id}/graph")
def get_graph(analysis_id: str, include_weak: bool = False, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return queries.build_graph(s, a, include_weak=include_weak)


@router.get("/analyses/{analysis_id}/timeline")
def get_timeline(analysis_id: str, s: Session = Depends(get_session)):
    return queries.timeline_list(s, _analysis(s, analysis_id).id)


@router.get("/analyses/{analysis_id}/mitre")
def get_mitre(analysis_id: str, request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    pack = _state(request).rule_pack()
    tactics_order = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                     "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
    return {"techniques": queries.mitre_list(s, a.id), "tactics": tactics_order, "catalog_size": len(pack.mitre)}


@router.get("/analyses/{analysis_id}/yara")
def get_yara(analysis_id: str, s: Session = Depends(get_session)):
    return queries.yara_list(s, _analysis(s, analysis_id).id)


@router.get("/analyses/{analysis_id}/appsec")
def get_appsec(analysis_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return queries.appsec_view(s, a)


class Board(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    edges: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    notes: str | None = Field(default=None, max_length=20000)


@router.get("/analyses/{analysis_id}/board")
def get_board(analysis_id: str, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    return a.board_json or {"nodes": [], "edges": [], "notes": ""}


@router.put("/analyses/{analysis_id}/board")
def put_board(analysis_id: str, body: Board, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    raw = body.model_dump()
    if len(json.dumps(raw)) > 2_000_000:
        raise HTTPException(413, "board too large")
    a.board_json = raw
    return {"saved": True, "nodes": len(body.nodes), "edges": len(body.edges)}


# --------------------------------------------------------------------------- reports / exports
@router.get("/analyses/{analysis_id}/report")
def get_report(analysis_id: str, request: Request, format: str = Query("html", pattern="^(html|md|markdown|json|pdf)$"),
               download: bool = False, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    if format == "pdf":
        raise HTTPException(501, "PDF reports are on the roadmap; print the HTML report to PDF meanwhile")
    fmt = {"md": "markdown"}.get(format, format)
    rep = s.query(Report).filter(Report.analysis_id == a.id, Report.format == fmt).one_or_none()
    st = _state(request)
    if rep is None:
        if a.status != "COMPLETED":
            raise HTTPException(409, "report not available until the analysis completes")
        from backend.reports.generator import generate_reports

        generate_reports(a.id, st.storage)
        s.expire_all()
        rep = s.query(Report).filter(Report.analysis_id == a.id, Report.format == fmt).one_or_none()
        if rep is None:
            raise HTTPException(500, "report generation failed")
    content = st.storage.resolve_relative(rep.storage_path).read_bytes()
    media = {"html": "text/html; charset=utf-8", "markdown": "text/markdown; charset=utf-8", "json": "application/json"}[fmt]
    ext = {"html": "html", "markdown": "md", "json": "json"}[fmt]
    headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    if fmt == "html":
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
        headers["X-Frame-Options"] = "SAMEORIGIN"
    if download:
        headers["Content-Disposition"] = f'attachment; filename="malx-report-{a.id[:8]}.{ext}"'
    return Response(content, media_type=media, headers=headers)


@router.get("/analyses/{analysis_id}/export/{kind}")
def export(analysis_id: str, kind: Literal["evidence", "analysis", "findings"], request: Request, s: Session = Depends(get_session)):
    a = _analysis(s, analysis_id)
    if kind == "evidence":
        data: Any = queries.evidence_list(s, a.id)
    elif kind == "findings":
        data = queries.findings_list(s, a.id)
    else:
        from backend.reports.generator import build_model

        data = build_model(s, a, _state(request).storage)
    return Response(json.dumps(data, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="malx-{kind}-{a.id[:8]}.json"'})


@router.get("/search")
def search(q: str = Query(..., min_length=2, max_length=200), s: Session = Depends(get_session)):
    return queries.search(s, q.strip())
