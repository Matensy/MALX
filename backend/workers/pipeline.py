"""The analysis pipeline (runs inside the isolated worker process).

UPLOAD → QUARANTINE → VALIDATION → IDENTIFICATION → HASHING → EXTRACTION →
STATIC ANALYSIS → SPECIALIZED ANALYSIS → HEURISTICS → IOC EXTRACTION →
CORRELATION → RISK MODEL → MITRE MAPPING → FINDINGS → (report, in the API process)

Nothing in this module executes, imports or loads the submitted content.
"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from backend.analyzers import (
    android,
    appsec,
    archive,
    correlation,
    documents,
    elf,
    entropy,
    heuristics,
    hashing,
    identify,
    ioc,
    pe,
    reverse,
    scripts,
    strings_engine,
)
from backend.analyzers.base import AnalysisCancelled, AnalysisContext, AnalysisTimeout, ArtifactContext, IOCItem
from backend.analyzers.yara_engine import get_yara_engine
from backend.core.config import Limits
from backend.core.enums import StringClass
from backend.core.security import sanitize_display_name
from backend.rules.loader import get_rule_pack
from backend.services import tools as tools_mod

ENGINE_VERSION = "0.1.0"
MAX_REVERSE_ARTIFACTS = 12
MAX_TOOL_ARTIFACTS = 3
NOTABLE_IOC_EVIDENCE = 60

STRING_TAG_SEVERITY = {StringClass.HIGH_RISK: "medium", StringClass.SUSPICIOUS: "low", StringClass.INTERESTING: "info"}


def _new_artifact(ctx: AnalysisContext, spec: dict[str, Any]) -> ArtifactContext:
    path = ctx.storage_root / spec["storage_rel"]
    san = sanitize_display_name(spec["original_name"], ctx.limits.max_filename_length)
    art = ArtifactContext(
        id=spec["artifact_id"], path=path, storage_rel=spec["storage_rel"], display_name=san.display,
        size=path.stat().st_size, name_issues=list(dict.fromkeys(san.issues + spec.get("name_issues", []))),
    )
    return ctx.add_artifact(art)


def _identify_and_hash(ctx: AnalysisContext, art: ArtifactContext) -> None:
    ctx.check()
    art.ident = identify.identify(art.path, art.display_name, ctx.limits.max_files_per_archive)
    art.architecture = art.ident.architecture
    hashes, lims = hashing.compute_hashes(art.path, art.size, ctx.limits.max_fuzzy_hash_size)
    art.hashes = hashes
    art.limitations += lims
    art.entropy = entropy.file_entropy(art.path, limit=ctx.limits.max_deep_scan_size)
    art.entropy_profile = entropy.entropy_profile(art.path, art.size)
    ctx.event(f"File identified: {art.ident.label}", engine="identification", artifact_id=art.id,
              detail=f"{art.display_name} sha256={hashes.get('sha256')}")
    _identity_evidence(ctx, art)


def _identity_evidence(ctx: AnalysisContext, art: ArtifactContext) -> None:
    ident = art.ident
    if ident.extension_mismatch:
        executable = ident.detected_type in identify.EXECUTABLE_TYPES or ident.category in ("script",)
        lure = ident.extension in identify.LURE_EXTENSIONS
        ctx.add_evidence(
            type="extension_mismatch", category="defense_evasion" if executable else "structure", source="identification",
            artifact=art, title=f"Extension mismatch: {ident.extension} vs {ident.label}",
            description=(ident.mismatch_reason or "") + (" Executable content behind a document/media extension is a masquerading technique." if executable and lure else ""),
            severity="high" if executable and lure else ("medium" if executable else "low"),
            confidence=0.85 if ident.confidence >= 0.9 else 0.6, reliability="high", value=f"{art.display_name} → {ident.detected_type}",
            mitre=["T1036.008"] if executable else [],
        )
    if ident.details.get("double_extension"):
        ctx.add_evidence(
            type="double_extension", category="defense_evasion", source="identification", artifact=art,
            title="Double file extension", description="The name hides the real extension behind a document-like one.",
            severity="medium", confidence=0.7, reliability="high", value=art.display_name, mitre=["T1036.007"],
        )
    issues = set(art.name_issues)
    if "bidi_override" in issues:
        ctx.add_evidence(
            type="rtlo_filename", category="defense_evasion", source="identification", artifact=art,
            title="Right-to-left override characters in filename",
            description="Unicode bidirectional controls make the displayed name differ from the real one (e.g. 'invoice‮fdp.exe').",
            severity="high", confidence=0.85, reliability="high", value=art.display_name, mitre=["T1036.002"],
        )
    weird = issues & {"null_byte", "control_characters", "malformed_unicode", "name_too_long"}
    if weird:
        ctx.add_evidence(
            type="malformed_filename", category="structure", source="identification", artifact=art,
            title="Malformed filename", description=f"The original filename had: {', '.join(sorted(weird))}. Names were sanitised for display.",
            severity="low", confidence=0.6, reliability="high", value=art.display_name,
        )
    if ident.detected_type == "pdf" and ident.details.get("header_offset", 0) > 0:
        art.tags.add("pdf_header_offset")


def _extract_strings(ctx: AnalysisContext, art: ArtifactContext) -> None:
    found, truncated = strings_engine.extract_strings(art.path, art.size, ctx.limits.max_deep_scan_size)
    art.strings = found + art.strings
    art.invalidate_strings()
    if truncated:
        art.limitations.append("String extraction truncated (file larger than max_deep_scan_size or too many strings).")


def _specialized(ctx: AnalysisContext, art: ArtifactContext, pack) -> None:
    parser = art.ident.parser if art.ident else "none"
    try:
        if parser == "pe_analyzer":
            pe.analyze_pe(ctx, art, pack)
        elif parser == "elf_analyzer":
            elf.analyze_elf(ctx, art, pack)
        elif parser == "macho_analyzer":
            elf.analyze_macho(ctx, art)
        elif parser == "pdf_analyzer":
            documents.analyze_pdf(ctx, art)
        elif parser == "ooxml_analyzer":
            documents.analyze_ooxml(ctx, art)
        elif parser == "ole_analyzer":
            documents.analyze_ole(ctx, art)
        elif parser == "rtf_analyzer":
            documents.analyze_rtf(ctx, art)
        elif parser == "lnk_analyzer":
            documents.analyze_lnk(ctx, art)
        elif parser == "apk_analyzer":
            android.analyze_apk(ctx, art)
        elif parser == "dex_analyzer":
            android.analyze_dex(ctx, art)
        elif parser == "java_analyzer":
            android.analyze_jar(ctx, art)
        elif parser == "script_analyzer":
            scripts.analyze_script(ctx, art)
        else:
            return
        ctx.event(f"{parser.replace('_', ' ').title()} completed", engine=parser, artifact_id=art.id)
    except Exception as exc:  # parser bugs must not abort the whole analysis
        if isinstance(exc, (AnalysisTimeout, AnalysisCancelled)):
            raise
        art.errors.append(f"{parser}: {type(exc).__name__}: {str(exc)[:200]}")
        ctx.limitation(f"{art.display_name}: {parser} failed ({type(exc).__name__}); results for this artifact are partial.")


def _string_evidence(ctx: AnalysisContext, art: ArtifactContext, pack) -> None:
    by_tag: dict[str, list] = defaultdict(list)
    for s in art.strings:
        for t in s.tags:
            by_tag[t].append(s)
    patterns = {p.tag: p for p in pack.string_patterns}
    for tag, items in by_tag.items():
        p = patterns.get(tag)
        if p is None:
            continue
        klass = StringClass(p.klass)
        if klass == StringClass.INTERESTING:
            continue
        examples = [{"offset": s.offset, "encoding": s.encoding, "value": s.value[:200], "origin": s.origin} for s in items[:6]]
        ctx.add_evidence(
            type="string_signature", category=p.category, source="string_analyzer", artifact=art,
            title=f"{p.description} ({len(items)} string(s))",
            description=f"String signature '{tag}' classified {klass.value}. Example: {items[0].value[:160]!r}.",
            severity=STRING_TAG_SEVERITY[klass], confidence=0.6 if klass == StringClass.HIGH_RISK else 0.45, reliability="medium",
            value=items[0].value[:300], offset=items[0].offset, rule_id=f"string:{tag}",
            details={"tag": tag, "class": klass.value, "count": len(items), "examples": examples},
        )


def _iocs(ctx: AnalysisContext, art: ArtifactContext, enricher: ioc.IOCEnricher) -> None:
    raw = ioc.extract_iocs(art.strings)
    added: list[IOCItem] = []
    for r in raw:
        item = IOCItem(type=r.type, value=r.value[:2000], normalized=r.normalized[:2000], artifact_id=art.id,
                       source="ioc_engine" if not r.meta.get("from_url") else "ioc_engine:url", offset=r.offset,
                       context=r.context[:240])
        info = enricher.enrich(r)
        item.enrich = {**r.meta, **info}
        item.common = bool(info.get("common"))
        before = len(ctx.iocs)
        stored = ctx.add_ioc(item)
        if len(ctx.iocs) > before:
            added.append(stored)
    notable = 0
    for item in added:
        if item.common or item.type not in ("url", "domain", "ipv4", "ipv6", "onion", "email", "crypto_wallet"):
            continue
        e = item.enrich
        sev, conf = "info", 0.4
        reasons = []
        if e.get("service"):
            sev, conf = ("medium" if e["service"] in ("dynamic_dns", "tunnels", "paste_sites", "file_sharing", "chat_api", "logger", "tor") else "low"), 0.55
            reasons.append(f"service: {e['service'].replace('_', ' ')}")
        if e.get("ip_host"):
            sev = "low" if sev == "info" else sev
            reasons.append("raw IP host")
        if e.get("unusual_port"):
            sev = "low" if sev == "info" else sev
            reasons.append(f"port {e['unusual_port']}")
        if e.get("suspicious_tld"):
            reasons.append(f"TLD .{e['suspicious_tld']}")
        if item.type == "onion":
            sev = "medium"
            reasons.append("Tor onion service")
        if item.type == "crypto_wallet":
            sev = "low"
        if notable >= NOTABLE_IOC_EVIDENCE and sev == "info":
            continue
        ev = ctx.add_evidence(
            type="network_indicator" if item.type not in ("crypto_wallet", "email") else f"{item.type}_indicator",
            category="network" if item.type not in ("crypto_wallet",) else "impact", source="ioc_engine", artifact=art,
            title=f"{item.type.upper()} indicator: {item.value[:120]}",
            description="Indicator extracted statically from strings" + (f" ({'; '.join(reasons)})" if reasons else "") +
                        ". Presence does not prove the endpoint is contacted or malicious.",
            severity=sev, confidence=conf, reliability="medium", value=item.value[:500], offset=item.offset,
            details={"ioc_type": item.type, "context": item.enrich},
        )
        item.evidence_ref = ev.ref
        notable += 1
    if added:
        ctx.event(f"{len(added)} IOC(s) extracted", engine="ioc_engine", artifact_id=art.id)


def run_pipeline(job: dict[str, Any], progress: Callable[[str, int, str | None], None] | None = None,
                 cancel_check: Callable[[], bool] | None = None) -> dict[str, Any]:
    limits = Limits(**job["limits"])
    storage_root = Path(job["storage_root"])
    rules_dir = Path(job["rules_dir"])
    if job.get("advisories_dir"):
        os.environ["MALX_ADVISORIES_DIR"] = job["advisories_dir"]
    ctx = AnalysisContext(job["analysis_id"], limits, storage_root, mode=job.get("mode", "auto"),
                          password=job.get("password"), progress=progress, cancel_check=cancel_check)
    pack = get_rule_pack(str(rules_dir))
    ctx.engine_status("rules", "ok", **pack.counts(), errors=pack.errors[:20])
    yara_engine = get_yara_engine(str(rules_dir / "yara"))
    ctx.engine_status("yara", "ok" if yara_engine.available else "unavailable", version=yara_engine.version,
                      rules=yara_engine.rule_count, errors=yara_engine.errors[:10])
    if not yara_engine.available:
        ctx.limitation("YARA engine unavailable (pip install yara-python); YARA layer skipped.")
    tool_cfg = job.get("tools", {})
    tool_infos = {}
    if tool_cfg.get("enabled"):
        tool_infos = {k: v for k, v in tools_mod.detect_tools_cached(tool_cfg.get("ghidra_home", ""), True).items() if v.available}
    ctx.engine_status("external_tools", "ok", available=sorted(tool_infos))
    ctx.engine_status("reverse", "ok" if reverse.capstone is not None else "unavailable",
                      version=getattr(reverse.capstone, "__version__", None) if reverse.capstone else None)
    enricher = ioc.IOCEnricher(pack)

    # ---------------------------------------------------------------- VALIDATING
    ctx.progress("VALIDATING", 5, "validating quarantined files")
    ctx.event("Analysis started", engine="pipeline")
    for spec in job["files"]:
        art = _new_artifact(ctx, spec)
        if art.size > limits.max_upload_size:
            raise ValueError("file exceeds max_upload_size")
        ctx.event(f"File received in quarantine: {art.display_name}", engine="quarantine", artifact_id=art.id,
                  detail=f"{art.size} bytes")
    if job.get("password_dropped"):
        ctx.limitation("The archive password was not retained across a restart; encrypted members may not be inspected.")

    # ---------------------------------------------------------------- EXTRACTING
    ctx.progress("EXTRACTING", 15, "identification, hashing and safe extraction")
    i = 0
    while i < len(ctx.artifacts):
        art = ctx.artifacts[i]
        i += 1
        _identify_and_hash(ctx, art)
        if art.detected_type in archive.ARCHIVE_TYPES:
            children = archive.analyze_archive(ctx, art)
            if children:
                ctx.event(f"Extracted {len(children)} member(s) from {art.display_name}", engine="archive_analyzer", artifact_id=art.id)
        ctx.progress("EXTRACTING", min(35, 15 + i), f"{len(ctx.artifacts)} artifact(s)")

    # ---------------------------------------------------------------- ANALYZING
    ctx.progress("ANALYZING", 40, "static analysis")
    reversed_count = 0
    tooled = 0
    i = 0
    while i < len(ctx.artifacts):
        art = ctx.artifacts[i]
        i += 1
        ctx.check()
        if art.ident is None:  # decoded payloads materialised during analysis
            _identify_and_hash(ctx, art)
            if art.detected_type in archive.ARCHIVE_TYPES:
                archive.analyze_archive(ctx, art)
        if art.detected_type not in ("empty",):
            # Containers are analysed through their extracted members; their compressed bytes only add noise.
            if art.detected_type not in archive.ARCHIVE_TYPES and (art.category not in ("image", "media") or art.size <= 32 * 1024 * 1024):
                _extract_strings(ctx, art)
            _specialized(ctx, art, pack)
            classifier = strings_engine.StringClassifier(pack)
            stats = classifier.classify(art.strings, art.imports)
            art.metadata["string_stats"] = dict(stats)
            _string_evidence(ctx, art, pack)
            _iocs(ctx, art, enricher)
            if yara_engine.available:
                try:
                    yara_engine.scan(ctx, art)
                except Exception as exc:  # yara timeouts / internal errors
                    art.errors.append(f"yara: {str(exc)[:200]}")
            if art.detected_type in ("pe", "elf") and tool_infos and tooled < MAX_TOOL_ARTIFACTS:
                tooled += 1
                timeout = int(tool_cfg.get("timeout", 120))
                if "capa" in tool_infos:
                    tools_mod.run_capa(ctx, art, tool_infos["capa"], timeout)
                if "floss" in tool_infos and art.detected_type == "pe":
                    tools_mod.run_floss(ctx, art, tool_infos["floss"], timeout)
                    classifier.classify([s for s in art.strings if s.origin == "floss"], art.imports)
                    _iocs(ctx, art, enricher)
            if art.detected_type in ("pe", "elf") and reversed_count < MAX_REVERSE_ARTIFACTS:
                reversed_count += 1
                try:
                    result = reverse.analyze_reverse(ctx, art)
                    if result and "radare2" in tool_infos and tool_cfg.get("decompile", True):
                        _decompile(ctx, art, tool_infos["radare2"], result, int(tool_cfg.get("timeout", 120)))
                except Exception as exc:
                    if isinstance(exc, (AnalysisTimeout, AnalysisCancelled)):
                        raise
                    art.errors.append(f"reverse: {type(exc).__name__}: {str(exc)[:200]}")
        ctx.progress("ANALYZING", min(70, 40 + int(30 * i / max(1, len(ctx.artifacts)))), art.display_name[:80])

    if ctx.mode != "malware":
        ctx.progress("ANALYZING", 72, "application security")
        appsec.run_appsec(ctx, pack, force=ctx.mode == "appsec")

    ctx.progress("ANALYZING", 78, "heuristics")
    fired = heuristics.run_heuristics(ctx, pack)
    ctx.event(f"Heuristic engine: {fired} rule(s) matched", engine="heuristic_engine")

    # ---------------------------------------------------------------- CORRELATING
    ctx.progress("CORRELATING", 85, "correlation, risk and MITRE mapping")
    findings = correlation.correlate(ctx, pack)
    appsec_findings = ctx.appsec.pop("findings", []) if ctx.appsec else []
    for f in appsec_findings:
        f["score"] = round(correlation.FINDING_BASE.get(f["severity"], 10) * (0.5 + 0.5 * f["confidence"]) * 0.8, 1)
        findings.append(f)
    findings.sort(key=lambda f: (-f["score"], f["title"]))
    for n, f in enumerate(findings, 1):
        f["ref"] = f"F-{n:03d}"
    classification, reason = correlation.classify(ctx, findings)
    risk = correlation.risk_model(ctx, findings)
    mitre = correlation.map_mitre(ctx, pack, findings)
    summary = correlation.investigation_summary(ctx, findings, classification, reason)
    summary["capabilities"] = correlation.capabilities(ctx)
    ctx.event(f"Correlation produced {len(findings)} finding(s)", engine="correlation_engine")
    ctx.event(f"Classification: {classification}", engine="risk_model")
    return _result(ctx, findings, classification, risk, mitre, summary)


def _decompile(ctx: AnalysisContext, art: ArtifactContext, info, result: dict[str, Any], timeout: int) -> None:
    import json

    interesting = [f["address"] for f in result["functions"] if f["imports"]][:20]
    pseudo = tools_mod.run_r2_decompile(ctx, art, info, timeout, interesting)
    if not pseudo or not art.reverse_path:
        return
    for f in result["functions"]:
        if f["address"] in pseudo:
            f["pseudocode"] = pseudo[f["address"]]
            f["pseudocode_engine"] = "radare2"
    path = ctx.storage_root / art.reverse_path
    os.chmod(path, 0o600)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh)


def _result(ctx: AnalysisContext, findings, classification, risk, mitre, summary) -> dict[str, Any]:
    limits = ctx.limits
    artifacts = []
    for a in ctx.artifacts:
        stored = strings_engine.select_for_storage(a.strings, limits.max_strings_per_artifact)
        ident = a.ident
        artifacts.append({
            "id": a.id, "parent_id": a.parent_id, "depth": a.depth, "display_name": a.display_name,
            "path_in_archive": a.path_in_archive, "storage_rel": a.storage_rel, "size": a.size,
            "hashes": a.hashes, "imphash": a.imphash,
            "detected_type": ident.detected_type if ident else None, "type_label": ident.label if ident else None,
            "category": ident.category if ident else None, "mime": ident.mime if ident else None,
            "confidence": ident.confidence if ident else None, "parser": ident.parser if ident else None,
            "extension": ident.extension if ident else None, "magic_hex": ident.magic_hex if ident else None,
            "extension_mismatch": bool(ident and ident.extension_mismatch),
            "mismatch_reason": ident.mismatch_reason if ident else None,
            "identification_details": ident.details if ident else {},
            "entropy": a.entropy, "entropy_profile": a.entropy_profile, "architecture": a.architecture,
            "tags": sorted(a.tags), "metadata": a.metadata, "name_issues": a.name_issues,
            "errors": a.errors[:50], "limitations": a.limitations[:50], "reverse_path": a.reverse_path,
            "string_count": len(a.strings),
            "strings": [{"offset": s.offset, "encoding": s.encoding, "value": s.value, "classification": s.classification.value,
                         "tags": s.tags, "origin": s.origin} for s in stored],
        })
    return {
        "analysis_id": ctx.analysis_id, "engine_version": ENGINE_VERSION, "mode": ctx.mode,
        "artifacts": artifacts,
        "evidence": [e.to_dict() for e in ctx.evidence],
        "iocs": [{"type": i.type, "value": i.value, "normalized": i.normalized, "artifact_id": i.artifact_id, "source": i.source,
                  "offset": i.offset, "occurrences": i.occurrences, "common": i.common, "evidence_ref": i.evidence_ref,
                  "context": i.context, "enrich": i.enrich} for i in ctx.iocs.values()],
        "yara": ctx.yara_matches, "findings": findings, "mitre": mitre, "risk": risk, "summary": summary,
        "classification": classification, "appsec": ctx.appsec, "dependencies": ctx.dependencies,
        "vulnerabilities": ctx.vulnerabilities, "timeline": ctx.timeline, "engines": ctx.engines,
        "limitations": ctx.limitations,
    }
