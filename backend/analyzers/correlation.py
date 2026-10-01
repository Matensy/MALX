"""Correlation engine, findings, risk model, MITRE mapping and classification.

Pipeline::

    evidence ──► correlation rules ──► correlated findings
             └─► leftover strong/weak indicators ──► indicator findings
    findings + evidence ──► risk dimensions ──► classification
    evidence/findings with ATT&CK references ──► MITRE mapping

Language is deliberately evidence-based ("potential", "indicators of"): a score is an
operational summary, not ground truth.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.core.enums import CATEGORIES, Classification, FindingStrength, Severity
from backend.rules.loader import RulePack

from .base import AnalysisContext, EvidenceItem

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
FINDING_BASE = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}
GENERIC_LIMITATIONS = [
    "Static analysis only: the sample was never executed, so runtime-only behaviour (unpacked code, downloaded stages, environment-dependent logic) is not observed.",
    "Indicators describe capability present in the file, not proof that the capability is used maliciously.",
]
RISK_DIMENSIONS = {
    "packing_likelihood": ("Packing likelihood", ["packing"]),
    "persistence": ("Persistence evidence", ["persistence"]),
    "credential": ("Credential evidence", ["credential_access", "collection"]),
    "network": ("Network evidence", ["network"]),
    "evasion": ("Evasion evidence", ["anti_analysis", "defense_evasion"]),
    "injection": ("Injection evidence", ["injection"]),
    "execution": ("Execution evidence", ["execution"]),
    "impact": ("Impact evidence", ["impact"]),
    "document": ("Document / delivery evidence", ["document", "archive", "mobile"]),
    "privilege": ("Privilege evidence", ["privilege"]),
}
APPSEC_DIMENSIONS = {
    "vulnerability_exposure": ("Vulnerable dependencies", ["vulnerability"]),
    "secret_exposure": ("Exposed secrets", ["secret"]),
    "code_weakness": ("Code weaknesses", ["code"]),
}


def _sev(v: str) -> int:
    return SEVERITY_ORDER.index(v) if v in SEVERITY_ORDER else 0


def _down(sev: str) -> str:
    return SEVERITY_ORDER[max(1, _sev(sev) - 1)]


PURE_CONTAINERS = {"zip", "tar", "gzip", "bzip2", "xz", "7z"}


def _units(ctx: AnalysisContext) -> list[tuple[str, set[str]]]:
    """Correlation units.

    A unit is an artifact plus the content that belongs to it (a document and its
    embedded objects/macros, an APK and its DEX, a script and its decoded payloads).
    Members of *pure* containers (ZIP/TAR/7z/gzip...) start their own unit: unrelated
    files that merely share an archive must not be correlated with each other.
    """
    def is_unit_root(a) -> bool:
        if a.parent_id is None:
            return True
        parent = ctx.by_id.get(a.parent_id)
        return parent is not None and parent.detected_type in PURE_CONTAINERS

    units = []
    for root in ctx.artifacts:
        if not is_unit_root(root):
            continue
        ids = {root.id}
        if root.detected_type not in PURE_CONTAINERS:
            stack = [root.id]
            while stack:
                cur = ctx.by_id[stack.pop()]
                for c in cur.children:
                    child = ctx.by_id.get(c)
                    if c not in ids and child is not None and not is_unit_root(child):
                        ids.add(c)
                        stack.append(c)
        units.append((root.id, ids))
    return units


def _group_match(group: dict[str, Any], evidence: list[EvidenceItem]) -> list[EvidenceItem]:
    min_sev = _sev(group.get("min_severity", "low"))
    cats = set(group.get("categories", []) or [])
    types = set(group.get("types", []) or [])
    rules = set(group.get("rules", []) or [])
    out = []
    for e in evidence:
        if e.severity.rank < min_sev:
            continue
        match = False
        if rules and e.rule_id and (e.rule_id in rules):
            match = True
        if types and e.type in types and (not cats or e.category in cats):
            match = True
        elif cats and not types and e.category in cats:
            match = True
        if match:
            out.append(e)
    out.sort(key=lambda e: e.weight, reverse=True)
    return out if len(out) >= int(group.get("min_count", 1)) else []


def _noisy_or(values: list[float]) -> float:
    p = 1.0
    for v in values:
        p *= 1.0 - max(0.0, min(0.99, v))
    return 1.0 - p


def correlate(ctx: AnalysisContext, pack: RulePack) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    used: set[str] = set()
    for unit_root, ids in _units(ctx):
        unit_ev = [e for e in ctx.evidence if e.artifact_id in ids]
        for rule in pack.correlations:
            scopes = [(unit_root, unit_ev)]
            if rule.get("scope") == "artifact":
                scopes = [(aid, [e for e in unit_ev if e.artifact_id == aid]) for aid in ids]
            for scope_id, ev in scopes:
                required_hits = []
                ok = True
                for group in rule["requires"]:
                    hits = _group_match(group, ev)
                    if not hits:
                        ok = False
                        break
                    required_hits.append(hits[:4])
                if not ok:
                    continue
                req_flat = {e.ref: e for hs in required_hits for e in hs}
                supporting = {}
                sup_groups = 0
                for group in rule.get("supporting", []) or []:
                    hits = [e for e in _group_match(group, ev) if e.ref not in req_flat]
                    if hits:
                        sup_groups += 1
                        for e in hits[:3]:
                            supporting[e.ref] = e
                members = list(req_flat.values()) + list(supporting.values())
                sources = {e.source for e in members}
                if len(sources) < int(rule.get("min_sources", 1)):
                    continue
                base = _noisy_or([max(e.confidence * e.reliability.factor for e in hs) * 0.85 for hs in required_hits])
                conf = min(0.97, base + 0.05 * sup_groups + 0.04 * max(0, len(sources) - 1))
                if len(sources) >= 3 and conf >= 0.72 or (conf >= 0.8 and len(sources) >= 2):
                    strength = FindingStrength.STRONG
                elif conf >= 0.5:
                    strength = FindingStrength.MODERATE
                else:
                    strength = FindingStrength.WEAK
                severity = rule.get("severity", "medium")
                if strength == FindingStrength.WEAK:
                    severity = _down(severity)
                mitre = sorted({t for e in members for t in e.mitre} | set(rule.get("mitre", []) or []))
                arts = sorted({e.artifact_id for e in members if e.artifact_id})
                where = [_where(ctx, a) for a in arts]
                limitations = list(GENERIC_LIMITATIONS)
                for a in arts:
                    limitations += ctx.by_id[a].limitations[:3]
                if len(sources) == 1:
                    limitations.append("All supporting evidence comes from a single engine; corroboration from other engines is missing.")
                findings.append({
                    "title": rule["title"], "kind": "correlated", "category": rule.get("category", "info"),
                    "severity": severity, "confidence": round(conf, 3), "strength": strength.value,
                    "needs_review": strength != FindingStrength.STRONG,
                    "what": rule.get("what", rule["title"]),
                    "why": rule.get("why", ""),
                    "where": where,
                    "limitations": limitations,
                    "recommendation": rule.get("recommendation"),
                    "hypothesis": rule.get("hypothesis"),
                    "rule_id": rule["id"],
                    "mitre": mitre,
                    "evidence": [{"ref": e.ref, "role": "required"} for e in req_flat.values()]
                                + [{"ref": e.ref, "role": "supporting"} for e in supporting.values()],
                    "sources": sorted(sources),
                    "scope": scope_id,
                })
                used.update(e.ref for e in members)
    # Dedupe identical rule hits across scopes: keep strongest
    best: dict[tuple, dict] = {}
    for f in findings:
        key = (f["rule_id"], f["scope"])
        if key not in best or f["confidence"] > best[key]["confidence"]:
            best[key] = f
    findings = list(best.values())

    # Leftover high-severity evidence that belongs to an existing correlated finding's
    # category/artifact becomes context of that finding instead of a duplicate.
    by_ref = {e.ref: e for e in ctx.evidence}
    for e in ctx.evidence:
        if e.ref in used or e.severity.rank < Severity.HIGH.rank:
            continue
        for f in findings:
            f_arts = {by_ref[x["ref"]].artifact_id for x in f["evidence"] if x["ref"] in by_ref}
            if f["category"] == e.category and e.artifact_id in f_arts:
                f["evidence"].append({"ref": e.ref, "role": "context"})
                used.add(e.ref)
                break
    # Leftover strong indicators -> individual indicator findings (need review)
    for e in ctx.evidence:
        if e.ref in used or e.severity.rank < Severity.HIGH.rank:
            continue
        strength = FindingStrength.MODERATE if e.reliability.value == "high" and e.confidence >= 0.7 else FindingStrength.WEAK
        findings.append({
            "title": e.title, "kind": "indicator", "category": e.category,
            "severity": e.severity.value if strength == FindingStrength.MODERATE else _down(e.severity.value),
            "confidence": round(e.confidence * e.reliability.factor * 0.8, 3), "strength": strength.value,
            "needs_review": True, "what": e.title, "why": e.description,
            "where": [_where(ctx, e.artifact_id)] if e.artifact_id else [],
            "limitations": GENERIC_LIMITATIONS + ["Single observation: no other evidence corroborates it yet."],
            "recommendation": "Review the evidence in context; a single indicator is not sufficient for a verdict.",
            "hypothesis": None, "rule_id": e.rule_id, "mitre": list(e.mitre),
            "evidence": [{"ref": e.ref, "role": "required"}], "sources": [e.source], "scope": e.artifact_id,
        })
        used.add(e.ref)
    # Remaining medium observations grouped per category -> weak indicator findings
    by_cat: dict[str, list[EvidenceItem]] = defaultdict(list)
    for e in ctx.evidence:
        if e.ref not in used and e.severity.rank == Severity.MEDIUM.rank:
            by_cat[e.category].append(e)
    for cat, items in by_cat.items():
        items.sort(key=lambda e: e.weight, reverse=True)
        label = CATEGORIES.get(cat, cat)
        findings.append({
            "title": f"Weak indicators: {label.lower()}", "kind": "indicator", "category": cat,
            "severity": "low", "confidence": round(min(0.6, _noisy_or([e.confidence * 0.4 for e in items])), 3),
            "strength": FindingStrength.WEAK.value, "needs_review": False,
            "what": f"{len(items)} medium-severity observation(s) related to {label.lower()} that did not correlate with other behaviour.",
            "why": "Kept for completeness: individually these are common in legitimate software.",
            "where": sorted({_where(ctx, e.artifact_id) for e in items if e.artifact_id}, key=str)[:10],
            "limitations": GENERIC_LIMITATIONS, "recommendation": None, "hypothesis": None, "rule_id": None,
            "mitre": sorted({t for e in items for t in e.mitre}),
            "evidence": [{"ref": e.ref, "role": "supporting"} for e in items[:25]], "sources": sorted({e.source for e in items}),
            "scope": None,
        })
    for f in findings:
        f["score"] = round(FINDING_BASE.get(f["severity"], 10) * (0.5 + 0.5 * f["confidence"])
                           * (1.0 if f["kind"] == "correlated" else 0.7), 1)
    findings.sort(key=lambda f: (-f["score"], f["title"]))
    for i, f in enumerate(findings, 1):
        f["ref"] = f"F-{i:03d}"
    return findings


def _where(ctx: AnalysisContext, artifact_id: str | None) -> str:
    if not artifact_id or artifact_id not in ctx.by_id:
        return "analysis"
    a = ctx.by_id[artifact_id]
    if a.path_in_archive:
        chain = []
        cur = a
        while cur.parent_id:
            chain.append(cur.path_in_archive or cur.display_name)
            cur = ctx.by_id.get(cur.parent_id)
            if cur is None:
                break
        root = cur.display_name if cur else "?"
        return " › ".join([root] + list(reversed(chain)))
    return a.display_name


# ------------------------------------------------------------------------------ risk
def _dimension(evidence: list[EvidenceItem], cats: list[str]) -> tuple[int, list[dict[str, Any]]]:
    items = sorted((e for e in evidence if e.category in cats and e.severity.rank >= 1), key=lambda e: e.weight, reverse=True)
    weights = []
    reasons = []
    for k, e in enumerate(items[:10]):
        w = e.weight * (0.85 ** k)
        weights.append(w)
        if k < 6:
            reasons.append({"ref": e.ref, "title": e.title, "contribution": round(w * 100, 1)})
    return int(round(100 * _noisy_or(weights))), reasons


def risk_model(ctx: AnalysisContext, findings: list[dict[str, Any]]) -> dict[str, Any]:
    ev = ctx.evidence
    dims = {}
    for key, (label, cats) in RISK_DIMENSIONS.items():
        score, reasons = _dimension(ev, cats)
        dims[key] = {"label": label, "score": score, "reasons": reasons}
    if any(e.category in ("vulnerability", "secret", "code") for e in ev):
        for key, (label, cats) in APPSEC_DIMENSIONS.items():
            score, reasons = _dimension(ev, cats)
            dims[key] = {"label": label, "score": score, "reasons": reasons}
    static_score, static_reasons = _dimension(ev, [c for c in CATEGORIES if c not in ("info", "signature")])
    dims = {"static_suspicion": {"label": "Static suspicion", "score": static_score, "reasons": static_reasons}, **dims}
    top = max((f["score"] for f in findings if f["kind"] in ("correlated", "appsec")), default=0)
    top_ind = max((f["score"] for f in findings if f["kind"] == "indicator"), default=0)
    overall = int(round(min(100, max(static_score * 0.6, top, top_ind * 0.75))))
    return {
        "overall": overall, "dimensions": dims,
        "note": "Scores are operational summaries derived from the evidence below — not ground truth.",
    }


def classify(ctx: AnalysisContext, findings: list[dict[str, Any]]) -> tuple[str, str]:
    correlated = [f for f in findings if f["kind"] == "correlated"]
    strong_high = [f for f in correlated if f["strength"] == "strong" and _sev(f["severity"]) >= 3]
    moderate_high = [f for f in correlated if f["strength"] in ("strong", "moderate") and _sev(f["severity"]) >= 3]
    hypotheses = {f["hypothesis"] for f in moderate_high}
    if strong_high or len(hypotheses) >= 3:
        return Classification.MALICIOUS_INDICATORS.value, (
            "Multiple independent engines corroborate high-severity behaviour" if strong_high
            else "Several distinct high-severity behaviours were correlated")
    if moderate_high or any(f["strength"] == "strong" for f in correlated):
        return Classification.HIGHLY_SUSPICIOUS.value, "Correlated high-severity behaviour with moderate support"
    detection = [e for e in ctx.evidence if e.source in ("heuristic_engine", "yara_engine") and e.severity.rank >= 2]
    if correlated or any(f["kind"] == "indicator" and _sev(f["severity"]) >= 2 for f in findings) or detection:
        return Classification.SUSPICIOUS.value, "Suspicious indicators present but not strongly corroborated"
    identified = any(a.detected_type not in ("unknown", "empty") for a in ctx.artifacts)
    if not identified and not ctx.evidence:
        return Classification.UNKNOWN.value, "Format not identified and no indicators extracted"
    return Classification.BENIGN_INDICATORS.value, "No suspicious behaviour correlated; only informational/low observations"


# ------------------------------------------------------------------------------ MITRE
def map_mitre(ctx: AnalysisContext, pack: RulePack, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    techs: dict[str, dict[str, Any]] = {}
    for e in ctx.evidence:
        if not e.mitre or e.confidence < 0.4 or e.severity.rank < 1:
            continue
        for t in e.mitre:
            rec = techs.setdefault(t, {"evidence": [], "conf": [], "sources": set(), "reasons": [], "findings": set()})
            rec["evidence"].append(e.ref)
            rec["conf"].append(e.confidence * e.reliability.factor)
            rec["sources"].add(e.rule_id or e.source)
            if len(rec["reasons"]) < 4:
                rec["reasons"].append(e.title)
    for f in findings:
        for t in f.get("mitre", []):
            if t in techs:
                techs[t]["findings"].add(f["ref"])
    out = []
    for tid, rec in techs.items():
        info = pack.mitre.get(tid, {})
        conf = min(0.95, _noisy_or([c * 0.7 for c in rec["conf"]]))
        out.append({
            "technique_id": tid, "name": info.get("name", "Technique not in local catalog"),
            "tactics": info.get("tactics", []), "evidence": rec["evidence"][:50], "findings": sorted(rec["findings"]),
            "reason": "; ".join(rec["reasons"]), "confidence": round(conf, 3), "sources": sorted(rec["sources"])[:20],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    out.sort(key=lambda r: (-r["confidence"], r["technique_id"]))
    return out


# ------------------------------------------------------------------------------ summary
def capabilities(ctx: AnalysisContext) -> list[dict[str, Any]]:
    caps = defaultdict(list)
    for e in ctx.evidence:
        if e.severity.rank >= 1 and e.category not in ("info", "signature", "structure", "yara", "ioc"):
            caps[e.category].append(e)
    out = []
    for cat, items in caps.items():
        items.sort(key=lambda e: e.weight, reverse=True)
        out.append({"category": cat, "label": CATEGORIES.get(cat, cat), "count": len(items),
                    "max_severity": max(items, key=lambda e: e.severity.rank).severity.value,
                    "evidence": [e.ref for e in items[:10]]})
    out.sort(key=lambda c: (-_sev(c["max_severity"]), -c["count"]))
    return out


def investigation_summary(ctx: AnalysisContext, findings: list[dict[str, Any]], classification: str, reason: str) -> dict[str, Any]:
    ev = ctx.evidence
    correlated_refs = {x["ref"] for f in findings if f["kind"] == "correlated" for x in f["evidence"]}
    interesting = [e.ref for e in ev if e.severity.rank >= 1]
    suspicious = [e.ref for e in ev if e.severity.rank >= 2]
    strong = [f["ref"] for f in findings if f["strength"] == "strong"]
    review = [f["ref"] for f in findings if f["needs_review"]]
    weak = [f["ref"] for f in findings if f["strength"] == "weak"]
    main = next((f for f in findings if f["kind"] in ("correlated", "appsec")), None) or (findings[0] if findings else None)
    chain = [
        {"stage": "observations", "label": "Observations", "count": len(ev), "refs": [e.ref for e in ev][:500]},
        {"stage": "interesting", "label": "Interesting", "count": len(interesting), "refs": interesting[:500]},
        {"stage": "suspicious", "label": "Suspicious", "count": len(suspicious), "refs": suspicious[:500]},
        {"stage": "correlated", "label": "Correlated", "count": len(correlated_refs), "refs": sorted(correlated_refs)[:500]},
        {"stage": "strong", "label": "Strong findings", "count": len(strong), "refs": strong},
        {"stage": "hypothesis", "label": "Main hypothesis", "count": 1 if main else 0, "refs": [main["ref"]] if main else []},
    ]
    lines = [f"I found {len(ev)} observations across {len(ctx.artifacts)} artifact(s)."]
    lines.append(f"After correlation: {len(findings)} potential finding(s).")
    if strong:
        lines.append(f"{len(strong)} finding(s) have strong supporting evidence.")
    if review:
        lines.append(f"{len(review)} require manual review.")
    if weak:
        lines.append(f"{len(weak)} are weak indicators.")
    if main:
        lines.append(f"Main hypothesis: {main['title']} ({main['strength']}, confidence {main['confidence']:.0%}).")
    lines.append(f"Classification: {classification.replace('_', ' ')} — {reason}.")
    return {
        "narrative": lines, "observations": len(ev), "interesting": len(interesting), "suspicious": len(suspicious),
        "correlated": len(correlated_refs), "findings": len(findings), "strong": len(strong), "needs_review": len(review),
        "weak": len(weak), "main_hypothesis": {"ref": main["ref"], "title": main["title"], "hypothesis": main.get("hypothesis")} if main else None,
        "chain": chain, "classification": classification, "classification_reason": reason,
        "severity_counts": {s: sum(1 for f in findings if f["severity"] == s) for s in reversed(SEVERITY_ORDER)},
    }
