"""Report engine: JSON, Markdown and HTML (PDF is on the roadmap).

Every value that originates from a sample is treated as hostile text:
HTML is rendered by Jinja2 with autoescaping and a CSP that forbids scripts;
Markdown escapes metacharacters and puts raw values in safe code spans.
Secrets are already masked upstream; passwords never reach this layer.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.core.database import session_scope
from backend.core.storage import Storage
from backend.models.entities import Analysis, Artifact, Report
from backend.services import queries

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]),
                   trim_blocks=True, lstrip_blocks=True)


def build_model(s, a: Analysis, storage: Storage | None = None) -> dict[str, Any]:
    arts = s.query(Artifact).filter(Artifact.analysis_id == a.id).order_by(Artifact.depth, Artifact.display_name).all()
    artifacts = [queries.artifact_detail(x) for x in arts]
    findings = queries.findings_list(s, a.id)
    evidence = queries.evidence_list(s, a.id)
    reverse = {}
    if storage:
        for x in arts:
            if x.has_reverse:
                data = queries.reverse_data(storage, x)
                if data:
                    reverse[x.id] = {"arch": data.get("arch"), "engine": data.get("engine"), "function_count": data.get("function_count"),
                                     "functions": [{k: f[k] for k in ("address", "name", "imports", "callers", "callees")} for f in data["functions"]
                                                   if f.get("imports")][:40]}
    recs = []
    for f in findings:
        if f.get("recommendation") and f["recommendation"] not in recs and f["strength"] != "weak":
            recs.append(f["recommendation"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "MALX static analysis workbench",
        "analysis": queries.analysis_detail(s, a),
        "artifacts": artifacts,
        "findings": findings,
        "evidence": evidence,
        "iocs": queries.iocs_list(s, a.id),
        "mitre": queries.mitre_list(s, a.id),
        "yara": queries.yara_list(s, a.id),
        "timeline": queries.timeline_list(s, a.id),
        "appsec": queries.appsec_view(s, a) if a.appsec_json and a.appsec_json.get("enabled") else None,
        "reverse": reverse,
        "recommendations": recs[:20],
        "disclaimer": "MALX performs static analysis only; no submitted file was executed. Scores and classifications summarise "
                      "evidence and are not ground truth.",
    }


# ------------------------------------------------------------------------- Markdown
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")


def md(text: Any) -> str:
    """Escape sample-derived text for Markdown prose."""
    if text is None:
        return ""
    t = str(text).replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", t)


def code(text: Any, limit: int = 300) -> str:
    """Render a raw value as an inline code span that cannot be broken out of."""
    if text is None or text == "":
        return "—"
    t = str(text)[:limit].replace("\r", " ").replace("\n", " ").replace("|", "¦")
    longest = max((len(m) for m in re.findall(r"`+", t)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return f"{fence}{pad}{t}{pad}{fence}"


def render_markdown(m: dict[str, Any]) -> str:
    a = m["analysis"]
    s = a.get("summary") or {}
    risk = a.get("risk") or {}
    L: list[str] = []
    w = L.append
    w(f"# MALX Report — {md(a['name'])}")
    w("")
    w(f"> {md(m['disclaimer'])}")
    w("")
    w("## Executive Summary")
    w("")
    w(f"- **Classification:** {md((a.get('classification') or 'UNKNOWN').replace('_', ' '))}")
    w(f"- **Risk score:** {a.get('risk_score')} / 100 (operational summary, not ground truth)")
    if s.get("main_hypothesis"):
        w(f"- **Main hypothesis:** {md(s['main_hypothesis']['title'])} ({s['main_hypothesis']['ref']})")
    w(f"- **Analysis ID:** {code(a['id'])} — completed {md(a.get('completed_at'))}")
    w("")
    for line in s.get("narrative", []):
        w(f"- {md(line)}")
    w("")
    w("### Analysis chain")
    w("")
    w(" → ".join(f"{c['count']} {md(c['label'])}" for c in s.get("chain", [])))
    w("")
    w("## Sample Information")
    w("")
    w("| Artifact | Type | Size | SHA-256 | Mismatch |")
    w("|---|---|---|---|---|")
    for x in m["artifacts"]:
        w(f"| {code(x['path_in_archive'] or x['name'], 120)} | {md(x['type_label'])} | {x['size']} | {code(x['sha256'])} | {'⚠ yes' if x['extension_mismatch'] else 'no'} |")
    w("")
    w("## Hashes")
    for x in m["artifacts"][:50]:
        w("")
        w(f"**{md(x['name'])}**")
        w("")
        for k, v in x["hashes"].items():
            if v:
                w(f"- {k.upper()}: {code(v, 200)}")
    w("")
    w("## File Type")
    w("")
    for x in m["artifacts"][:50]:
        i = x["identification"]
        w(f"- {code(x['name'], 120)}: {md(i['label'])} (confidence {i['confidence']}, parser {code(i['parser'])}, magic {code(i['magic_hex'])}, extension {code(i['extension'])})"
          + (f" — ⚠ EXTENSION MISMATCH: {md(i['mismatch_reason'])}" if i["extension_mismatch"] else ""))
    w("")
    w("## Risk Summary")
    w("")
    w("| Dimension | Score | Top reasons |")
    w("|---|---|---|")
    for key, d in (risk.get("dimensions") or {}).items():
        reasons = "; ".join(f"{r['ref']} {md(r['title'])}" for r in d.get("reasons", [])[:3])
        w(f"| {md(d['label'])} | {d['score']} | {reasons} |")
    w("")
    w("## Findings")
    for f in m["findings"]:
        w("")
        w(f"### [{f['severity'].upper()}] {f['id']} — {md(f['title'])}")
        w("")
        w(f"- **What?** {md(f['what'])}")
        w(f"- **Where?** {', '.join(code(x, 160) for x in f['where'][:8]) or 'analysis'}")
        w(f"- **Why?** {md(f['why'])}")
        w(f"- **Evidence?** " + ", ".join(f"{e['id']} ({e['role']}: {md(e['title'])})" for e in f["evidence"][:12]))
        w(f"- **Confidence?** {f['confidence']:.0%} ({f['strength']}{', needs manual review' if f['needs_review'] else ''})")
        w(f"- **Limitations?** " + " ".join(md(x) for x in f["limitations"][:4]))
        if f.get("mitre"):
            w(f"- **MITRE ATT&CK:** {', '.join(f['mitre'])}")
        if f.get("recommendation"):
            w(f"- **Recommendation:** {md(f['recommendation'])}")
    w("")
    w("## MITRE ATT&CK")
    w("")
    w("| Technique | Name | Confidence | Evidence | Reason |")
    w("|---|---|---|---|---|")
    for t in m["mitre"]:
        w(f"| {t['technique_id']} | {md(t['name'])} | {t['confidence']:.0%} | {', '.join(t['evidence'][:6])} | {md(t['reason'][:200])} |")
    w("")
    w("## YARA")
    w("")
    for y in m["yara"]:
        w(f"- {code(y['rule'])} ({y['severity']}) — {md(y['description'])} — {len(y['strings'])} matched string(s); author {md(y['author'])}; reference {code(y['reference'], 200)}")
    if not m["yara"]:
        w("No YARA rule matched.")
    w("")
    w("## IOCs")
    w("")
    w("| Type | Value | Context |")
    w("|---|---|---|")
    for i in m["iocs"][:1000]:
        w(f"| {i['type']} | {code(i['value'], 200)} | {'common reference' if i['common'] else ''} |")
    w("")
    w("## Static Analysis")
    for x in m["artifacts"][:30]:
        meta = x["metadata"]
        if "pe" in meta and isinstance(meta["pe"], dict) and "sections" in meta["pe"]:
            pe = meta["pe"]
            w("")
            w(f"### PE — {md(x['name'])}")
            w("")
            w("| Section | Perms | Raw size | Entropy |")
            w("|---|---|---|---|")
            for sec in pe["sections"]:
                w(f"| {code(sec['name'])} | {sec['permissions']} | {sec['raw_size']} | {sec['entropy']} |")
            w("")
            w("**Imports**")
            w("")
            for imp in pe.get("imports", [])[:40]:
                w(f"- {code(imp['dll'])}: {', '.join(code(fn, 60) for fn in imp['functions'][:30])}")
            if pe.get("resources"):
                w("")
                w("**Resources**")
                w("")
                for r in pe["resources"][:40]:
                    w(f"- {code(r['type'])}/{code(r['name'])} size {r['size']} entropy {r['entropy']} {md(r.get('magic') or '')}")
        if "elf" in meta and isinstance(meta["elf"], dict) and "sections" in meta["elf"]:
            w("")
            w(f"### ELF — {md(x['name'])}")
            w("")
            w(f"- Interpreter: {code(meta['elf'].get('interpreter'))}; NEEDED: {', '.join(code(n) for n in meta['elf'].get('needed', [])[:30])}")
    w("")
    w("## Reverse Engineering")
    w("")
    if m["reverse"]:
        for aid, r in m["reverse"].items():
            w(f"- {code(aid)}: {r['function_count']} functions ({md(r['engine'])}, {r['arch']})")
            for f in r["functions"][:15]:
                w(f"  - {code(f['name'])} @ {f['address']}: {', '.join(code(i, 60) for i in f['imports'][:8])}")
    else:
        w("No native code was disassembled.")
    if m.get("appsec"):
        ap = m["appsec"]
        w("")
        w("## Application Security")
        w("")
        w(f"- Languages: {', '.join(md(l['language']) + ' (' + str(l['files']) + ')' for l in ap.get('languages', []))}")
        w(f"- Frameworks: {', '.join(md(x) for x in ap.get('frameworks', [])) or '—'}")
        w(f"- Dependencies: {len(ap.get('dependencies', []))}; vulnerable: {len(ap.get('vulnerabilities', []))}")
        w(f"- Endpoints: {len(ap.get('endpoints', []))}; secrets: {len(ap.get('secrets', []))} (masked)")
    w("")
    w("## Evidence")
    w("")
    w("| ID | Severity | Source | Title | Value |")
    w("|---|---|---|---|---|")
    for e in m["evidence"][:2000]:
        w(f"| {e['id']} | {e['severity']} | {md(e['source_label'])} | {md(e['title'][:120])} | {code(e['value'], 120)} |")
    w("")
    w("## Recommendations")
    w("")
    for r in m["recommendations"] or ["No specific recommendation: review the findings above."]:
        w(f"- {md(r)}")
    w("")
    w("## Technical Appendix")
    w("")
    w("### Limitations")
    for lim in a.get("limitations") or []:
        w(f"- {md(lim)}")
    w("")
    w("### Engines")
    w("")
    w(code(json.dumps(a.get("engines") or {}, default=str), 2000))
    w("")
    return "\n".join(L)


def render_html(m: dict[str, Any]) -> str:
    return _env.get_template("report.html.j2").render(m=m)


def render_json(m: dict[str, Any]) -> str:
    return json.dumps(m, indent=2, default=str)


def generate_reports(analysis_id: str, storage: Storage) -> list[dict[str, Any]]:
    out = []
    with session_scope() as s:
        a = s.get(Analysis, analysis_id)
        if a is None:
            return out
        model = build_model(s, a, storage)
        rdir = storage.reports_dir(analysis_id, create=True)
        s.query(Report).filter(Report.analysis_id == analysis_id).delete()
        for fmt, renderer, ext in (("json", render_json, "json"), ("markdown", render_markdown, "md"), ("html", render_html, "html")):
            content = renderer(model).encode("utf-8")
            path = rdir / f"report.{ext}"
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(content)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            rel = storage.relative(path)
            s.add(Report(analysis_id=analysis_id, format=fmt, storage_path=rel, size=len(content),
                         sha256=hashlib.sha256(content).hexdigest()))
            out.append({"format": fmt, "path": rel, "size": len(content)})
    return out
