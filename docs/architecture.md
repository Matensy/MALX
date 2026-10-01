# Architecture

```
Browser (React UI)
   │  HTTP (127.0.0.1 only, Host allow-list, X-MALX-Request on writes)
   ▼
FastAPI API ── streaming upload ──► storage/quarantine/<analysis_id>/<uuid>.bin (0400)
   │                                   (original name kept as data only)
   │  Analysis row (QUEUED) + in-memory password
   ▼
JobManager (dispatcher threads)
   │  multiprocessing "spawn" → one fresh worker process per analysis
   ▼
Worker process  (rlimits · no_new_privs · private netns or socket guard · scratch dir)
   │  run_pipeline(job) → result.json   (no DB credentials, no network)
   ▼
JobManager → ingest() → SQLite (SQLAlchemy; any URL works, e.g. PostgreSQL)
           → reports (JSON / Markdown / HTML)
```

## Pipeline (spec §12)

| Stage | Module |
|---|---|
| Upload / quarantine | `backend/api/upload.py`, `backend/core/storage.py` |
| Validation | `backend/workers/pipeline.py` (`_new_artifact`), `backend/core/security.py` |
| Identification | `backend/analyzers/identify.py` — magic bytes + structure; extension is auxiliary |
| Hashing | `backend/analyzers/hashing.py` — MD5/SHA1/SHA256/SHA512, ssdeep (ppdeep), TLSH (native or pure-Python port, validated against the reference) |
| Extraction | `backend/analyzers/archive.py` — ZIP (incl. AES), TAR, gzip/bz2/xz, 7z; recursive within limits |
| Static analysis | `strings_engine.py`, `entropy.py` |
| Specialised analysis | `pe.py`, `elf.py` (ELF + Mach-O), `documents.py` (PDF/OOXML/OLE+VBA/RTF/LNK), `android.py` (APK/AXML/DEX/JAR/class), `scripts.py` |
| YARA | `yara_engine.py` + `rules/yara/` |
| Reverse engineering | `reverse.py` (Capstone recursive descent) + `backend/services/tools.py` (capa, FLOSS, radare2, Ghidra when installed) |
| Heuristics | `heuristics.py` + `rules/heuristics/*.yaml` |
| IOC extraction | `ioc.py` + `rules/signatures/network.yaml` |
| Application security | `appsec.py` + `rules/appsec/*.yaml`, `rules/advisories/` |
| Correlation / risk / MITRE / classification | `correlation.py` + `rules/correlation/`, `rules/mitre/` |
| Findings / report | `backend/services/persist.py`, `backend/reports/generator.py` |

Statuses: `QUEUED → VALIDATING → EXTRACTING → ANALYZING → CORRELATING → REPORTING → COMPLETED | FAILED | CANCELLED`.

## Evidence model

Every engine records `EvidenceItem`s (`backend/analyzers/base.py`):

```json
{
  "id": "EV-0012", "type": "suspicious_import", "source": "pe_analyzer", "artifact": "sample.exe",
  "value": "VirtualAlloc", "severity": "low", "confidence": 0.55, "reliability": "high",
  "description": "Allocates virtual memory… Legitimate uses: JIT compilers…",
  "details": {...}, "mitre": [], "related_findings": ["F-002"]
}
```

* **Findings** are built only from evidence. *Correlated* findings need every `requires` group
  of a correlation rule to be satisfied, from at least `min_sources` distinct engines. Leftover
  high-severity observations become *indicator* findings that always need manual review; leftover
  medium ones are grouped as weak indicators.
* Correlation **units**: a submitted file plus the content that belongs to it (document → embedded
  objects/macros, APK → DEX, script → decoded payload). Members of plain archives are separate
  units, so unrelated files sharing a ZIP are never correlated with each other.
* **Risk model**: per dimension, noisy-OR of `severity weight × confidence × reliability` with
  diminishing returns; every score lists the evidence that produced it.
* **Classification**: `MALICIOUS_INDICATORS` requires a *strong* correlated high/critical finding
  (≥ 3 engines or ≥ 2 engines with ≥ 0.8 confidence) or three distinct correlated hypotheses. A
  single heuristic can never produce it.
* **MITRE ATT&CK**: mapped only when an evidence item with confidence ≥ 0.4 references a technique.

## Data model (spec §10)

| Spec entity | Implementation |
|---|---|
| Analysis, Report, Finding, Evidence, IOC, YaraMatch, Dependency, Vulnerability | dedicated tables |
| MITRETechnique | `mitre_mappings` |
| Sample / Artifact / File / Hash | `artifacts` (roots have `parent_id = NULL`; hashes are columns, SHA-256 primary) |
| String | `strings` (most relevant strings per artifact; the full set is used during analysis) |
| PEMetadata / ELFMetadata | `artifacts.metadata_json["pe" / "elf"]` |
| Network/Registry/Process indicators | IOC types + evidence categories |
| RuleMatch | evidence rows with `rule_id` |

Evidence ↔ finding links live in `finding_evidence` (role: `required` / `supporting` / `context`).
The investigation board is stored as JSON on the analysis.

## Frontend

React + TypeScript + Vite + Tailwind v4, React Flow (+ dagre) for the analysis graph, call graph,
attack surface and investigation board. The production build is served by FastAPI from
`frontend/dist`; during development Vite proxies `/api`.
