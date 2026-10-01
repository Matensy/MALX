# MALX — Malware Analysis & Security Workbench

> **Evidence-first security analysis.** MALX doesn't just say "malicious" or "safe" — it shows the
> chain of evidence behind every conclusion. And it **never executes the files you give it.**

MALX is a local, browser-based investigation workbench for potentially hostile files, applications
and projects. It combines static analysis, reverse-engineering assistance, YARA, declarative
heuristics and evidence correlation — without any AI/LLM dependency — and presents the result as an
investigation: findings that answer *what / where / why / evidence / confidence / limitations*, an
evidence graph, a timeline, MITRE ATT&CK mapping, an IOC center and reproducible reports.

**Resumo (PT-BR):** MALX é uma bancada local de análise de malware e segurança de aplicações.
Faz análise estática, engenharia reversa assistida, YARA, heurísticas declarativas e correlação de
evidências; mostra *por que* chegou a cada conclusão; roda 100% offline e **nunca executa os
arquivos enviados**.

```
37 Observations → 21 Interesting → 12 Suspicious → 8 Correlated → 3 Strong Findings → 1 Main Hypothesis
```

## Quick start

```bash
# Python 3.11+ and Node 20+
python -m pip install -e ".[full]"
cd frontend && npm install && npm run build && cd ..
malx                                   # → http://127.0.0.1:8000
```

or with Docker:

```bash
docker compose up --build              # → http://127.0.0.1:8000
```

Command line: `malx analyze suspicious.exe` prints a JSON summary.
Synthetic, harmless demo samples: `python scripts/generate_samples.py` → `tests/samples/generated/`.

## What it does

| Area | Highlights |
|---|---|
| **Safe intake** | Streaming upload straight into quarantine under UUID names (0400, never served), size/count limits, archive password kept in memory only |
| **Identification** | Magic bytes + structure for PE, ELF, Mach-O, APK, DEX, JAR/class, ZIP/TAR/7z/gzip, PDF, OOXML, OLE, RTF, LNK, scripts, images, databases…; **⚠ EXTENSION MISMATCH**, double extensions, RTLO names |
| **Hashes** | MD5, SHA1, **SHA256** (primary id), SHA512, ssdeep, TLSH |
| **Archives** | Recursive, defensive extraction: ZipSlip/absolute/drive paths, symlinks, devices, duplicate names, bombs (ratio, size, count, depth), AES/ZipCrypto/7z passwords |
| **Strings & IOCs** | ASCII/UTF-8/UTF-16, classification NORMAL → HIGH_RISK, URLs, domains, IPv4/6, e-mails, paths, registry, mutexes, hashes, user agents, onion, validated wallets; offline context (common references, dynamic DNS, paste/chat/tunnel services, unusual ports) |
| **PE** | Headers, sections (entropy, RWX), imports/imphash, exports, resources, TLS callbacks, debug/PDB, version info, manifest, Authenticode certificates, overlay, Rich header, .NET metadata (#Strings/#US), packer/installer/compiler fingerprints |
| **ELF / Mach-O** | Segments/sections, RWX/exec-stack, interpreter, NEEDED, RPATH/RUNPATH, dynamic symbols, hardening properties; Mach-O load commands |
| **Documents** | PDF (keywords incl. hex-obfuscated names, Flate streams, JavaScript, actions, polyglots), OOXML (external templates, DDE, XLM, embeddings), OLE/VBA (MS-OVBA decompression — read, never run), RTF objects, LNK targets |
| **Android / Java** | Binary AndroidManifest parser, permissions, exported components, accessibility/device-admin, DEX strings, JAR/class constant pools |
| **Scripts** | PowerShell `-EncodedCommand`, base64/hex/char-code/concatenation/backtick deobfuscation; decoded binaries become artifacts; HTML smuggling |
| **YARA** | 24 bundled technique rules + your own; matches with offsets and strings |
| **Reverse engineering** | Built-in Capstone disassembly: functions, call graph, callers/callees, xrefs, import/string references, per-function API-sequence evidence; capa, FLOSS and radare2 used automatically when installed |
| **Heuristics** | ~90 declarative YAML rules (execution, persistence, injection, credential access, network, evasion, impact, documents, archives, mobile, Linux, scripts) — each with explanation, legitimate uses and ATT&CK ids |
| **Correlation** | Many observations → one investigation finding; multi-engine requirement; strong/moderate/weak; manual-review flags |
| **Risk & classification** | Dimensioned scores with reasons; UNKNOWN / BENIGN_INDICATORS / SUSPICIOUS / HIGHLY_SUSPICIOUS / MALICIOUS_INDICATORS — never from a single rule |
| **Application security** | Languages, frameworks, endpoints, ~45 code-weakness rules (CWE), 20 secret patterns (masked), dependency manifests (pip/poetry/npm/yarn/Maven/Gradle/Go/Cargo/Composer/RubyGems/NuGet), local OSV advisories, attack-surface map |
| **Investigation UI** | Dashboard, live pipeline, automatic investigation narrative, clickable analysis chain, navigable evidence graph, investigation board (drag, connect, hypotheses, states), timeline, IOC center, MITRE matrix, global search |
| **Reports** | HTML (script-free, escaped), Markdown, JSON; evidence/IOC/analysis exports (TXT/CSV/JSON) |

## Security model

* No sample is executed, imported, loaded or opened with a default application — enforced by an
  AST test over the backend.
* One fresh worker process per analysis: memory/CPU/file-size limits, no core dumps,
  `no_new_privs`, private network namespace (or socket guard), no database access.
* Localhost-only server with Host allow-list (DNS-rebinding protection) and CSRF header.
* Offline by default: **YOUR FILES STAY LOCAL** · **External integrations: DISABLED**.

Details: [docs/security.md](docs/security.md).

## Documentation

* [Architecture & evidence model](docs/architecture.md)
* [Security design](docs/security.md)
* [Writing rules](docs/rules.md) (heuristics, correlation, YARA, AppSec)
* [REST API](docs/api.md)
* [Development, tests & spec coverage](docs/development.md)

## Project layout

```
backend/   api · core · models · services · analyzers · rules · workers · reports
frontend/  React + TypeScript + Vite + Tailwind + React Flow
rules/     yara · heuristics · correlation · signatures · mitre · appsec · advisories
storage/   quarantine · extracted · evidence · reports   (runtime, git-ignored)
tests/     unit, end-to-end and security tests + synthetic sample factory
docker/    Dockerfile        docker-compose.yml   scripts/
```

> Scores are operational summaries, not absolute truth. A technique can be legitimate in legitimate
> software — MALX builds a chain of evidence instead of trusting a single detection.
