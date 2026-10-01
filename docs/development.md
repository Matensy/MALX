# Development

## Setup

```bash
python -m pip install -e ".[full,dev]"     # yara-python, capstone, py7zr, pyzipper, pytest
cd frontend && npm install && cd ..
./scripts/dev.sh                           # API :8000 (reload) + Vite :5173 (proxy /api)
```

Production-style run: `cd frontend && npm run build && cd .. && malx` → http://127.0.0.1:8000

## Tests

```bash
pytest                    # ~120 tests: parsers, extraction defences, rules, correlation, API, security (§60–61)
cd frontend && npm run typecheck
```

* Analyses run in `inline` worker mode in most tests for speed; `test_isolated_worker_process`
  and `test_worker_memory_limit_is_enforced` exercise the real spawned worker.
* Samples are synthetic and generated at test time (`tests/samples/factory.py`).
  `python scripts/generate_samples.py` writes them to `tests/samples/generated/` for manual use.

## Configuration

`malx.yaml` (or `MALX_CONFIG=…`), overridable with environment variables
(`MALX_LIMITS__MAX_UPLOAD_SIZE=100MB`, `MALX_WORKERS__MAX_CONCURRENT_ANALYSES=4`,
`MALX_STORAGE_DIR=/data`, `MALX_DATABASE_URL=postgresql+psycopg://…`, `MALX_HOME=/app`).

## Optional local tools

Install any of these and MALX uses them automatically (Settings shows what was found):

| Tool | Use |
|---|---|
| [capa](https://github.com/mandiant/capa) | capabilities with ATT&CK ids → evidence |
| [FLOSS](https://github.com/mandiant/flare-floss) | decoded/stack/tight strings → string & IOC engines |
| [radare2](https://rada.re) + r2ghidra/r2dec | pseudo-code for functions that reference APIs |
| Ghidra (`integrations.ghidra_home`) | detected for headless use |

All of them analyse the file statically; MALX passes the path as an argument and never runs the sample.

## Specification coverage

| Spec | Status |
|---|---|
| §2 No execution, §4–8 zero-trust upload, quarantine, limits, magic-byte identification | ✅ |
| §14–16 identification, hashes (incl. ssdeep, TLSH), strings & classification | ✅ |
| §17–21 PE, ELF, Mach-O (basic), APK/DEX/JAR, PDF/OOXML/OLE-VBA/RTF/LNK, archives (ZIP/TAR/7Z/GZ) | ✅ |
| §22–24, §56–58 YARA, declarative heuristics, correlation, false-positive context | ✅ |
| §25–28, §42–44 evidence graph, risk model, classification, MITRE, explanations, chain of analysis | ✅ |
| §29–31 reverse engineering: built-in disassembly/call graph/xrefs; capa/FLOSS/r2 integration | ✅ (Ghidra headless export: detection only) |
| §32–37 application security: languages, frameworks, endpoints, code rules, secrets, dependencies, local advisories, attack surface | ✅ |
| §38–40, §50–55, §66–71 investigation board, timeline, reports (HTML/MD/JSON), UI, search, IOC center, API, routes | ✅ |
| §45–47 job queue, isolated workers, containers | ✅ |
| §59–62 test lab, unit & security tests, logging rules | ✅ |
| PDF reports, STIX export | 🔜 roadmap (HTML report prints to PDF; STIX endpoint returns 501) |
| §48–49 dynamic analysis / sandbox | ❌ explicitly out of scope |

## Roadmap ideas

* Native PDF report rendering, STIX 2.1 export
* Ghidra headless post-script for decompilation export
* .NET IL disassembly; deeper Mach-O (code signature parsing)
* Redis/RQ queue and split API/worker containers (worker with `network_mode: none`)
* Optional, explicit external intelligence connectors (disabled by default)
