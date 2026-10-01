# REST API

Base URL `http://127.0.0.1:8000/api` · interactive docs at `/api/docs`.
State-changing requests (POST/PUT/PATCH/DELETE) must send `X-MALX-Request: 1`.

| Method | Path | Description |
|---|---|---|
| POST | `/analyses` | multipart: `files` (1..N), `mode` (`auto`/`malware`/`appsec`), `password`, `name`, `notes` |
| GET | `/analyses` | list (`limit`, `offset`, `q`, `status`) |
| GET | `/analyses/{id}` | detail: status, progress, classification, risk, investigation summary, artifacts |
| DELETE | `/analyses/{id}` | delete and purge quarantine/extracted/evidence/reports |
| POST | `/analyses/{id}/cancel` | cancel a queued/running analysis |
| POST | `/analyses/{id}/reanalyze` | re-run on the quarantined files |
| GET | `/analyses/{id}/findings` | findings with What/Where/Why/Evidence/Confidence/Limitations |
| POST | `/analyses/{id}/findings` | analyst finding (`title`, `severity`, `evidence` refs, `status`) |
| PATCH | `/analyses/{id}/findings/{ref}` | analyst state / note |
| GET | `/analyses/{id}/findings/{ref}/chain` | Sample → Parser → Observation → Heuristic → Correlation → Finding → Classification |
| GET | `/analyses/{id}/evidence` | all evidence (spec §41 format) |
| PATCH | `/analyses/{id}/evidence/{ref}` | analyst state / note |
| GET | `/analyses/{id}/iocs` | `format=json|json-download|csv|txt`, `defang`, `include_common`, `type` |
| GET | `/analyses/{id}/graph` | evidence graph (`include_weak`) |
| GET | `/analyses/{id}/timeline` | pipeline and artifact timestamps |
| GET | `/analyses/{id}/mitre` | ATT&CK techniques with evidence, reason, confidence, source |
| GET | `/analyses/{id}/yara` | YARA matches with offsets and matched strings |
| GET | `/analyses/{id}/appsec` | languages, frameworks, endpoints, dependencies, vulnerabilities, secrets (masked), attack surface |
| GET/PUT | `/analyses/{id}/board` | investigation board |
| GET | `/analyses/{id}/report` | `format=html|md|json` (`download=true`) |
| GET | `/analyses/{id}/export/{evidence|findings|analysis}` | JSON exports |
| GET | `/analyses/{id}/artifacts[/{aid}]` | artifacts / full metadata |
| GET | `/analyses/{id}/artifacts/{aid}/strings` | `classification`, `q`, `offset`, `limit` |
| GET | `/analyses/{id}/artifacts/{aid}/hex` | `offset`, `length ≤ 4096` — hex text, never raw bytes |
| GET | `/analyses/{id}/artifacts/{aid}/functions[/{address}]` | disassembly, callers/callees, xrefs, strings, imports, related findings |
| GET | `/iocs` | global IOC center |
| GET | `/search?q=` | SHA256, filename, URL, domain, IP, API, string, IOC, finding, MITRE |
| GET | `/system`, `/rules`, `/stats`, `/health` | system information |

CLI: `malx analyze FILE… [--mode appsec] [--password …]` prints a JSON summary.
