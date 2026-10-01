# Security design

**MALX never executes submitted files.** It is a static analysis, reverse-engineering and
correlation workbench. Every uploaded file is assumed hostile — including towards MALX itself.

## Controls

| Threat (spec §3) | Control | Where |
|---|---|---|
| Executing a sample | No `subprocess`/`os.system`/`exec`/dynamic import on sample data; enforced by an AST test | `tests/test_security.py::test_no_dynamic_execution_primitives_in_backend` |
| External tools | Allow-listed binaries only, argument lists, no shell, closed stdin, minimal env, timeout; tools *analyse* the file | `backend/services/tools.py` |
| Path traversal / hostile names | Original names are display data; storage uses `<uuid>.bin`; `ensure_within` on every resolved path; ZIP/TAR member names validated and flagged | `core/security.py`, `core/storage.py`, `analyzers/archive.py` |
| Symlinks / hardlinks / devices in archives | Recorded, never materialised | `archive.py` |
| Decompression bombs | Bytes produced are counted while streaming (headers are not trusted); per-member ratio, per-member size, per-analysis total, entry count read from EOCD before parsing, depth and artifact limits | `archive.py`, `malx.yaml` |
| Oversized uploads | Streaming multipart parser writes straight to quarantine, aborts at the limit and deletes the partial file | `api/upload.py` |
| Parser exploitation / DoS | Each analysis runs in a fresh `spawn` worker with `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CORE=0`, `PR_SET_NO_NEW_PRIVS`, umask 077; wall-clock deadline and cancellation enforced by the parent (terminate → kill) | `workers/sandbox.py`, `workers/manager.py` |
| SSRF / network from parsers | Worker enters a private network namespace when permitted, otherwise a socket guard refuses connections; XML parsed with `defusedxml` | `workers/sandbox.py`, `analyzers/documents.py` |
| Worker privileges | Worker has no database access: it only writes `result.json`; the parent ingests | `workers/worker.py` |
| Report injection (XSS, Markdown breakout) | Jinja2 autoescape + CSP `default-src 'none'` (no scripts) on HTML reports; Markdown escaping and fence-safe code spans; React escapes all text; report preview in a `sandbox=""` iframe | `reports/generator.py`, `frontend/src/pages/analysis/Report.tsx` |
| CSV injection in exports | Cells starting with `= + - @` are prefixed | `api/routes.py` |
| Serving samples | No download endpoint; the hex viewer returns hex text in JSON, at most 4 KiB per request | `api/routes.py` |
| CSRF / DNS rebinding against localhost | State-changing requests require `X-MALX-Request: 1` (forces a CORS preflight) and a same-origin `Origin`; `TrustedHostMiddleware` allow-list | `backend/main.py` |
| Secrets / passwords | Archive password lives only in memory (pipe to the worker); never logged, stored or reported; secrets are masked before storage; JSON log formatter redacts password/token patterns | `workers/manager.py`, `core/logging.py`, `analyzers/appsec.py` |
| Privacy | No external calls; external integrations disabled by default; works offline | `malx.yaml` → `integrations.external_enabled: false` |

## Limitations and recommendations

* Python rlimits and namespaces reduce — not eliminate — the impact of a memory-corruption bug in
  a native parser library (yara, capstone, zlib…). For hostile workloads run MALX in the provided
  container (read-only root FS, `cap_drop: ALL`, `no-new-privileges`) or in a dedicated VM.
* Inside unprivileged containers the network namespace cannot be created; the socket guard still
  blocks Python-level connections. Add `network_mode: none` to a dedicated worker deployment if you
  split the API and workers.
* Containers are **not** a sandbox for executing malware. Dynamic analysis is explicitly out of
  scope (spec §48) and should be a separate, strongly isolated project.
* Authenticode signatures are parsed, not cryptographically verified (stated in every report).
