"""MALX application factory and CLI.

    malx                 # serve API + built frontend on http://127.0.0.1:8000
    malx --port 9000
    malx analyze FILE…   # run an analysis from the command line (JSON summary)
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend.core.config import Settings, get_settings
from backend.core.database import init_engine
from backend.core.logging import configure_logging, get_logger, log_event
from backend.core.storage import Storage

log = get_logger("app")
VERSION = "0.1.0"
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER = "x-malx-request"


class AppState:
    def __init__(self, settings: Settings):
        from backend.workers.manager import JobManager

        self.settings = settings
        self.storage = Storage(settings.storage_dir)
        self.storage.init()
        init_engine(settings.database_url)
        self.manager = JobManager(settings, self.storage)
        self._system: dict[str, Any] | None = None

    def rule_pack(self):
        from backend.rules.loader import get_rule_pack

        return get_rule_pack(str(self.settings.rules_dir))

    def system_info(self) -> dict[str, Any]:
        from backend.analyzers import hashing, reverse
        from backend.analyzers.appsec import advisory_index_info
        from backend.analyzers.yara_engine import get_yara_engine
        from backend.services.tools import tools_summary

        st = self.settings
        if self._system is None:
            y = get_yara_engine(str(st.rules_dir / "yara"))
            try:
                import py7zr  # noqa: F401
                sevenzip = True
            except Exception:
                sevenzip = False
            try:
                import pyzipper  # noqa: F401
                aes_zip = True
            except Exception:
                aes_zip = False
            self._system = {
                "engines": {
                    "yara": {"available": y.available, "version": y.version, "rules": y.rule_count, "errors": y.errors},
                    "capstone": {"available": reverse.capstone is not None,
                                 "version": getattr(reverse.capstone, "__version__", None) if reverse.capstone else None},
                    "ssdeep": {"available": True, "implementation": "native" if hashing._ssdeep_native else "ppdeep (pure Python)"},
                    "tlsh": {"available": True, "implementation": "py-tlsh" if hashing._tlsh_native else "MALX pure-Python port"},
                    "7z": {"available": sevenzip}, "aes_zip": {"available": aes_zip},
                },
                "tools": tools_summary(st.integrations.ghidra_home, st.integrations.local_tools_enabled),
            }
        pack = self.rule_pack()
        return {
            "version": VERSION, "python": platform.python_version(), "platform": platform.platform(),
            "privacy": "YOUR FILES STAY LOCAL",
            "offline": True,
            "execution_policy": "MALX never executes submitted files (static analysis only).",
            "external_integrations": "ENABLED" if st.integrations.external_enabled else "DISABLED",
            "limits": st.limits.model_dump(),
            "workers": {**st.workers.model_dump(), "active": sorted(self.manager.active), "queued": self.manager.q.qsize()},
            "rules": {**pack.counts(), "errors": pack.errors},
            "advisories": advisory_index_info(str(st.rules_dir / "advisories")),
            "storage": {"root": str(self.storage.root), "usage_bytes": self.storage.usage()},
            "database": st.database_url.split("://", 1)[0],
            **self._system,
        }


def create_app(settings: Settings | None = None, start_workers: bool = True) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = AppState(settings)
        app.state.malx = state
        if start_workers:
            state.manager.start()
        log_event(log, "startup", status="ok", detail=f"storage={state.storage.root}")
        yield
        state.manager.stop()

    app = FastAPI(title="MALX", version=VERSION, lifespan=lifespan,
                  description="Malware Analysis & Security Workbench — evidence-first static analysis. Never executes samples.",
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)

    allowed_hosts = list(dict.fromkeys(settings.server.allowed_hosts + ["testserver"]))
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    origins = settings.server.cors_origins
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["content-type", CSRF_HEADER])
    same_origins = {f"http://{h}:{settings.server.port}" for h in settings.server.allowed_hosts} | set(origins)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.url.path.startswith("/api") and request.method in STATE_CHANGING:
            # Cross-site requests from a malicious page cannot set custom headers without a CORS preflight,
            # which MALX refuses for foreign origins.
            origin = request.headers.get("origin")
            if request.headers.get(CSRF_HEADER) != "1" or (origin and origin not in same_origins):
                return JSONResponse({"detail": "missing or invalid X-MALX-Request header / origin"}, status_code=403)
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        h.setdefault("Content-Security-Policy",
                     "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                     "connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if request.url.path.startswith("/api"):
            h.setdefault("Cache-Control", "no-store")
        return response

    from backend.api.routes import router

    app.include_router(router)

    dist = settings.frontend_dist
    if dist.is_dir() and (dist / "index.html").is_file():
        index = dist / "index.html"
        dist_resolved = dist.resolve()

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist_resolved in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(index)
    else:
        @app.get("/", include_in_schema=False)
        def root():
            return JSONResponse({"name": "MALX", "message": "API running. Build the frontend (cd frontend && npm install && npm run build) "
                                 "or run the Vite dev server on :5173.", "docs": "/api/docs"})
    return app


def _cli_analyze(paths: list[str], mode: str, password: str | None) -> int:
    from backend.core.database import session_scope
    from backend.core.security import harden_file, internal_name, new_id, sanitize_display_name
    from backend.models.entities import Analysis
    from backend.services import queries

    settings = get_settings()
    state = AppState(settings)
    aid = new_id()
    files = []
    for p in paths:
        src = Path(p)
        with open(src, "rb") as fh:
            stored = state.storage.store_upload(aid, fh, settings.limits.max_upload_size)
        harden_file(stored.path)
        san = sanitize_display_name(src.name)
        files.append({"artifact_id": stored.internal_name.split(".")[0], "storage_rel": f"quarantine/{aid}/{stored.internal_name}",
                      "original_name": src.name, "display_name": san.display, "name_issues": san.issues, "size": stored.size})
    with session_scope() as s:
        s.add(Analysis(id=aid, name=files[0]["display_name"], mode=mode, status="QUEUED", options_json={"files": files, "has_password": bool(password)}))
    state.manager.submit(aid, password)
    state.manager.run_now(aid)
    with session_scope() as s:
        a = s.get(Analysis, aid)
        out = queries.analysis_summary(a)
        out["narrative"] = (a.summary_json or {}).get("narrative")
        out["findings"] = [{"id": f["id"], "severity": f["severity"], "title": f["title"], "strength": f["strength"]}
                           for f in queries.findings_list(s, aid)]
    print(json.dumps(out, indent=2))
    return 0


def cli(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "analyze":
        ap = argparse.ArgumentParser(prog="malx analyze")
        ap.add_argument("paths", nargs="+")
        ap.add_argument("--mode", default="auto", choices=["auto", "malware", "appsec"])
        ap.add_argument("--password", default=None, help="archive password (used for extraction only)")
        args = ap.parse_args(argv[1:])
        return _cli_analyze(args.paths, args.mode, args.password)
    ap = argparse.ArgumentParser(prog="malx", description="MALX — Malware Analysis & Security Workbench")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args(argv)
    import uvicorn

    settings = get_settings()
    host = args.host or settings.server.host
    port = args.port or settings.server.port
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding MALX to {host}. MALX is designed as a local workbench.", file=sys.stderr)
    uvicorn.run("backend.main:create_app", factory=True, host=host, port=port, reload=args.reload, access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(cli())
