"""Application security mode: "where can this application fail?"

* language / framework inventory
* source-code weakness rules (``rules/appsec/code.yaml``)
* secret detection with masking (``rules/appsec/secrets.yaml``)
* dependency manifests → dependency graph → local advisory matching (OSV format)
* endpoint extraction → attack-surface map

Advisories are only reported from a local advisory database the user imports
(``scripts/import_osv.py``) — MALX never invents CVEs.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.core.security import mask_secret
from backend.rules.loader import RulePack

from .base import AnalysisContext, ArtifactContext
from .identify import SCRIPT_EXTENSIONS, SOURCE_EXTENSIONS

MAX_SOURCE_FILE = 2 * 1024 * 1024
SKIP_PATH_RE = re.compile(r"(^|/)(node_modules|vendor|site-packages|dist|build|\.git|__pycache__|bower_components|third_party)/|\.min\.(js|css)$")
LANG_ALIASES = {"typescript": {"typescript", "javascript"}, "javascript": {"javascript", "typescript"}, "kotlin": {"kotlin", "java"}, "cpp": {"cpp", "c"}}
BINARY_SAFE_SECRETS = {"SECRET-AWS-001", "SECRET-GH-001", "SECRET-GL-001", "SECRET-SLACK-001", "SECRET-STRIPE-001", "SECRET-GCP-001",
                       "SECRET-PK-001", "SECRET-JWT-001", "SECRET-TG-001", "SECRET-DISCORD-001", "SECRET-NPM-001", "SECRET-SENDGRID-001",
                       "SECRET-DBURL-001", "SECRET-LLM-001"}

FRAMEWORK_DEPS = {
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "starlette": "Starlette", "tornado": "Tornado", "aiohttp": "aiohttp",
    "express": "Express", "koa": "Koa", "@nestjs/core": "NestJS", "next": "Next.js", "react": "React", "vue": "Vue", "@angular/core": "Angular",
    "hapi": "hapi", "fastify": "Fastify", "spring-boot-starter-web": "Spring Boot", "spring-webmvc": "Spring MVC",
    "laravel/framework": "Laravel", "symfony/symfony": "Symfony", "rails": "Ruby on Rails", "sinatra": "Sinatra",
    "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo/v4": "Echo", "github.com/gofiber/fiber/v2": "Fiber",
    "microsoft.aspnetcore.app": "ASP.NET Core", "actix-web": "Actix", "axum": "Axum", "rocket": "Rocket",
}
DB_DEPS = {"sqlalchemy", "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient", "pymongo", "redis", "django", "peewee",
           "mysql", "mysql2", "pg", "mongoose", "mongodb", "sequelize", "typeorm", "prisma", "@prisma/client", "knex", "ioredis",
           "gorm.io/gorm", "github.com/lib/pq", "github.com/go-sql-driver/mysql", "spring-boot-starter-data-jpa", "hibernate-core",
           "mysql-connector-java", "postgresql", "diesel", "sqlx", "microsoft.entityframeworkcore", "doctrine/orm"}
HTTP_CLIENT_DEPS = {"requests", "httpx", "aiohttp", "urllib3", "axios", "node-fetch", "got", "superagent", "okhttp", "reqwest", "guzzlehttp/guzzle"}
AUTH_DEPS = {"flask-login", "flask-jwt-extended", "pyjwt", "python-jose", "authlib", "django-allauth", "djangorestframework-simplejwt",
             "passport", "jsonwebtoken", "express-session", "next-auth", "spring-boot-starter-security", "jjwt", "laravel/sanctum",
             "devise", "github.com/golang-jwt/jwt/v5", "microsoft.aspnetcore.authentication.jwtbearer"}

ENDPOINT_PATTERNS = [
    ("Flask", re.compile(r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?"), 2, 3),
    ("FastAPI", re.compile(r"@(\w+)\.(get|post|put|delete|patch|options|head|websocket)\(\s*['\"]([^'\"]*)['\"]"), 3, 2),
    ("Django", re.compile(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,"), 1, None),
    ("Express", re.compile(r"\b(app|router|server)\.(get|post|put|delete|patch|all|options)\(\s*['\"`]([^'\"`]+)['\"`]"), 3, 2),
    ("Spring", re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\""), 2, 1),
    ("Go", re.compile(r"\.(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\(\s*\"(/[^\"]*)\""), 2, 1),
    ("Laravel", re.compile(r"Route::(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]+)['\"]"), 2, 1),
    ("ASP.NET", re.compile(r"\[(Http(Get|Post|Put|Delete|Patch)|Route)\(\s*\"([^\"]*)\""), 3, 2),
    ("Rails", re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]"), 2, 1),
]
AUTH_HINT_RE = re.compile(r"(?i)(login_required|jwt_required|auth_required|permission_required|@Secured|@PreAuthorize|@RolesAllowed|\[Authorize|Depends\(\s*(get_current_user|oauth2_scheme|verify_token|require_)|passport\.authenticate|authMiddleware|isAuthenticated|requireAuth|ensureAuth|middleware\(\s*['\"]auth|->middleware\(|@login_required|IsAuthenticated|authenticate\()")


def _language(art: ArtifactContext) -> str | None:
    if art.ident and art.ident.details.get("language"):
        return art.ident.details["language"]
    ext = os.path.splitext(art.display_name.lower())[1]
    return SOURCE_EXTENSIONS.get(ext) or SCRIPT_EXTENSIONS.get(ext)


def _rel(art: ArtifactContext) -> str:
    return art.path_in_archive or art.display_name


def is_project(ctx: AnalysisContext) -> bool:
    src = [a for a in ctx.artifacts if a.category in ("source", "script") or a.detected_type in ("manifest", "config")]
    has_manifest = any(a.detected_type == "manifest" for a in ctx.artifacts)
    return has_manifest or len(src) >= 3


def _read_text(art: ArtifactContext) -> str | None:
    if art.size > MAX_SOURCE_FILE:
        return None
    try:
        raw = art.path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096] and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def _applies(rule: dict[str, Any], lang: str | None) -> bool:
    langs = set(rule.get("languages") or ["any"])
    if "any" in langs:
        return True
    if not lang:
        return False
    return bool(langs & LANG_ALIASES.get(lang, {lang}))


def run_appsec(ctx: AnalysisContext, pack: RulePack, force: bool) -> None:
    project = force or is_project(ctx)
    secret_rules = [r for r in pack.appsec if r.get("kind") == "secret"]
    code_rules = [r for r in pack.appsec if r.get("kind") != "secret"]
    hits_by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    secrets: list[dict[str, Any]] = []
    languages: Counter = Counter()
    loc: Counter = Counter()
    endpoints: list[dict[str, Any]] = []
    frameworks: set[str] = set()
    skipped_vendor = 0

    for art in ctx.artifacts:
        ctx.check()
        textual = art.category in ("source", "script", "text") or art.detected_type in ("manifest", "config", "json", "xml", "html")
        if textual:
            text = _read_text(art)
            if text is None:
                continue
            lang = _language(art)
            rel = _rel(art)
            lines = text.splitlines()
            if lang:
                languages[lang] += 1
                loc[lang] += len(lines)
            _scan_secrets(ctx, art, lines, secret_rules, secrets, rel, text_mode=True)
            if not project:
                continue
            if SKIP_PATH_RE.search(rel.lower()):
                skipped_vendor += 1
                continue
            for i, line in enumerate(lines[:50000], 1):
                if len(line) > 4000:
                    continue
                for rule in code_rules:
                    if not _applies(rule, lang):
                        continue
                    m = rule["_regex"].search(line)
                    if not m:
                        continue
                    if rule.get("_exclude") and rule["_exclude"].search(line):
                        continue
                    hits_by_rule[rule["id"]].append({"artifact_id": art.id, "file": rel, "line": i, "snippet": line.strip()[:240]})
            if lang:
                endpoints += _endpoints(lines, rel, lang)
            low = text[:200_000].lower()
            for needle, fw in (("from flask", "Flask"), ("import django", "Django"), ("from fastapi", "FastAPI"),
                               ("require('express')", "Express"), ('require("express")', "Express"), ("from 'express'", "Express"),
                               ("@springbootapplication", "Spring Boot"), ("illuminate\\", "Laravel"), ("gin-gonic/gin", "Gin"),
                               ("microsoft.aspnetcore", "ASP.NET Core")):
                if needle in low:
                    frameworks.add(fw)
        elif art.category in ("pe", "elf", "macho", "dex", "jar", "apk"):
            _scan_secrets(ctx, art, [s.value for s in art.strings[:200_000]], [r for r in secret_rules if r["id"] in BINARY_SAFE_SECRETS],
                          secrets, _rel(art), text_mode=False)

    deps, graph = parse_dependencies(ctx) if project else ([], {"nodes": [], "edges": []})
    for d in deps:
        fw = FRAMEWORK_DEPS.get(d["name"].lower())
        if fw:
            frameworks.add(fw)
    vulns = match_advisories(ctx, deps) if deps else []
    ctx.dependencies = deps
    ctx.vulnerabilities = vulns

    # ---- evidence & appsec findings ----------------------------------------------
    rules_by_id = {r["id"]: r for r in pack.appsec}
    code_findings = []
    for rid, hits in hits_by_rule.items():
        rule = rules_by_id[rid]
        files = sorted({h["file"] for h in hits})
        art_ids = sorted({h["artifact_id"] for h in hits})
        evs = []
        for aid in art_ids[:20]:
            a_hits = [h for h in hits if h["artifact_id"] == aid]
            ev = ctx.add_evidence(
                type="code_weakness", category="code", source="appsec_engine", artifact=ctx.by_id[aid], title=rule["title"],
                description=f"{rule['description']} Pattern-based detection: confirm that untrusted data actually reaches this code.",
                severity=rule["severity"], confidence=float(rule.get("confidence", 0.55)), reliability="medium",
                value=f"{a_hits[0]['file']}:{a_hits[0]['line']}", rule_id=rid,
                details={"cwe": rule.get("cwe"), "category": rule.get("category"), "locations": a_hits[:20], "recommendation": rule.get("recommendation")},
            )
            evs.append(ev.ref)
        code_findings.append({
            "title": rule["title"], "kind": "appsec", "category": "code", "severity": rule["severity"],
            "confidence": float(rule.get("confidence", 0.55)), "strength": "moderate" if len(hits) > 1 else "weak", "needs_review": True,
            "what": f"{rule['title']} ({len(hits)} occurrence(s) in {len(files)} file(s)).",
            "why": rule["description"], "where": [f"{h['file']}:{h['line']}" for h in hits[:15]],
            "limitations": ["Line-based pattern matching: data flow from untrusted input is not proven.",
                            "Framework-level protections (ORMs, middleware, sanitizers) may already mitigate this."],
            "recommendation": rule.get("recommendation"), "hypothesis": None, "rule_id": rid, "mitre": [], "cwe": rule.get("cwe"),
            "evidence": [{"ref": r, "role": "required"} for r in evs], "sources": ["appsec_engine"], "scope": None,
        })
    for s in secrets:
        code_findings.append({
            "title": f"Exposed secret: {s['title']}", "kind": "appsec", "category": "secret", "severity": s["severity"],
            "confidence": s["confidence"], "strength": "moderate", "needs_review": True,
            "what": f"{s['title']} found ({s['masked']}).", "why": s["description"], "where": [s["location"]],
            "limitations": ["MALX does not test whether the secret is valid or still active."],
            "recommendation": s["recommendation"], "hypothesis": None, "rule_id": s["rule_id"], "mitre": [], "cwe": s.get("cwe"),
            "evidence": [{"ref": s["evidence_ref"], "role": "required"}], "sources": ["secret_scanner"], "scope": None,
        })
    for v in vulns:
        code_findings.append({
            "title": f"Vulnerable dependency: {v['package']} {v['version']} ({v['advisory_id']})", "kind": "appsec",
            "category": "vulnerability", "severity": v["severity"], "confidence": 0.85 if v["exact"] else 0.5,
            "strength": "strong" if v["exact"] else "weak", "needs_review": not v["exact"],
            "what": v.get("summary") or v["advisory_id"], "why": f"Version {v['version']} falls in the affected range {v['affected_range']}.",
            "where": [v["manifest"]], "limitations": [f"Advisory source: {v['source']} (local database, as current as its last import)."]
            + ([] if v["exact"] else ["Version taken from a range specifier; the installed version may differ."]),
            "recommendation": f"Upgrade to {v['fixed_version']} or later." if v.get("fixed_version") else "Check the advisory for remediation.",
            "hypothesis": None, "rule_id": v["advisory_id"], "mitre": [], "cwe": None,
            "evidence": [{"ref": v["evidence_ref"], "role": "required"}], "sources": ["dependency_scanner"], "scope": None,
        })

    surface = attack_surface(ctx, endpoints, deps, hits_by_rule, rules_by_id, secrets)
    advisory_db = advisory_index_info(_advisory_dir(ctx))
    ctx.appsec = {
        "enabled": project, "languages": [{"language": k, "files": v, "lines": loc[k]} for k, v in languages.most_common()],
        "frameworks": sorted(frameworks), "endpoints": endpoints[:2000], "dependencies": deps, "dependency_graph": graph,
        "vulnerabilities": vulns, "secrets": secrets, "code_findings": len(hits_by_rule),
        "attack_surface": surface, "advisory_database": advisory_db, "skipped_vendor_files": skipped_vendor,
        "findings": code_findings,
    }
    if skipped_vendor:
        ctx.limitation(f"{skipped_vendor} vendored/minified file(s) skipped by source-code rules.")
    if project and not advisory_db["advisories"]:
        ctx.limitation("No local advisory database imported: dependency vulnerability matching is disabled (see scripts/import_osv.py).")


def _scan_secrets(ctx, art, lines, rules, out, rel, text_mode: bool) -> None:
    seen = set()
    for i, line in enumerate(lines[:100_000], 1):
        if len(line) > 8000:
            line = line[:8000]
        for rule in rules:
            m = rule["_regex"].search(line)
            if not m:
                continue
            if rule.get("_exclude") and rule["_exclude"].search(line):
                continue
            value = m.group()
            key = (rule["id"], value)
            if key in seen:
                continue
            seen.add(key)
            masked = mask_secret(value, keep=6 if len(value) > 16 else 4)
            location = f"{rel}:{i}" if text_mode else f"{rel} (string)"
            ev = ctx.add_evidence(
                type="exposed_secret", category="secret", source="secret_scanner", artifact=art, title=rule["title"],
                description=f"{rule['description']} The value is masked; MALX never stores the full secret.",
                severity=rule["severity"], confidence=0.7 if rule["id"] != "SECRET-PWD-001" else 0.45, reliability="medium",
                value=f"{location} {masked}", rule_id=rule["id"],
                details={"masked": masked, "location": location, "cwe": rule.get("cwe"), "category": rule.get("category")},
                mitre=["T1552.001"] if not text_mode else [],
            )
            out.append({"rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"], "masked": masked,
                        "location": location, "artifact_id": art.id, "evidence_ref": ev.ref, "description": rule["description"],
                        "recommendation": rule.get("recommendation"), "cwe": rule.get("cwe"), "confidence": ev.confidence,
                        "category": rule.get("category")})
            if len(out) >= 500:
                return


def _endpoints(lines: list[str], rel: str, lang: str) -> list[dict[str, Any]]:
    out = []
    for i, line in enumerate(lines[:50000]):
        for fw, rx, path_g, method_g in ENDPOINT_PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            path = m.group(path_g) or "/"
            method = (m.group(method_g) if method_g and m.group(method_g) else "ANY")
            if fw == "Flask" and m.group(3):
                method = ",".join(x.strip(" '\"") for x in m.group(3).split(","))
            if fw == "Spring" and method == "Request":
                method = "ANY"
            if fw == "Go" and method in ("HandleFunc", "Handle"):
                method = "ANY"
            context = "\n".join(lines[max(0, i - 4):i + 3])
            low = path.lower()
            kinds = []
            if any(k in low for k in ("login", "auth", "token", "signin", "oauth", "session", "register", "signup", "password", "logout")):
                kinds.append("authentication")
            if "admin" in low or "manage" in low or "dashboard" in low:
                kinds.append("admin")
            if "upload" in low or re.search(r"(?i)(request\.files|multer|MultipartFile|IFormFile|\$_FILES|FormFile\()", context):
                kinds.append("upload")
            if low.startswith("/api") or "/api/" in low or "/v1" in low or "/graphql" in low:
                kinds.append("api")
            out.append({"framework": fw, "method": method.upper(), "path": path[:300], "file": rel, "line": i + 1,
                        "auth_hint": bool(AUTH_HINT_RE.search(context)), "kinds": kinds or ["web"]})
            break
    return out


# ------------------------------------------------------------------------- dependencies
def _add(deps, art, eco, name, version, spec, manifest, direct=True, dev=False):
    if not name:
        return
    deps.append({"id": os.urandom(8).hex(), "artifact_id": art.id, "ecosystem": eco, "name": name.strip()[:300],
                 "version": (version or None) and str(version).strip()[:120], "version_spec": (spec or None) and str(spec)[:200],
                 "manifest": manifest, "direct": direct, "dev": dev})


def _exact(spec: str | None) -> str | None:
    if not spec:
        return None
    s = spec.strip()
    m = re.fullmatch(r"(==|=)?\s*v?(\d+(\.\d+)*([\-+.][0-9A-Za-z.\-]+)?)", s)
    return m.group(2) if m else None


def parse_dependencies(ctx: AnalysisContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from defusedxml import ElementTree as ET

    deps: list[dict[str, Any]] = []
    for art in ctx.artifacts:
        name = art.display_name.lower()
        rel = _rel(art)
        if art.size > 16 * 1024 * 1024:
            continue
        is_csproj = name.endswith(".csproj")
        if art.detected_type != "manifest" and not is_csproj and name not in ("packages.config",):
            continue
        try:
            text = art.path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        try:
            if name.startswith("requirements") and name.endswith(".txt"):
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith(("-", "git+", "http")):
                        continue
                    m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([<>=!~]=?.*)?$", line)
                    if m:
                        spec = (m.group(3) or "").split(";")[0].strip()
                        _add(deps, art, "PyPI", m.group(1), _exact(spec), spec, rel, dev="dev" in name)
            elif name == "pyproject.toml":
                data = tomllib.loads(text)
                for d in (data.get("project", {}) or {}).get("dependencies", []) or []:
                    m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)", d)
                    if m:
                        spec = m.group(3).split(";")[0].strip()
                        _add(deps, art, "PyPI", m.group(1), _exact(spec), spec, rel)
                poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
                for section, dev in (("dependencies", False), ("dev-dependencies", True)):
                    for k, v in (poetry.get(section, {}) or {}).items():
                        if k.lower() == "python":
                            continue
                        spec = v if isinstance(v, str) else (v.get("version") if isinstance(v, dict) else None)
                        _add(deps, art, "PyPI", k, _exact(spec), spec, rel, dev=dev)
            elif name in ("poetry.lock", "cargo.lock"):
                data = tomllib.loads(text)
                eco = "PyPI" if name == "poetry.lock" else "crates.io"
                for p in data.get("package", []) or []:
                    _add(deps, art, eco, p.get("name"), p.get("version"), p.get("version"), rel, direct=False)
            elif name == "pipfile.lock":
                data = json.loads(text)
                for section, dev in (("default", False), ("develop", True)):
                    for k, v in (data.get(section) or {}).items():
                        spec = v.get("version") if isinstance(v, dict) else None
                        _add(deps, art, "PyPI", k, _exact(spec), spec, rel, direct=False, dev=dev)
            elif name == "package.json":
                data = json.loads(text)
                for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False), ("peerDependencies", False)):
                    for k, v in (data.get(section) or {}).items():
                        _add(deps, art, "npm", k, _exact(str(v).lstrip("^~")) if str(v)[:1] not in "^~" else None, v, rel, dev=dev)
            elif name == "package-lock.json":
                data = json.loads(text)
                if "packages" in data:
                    for path, v in data["packages"].items():
                        if not path:
                            continue
                        pkg = path.split("node_modules/")[-1]
                        _add(deps, art, "npm", pkg, v.get("version"), v.get("version"), rel, direct=False, dev=bool(v.get("dev")))
                else:
                    for k, v in (data.get("dependencies") or {}).items():
                        _add(deps, art, "npm", k, v.get("version"), v.get("version"), rel, direct=False, dev=bool(v.get("dev")))
            elif name == "yarn.lock":
                for m in re.finditer(r'(?m)^"?((?:@[^@\s"/]+/)?[^@\s",]+)@[^\n]*:\n\s+version:?\s+"?([^"\n]+)"?', text):
                    _add(deps, art, "npm", m.group(1), m.group(2), m.group(2), rel, direct=False)
            elif name == "pom.xml":
                root = ET.fromstring(text.encode())
                ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
                pre = "m:" if ns else ""
                props = {}
                pnode = root.find(f"{pre}properties", ns)
                if pnode is not None:
                    for p in pnode:
                        props[p.tag.split("}")[-1]] = (p.text or "").strip()
                for dep in root.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
                    g = dep.find(f"{pre}groupId", ns)
                    a = dep.find(f"{pre}artifactId", ns)
                    v = dep.find(f"{pre}version", ns)
                    sc = dep.find(f"{pre}scope", ns)
                    ver = (v.text or "").strip() if v is not None else None
                    if ver and ver.startswith("${"):
                        ver = props.get(ver[2:-1], ver)
                    if g is not None and a is not None:
                        _add(deps, art, "Maven", f"{(g.text or '').strip()}:{(a.text or '').strip()}", _exact(ver), ver, rel,
                             dev=(sc is not None and (sc.text or "").strip() == "test"))
            elif name in ("build.gradle", "build.gradle.kts"):
                for m in re.finditer(r"(implementation|api|compile|runtimeOnly|compileOnly|testImplementation)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]", text):
                    _add(deps, art, "Maven", f"{m.group(2)}:{m.group(3)}", _exact(m.group(4)), m.group(4), rel, dev=m.group(1).startswith("test"))
            elif name == "go.mod":
                for m in re.finditer(r"(?m)^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]{2,}[^\s]*)\s+(v[0-9][^\s]*)(\s*//\s*indirect)?", text):
                    _add(deps, art, "Go", m.group(1), m.group(2).lstrip("v"), m.group(2), rel, direct=not m.group(3))
            elif name == "cargo.toml":
                data = tomllib.loads(text)
                for section, dev in (("dependencies", False), ("dev-dependencies", True), ("build-dependencies", False)):
                    for k, v in (data.get(section, {}) or {}).items():
                        spec = v if isinstance(v, str) else (v.get("version") if isinstance(v, dict) else None)
                        _add(deps, art, "crates.io", k, _exact(spec.lstrip("=") if spec and spec.startswith("=") else None), spec, rel, dev=dev)
            elif name == "composer.json":
                data = json.loads(text)
                for section, dev in (("require", False), ("require-dev", True)):
                    for k, v in (data.get(section) or {}).items():
                        if k == "php" or k.startswith("ext-"):
                            continue
                        _add(deps, art, "Packagist", k, _exact(v), v, rel, dev=dev)
            elif name == "composer.lock":
                data = json.loads(text)
                for section, dev in (("packages", False), ("packages-dev", True)):
                    for p in data.get(section) or []:
                        _add(deps, art, "Packagist", p.get("name"), str(p.get("version", "")).lstrip("v"), p.get("version"), rel, direct=False, dev=dev)
            elif name == "gemfile.lock":
                for m in re.finditer(r"(?m)^    ([A-Za-z0-9_\-]+) \(([0-9][^)]*)\)", text):
                    _add(deps, art, "RubyGems", m.group(1), m.group(2), m.group(2), rel, direct=False)
            elif is_csproj:
                for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
                    _add(deps, art, "NuGet", m.group(1), _exact(m.group(2)), m.group(2), rel)
            elif name == "packages.config":
                for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
                    _add(deps, art, "NuGet", m.group(1), _exact(m.group(2)), m.group(2), rel)
        except Exception as exc:
            art.errors.append(f"manifest parse: {str(exc)[:200]}")
    # Merge: prefer lockfile versions for direct deps without exact version
    locked = {(d["ecosystem"], d["name"].lower()): d["version"] for d in deps if not d["direct"] and d["version"]}
    for d in deps:
        if d["direct"] and not d["version"]:
            d["version"] = locked.get((d["ecosystem"], d["name"].lower()))
            if d["version"]:
                d["version_source"] = "lockfile"
    nodes = [{"id": "app", "label": "Application", "type": "application"}]
    edges = []
    manifests = sorted({d["manifest"] for d in deps})
    for m in manifests:
        nodes.append({"id": f"m:{m}", "label": m, "type": "manifest"})
        edges.append({"source": "app", "target": f"m:{m}", "relationship": "declares"})
    seen = set()
    for d in deps:
        nid = f"d:{d['ecosystem']}:{d['name'].lower()}"
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "label": f"{d['name']} {d['version'] or d['version_spec'] or ''}".strip(), "type": "dependency",
                          "direct": d["direct"], "ecosystem": d["ecosystem"]})
        edges.append({"source": f"m:{d['manifest']}", "target": nid, "relationship": "depends_on" if d["direct"] else "locks"})
    return deps, {"nodes": nodes[:3000], "edges": edges[:6000]}


# ------------------------------------------------------------------------- advisories
def _advisory_dir(ctx: AnalysisContext) -> str:
    env = os.environ.get("MALX_ADVISORIES_DIR")
    if env:
        return env
    from backend.core.config import get_settings

    return str(get_settings().rules_dir / "advisories")


@lru_cache(maxsize=2)
def _load_advisories(directory: str) -> dict[tuple[str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    base = Path(directory)
    if not base.is_dir():
        return index
    for path in sorted(base.rglob("*.json*")):
        try:
            if path.suffix == ".jsonl":
                records = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]
            else:
                data = json.loads(path.read_text("utf-8"))
                records = data if isinstance(data, list) else [data]
        except Exception:
            continue
        for rec in records:
            if not isinstance(rec, dict) or "id" not in rec:
                continue
            rec["_source"] = path.name
            for aff in rec.get("affected", []) or []:
                pkg = aff.get("package") or {}
                if pkg.get("ecosystem") and pkg.get("name"):
                    index[(pkg["ecosystem"].lower(), pkg["name"].lower())].append(rec)
    return index


def advisory_index_info(directory: str) -> dict[str, Any]:
    idx = _load_advisories(directory)
    return {"directory": directory, "packages": len(idx), "advisories": len({r["id"] for v in idx.values() for r in v})}


def _vkey(eco: str, v: str):
    v = v.strip().lstrip("v")
    if eco.lower() == "pypi":
        try:
            from packaging.version import Version

            return (0, Version(v))
        except Exception:
            pass
    main, _, pre = v.partition("-")
    parts = []
    for p in re.split(r"[.+]", main):
        parts.append(int(p) if p.isdigit() else 0)
    while len(parts) < 4:
        parts.append(0)
    return (1, tuple(parts), 0 if pre else 1, pre)


def _cmp(eco, a, b) -> int:
    ka, kb = _vkey(eco, a), _vkey(eco, b)
    try:
        return (ka > kb) - (ka < kb)
    except TypeError:
        return 0


def version_affected(eco: str, version: str, affected: dict[str, Any]) -> tuple[bool, str, str | None]:
    """OSV semantics: affected if introduced <= v < fixed (or <= last_affected)."""
    if version in (affected.get("versions") or []):
        return True, "listed version", None
    for rng in affected.get("ranges", []) or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        intervals: list[tuple[str, str | None, str | None]] = []
        intro: str | None = None
        for ev in rng.get("events", []) or []:
            if "introduced" in ev:
                if intro is not None:
                    intervals.append((intro, None, None))
                intro = str(ev["introduced"])
            elif "fixed" in ev and intro is not None:
                intervals.append((intro, str(ev["fixed"]), None))
                intro = None
            elif "last_affected" in ev and intro is not None:
                intervals.append((intro, None, str(ev["last_affected"])))
                intro = None
        if intro is not None:
            intervals.append((intro, None, None))
        for lo, fixed, last in intervals:
            lo_ok = lo == "0" or _cmp(eco, version, lo) >= 0
            hi_ok = (fixed is None or _cmp(eco, version, fixed) < 0) and (last is None or _cmp(eco, version, last) <= 0)
            if lo_ok and hi_ok:
                desc = f">={lo}" + (f", <{fixed}" if fixed else "") + (f", <={last}" if last else "")
                return True, desc, fixed
    return False, "", None


def _osv_severity(rec: dict[str, Any]) -> str:
    sev = ((rec.get("database_specific") or {}).get("severity") or "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    if sev == "moderate":
        return "medium"
    for s in rec.get("severity", []) or []:
        score = s.get("score", "")
        m = re.search(r"CVSS:3\.\d/AV:(\w)/AC:(\w)/PR:(\w)/UI:(\w)/S:(\w)/C:(\w)/I:(\w)/A:(\w)", score)
        if m:
            c, i, a = m.group(6), m.group(7), m.group(8)
            highs = sum(1 for x in (c, i, a) if x == "H")
            if m.group(1) == "N" and m.group(3) == "N" and highs >= 2:
                return "critical"
            return "high" if highs >= 1 else "medium"
    return "medium"


def match_advisories(ctx: AnalysisContext, deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index = _load_advisories(_advisory_dir(ctx))
    out = []
    if not index:
        return out
    for d in deps:
        version = d.get("version")
        exact = bool(version)
        if not version:
            spec = d.get("version_spec") or ""
            m = re.search(r"(\d+(\.\d+)+)", spec)
            if not m:
                continue
            version = m.group(1)
        for rec in index.get((d["ecosystem"].lower(), d["name"].lower()), []):
            for aff in rec.get("affected", []) or []:
                pkg = aff.get("package") or {}
                if pkg.get("name", "").lower() != d["name"].lower():
                    continue
                ok, rng, fixed = version_affected(d["ecosystem"], version, aff)
                if not ok:
                    continue
                sev = _osv_severity(rec)
                art = ctx.by_id.get(d["artifact_id"])
                ev = ctx.add_evidence(
                    type="vulnerable_dependency", category="vulnerability", source="dependency_scanner", artifact=art,
                    title=f"{d['name']} {version} affected by {rec['id']}",
                    description=(rec.get("summary") or rec.get("details", "")[:300] or rec["id"]) + f" (local advisory database: {rec['_source']}).",
                    severity=sev, confidence=0.85 if exact else 0.5, reliability="high", value=f"{d['name']}@{version}",
                    rule_id=rec["id"], details={"aliases": rec.get("aliases", []), "range": rng, "fixed": fixed},
                )
                out.append({
                    "dependency_id": d["id"], "package": d["name"], "ecosystem": d["ecosystem"], "version": version, "exact": exact,
                    "advisory_id": rec["id"], "aliases": rec.get("aliases", []), "summary": (rec.get("summary") or "")[:500],
                    "severity": sev, "affected_range": rng, "fixed_version": fixed, "source": rec["_source"],
                    "manifest": d["manifest"], "evidence_ref": ev.ref,
                })
                break
    return out


# ------------------------------------------------------------------------- surface
def attack_surface(ctx, endpoints, deps, hits_by_rule, rules_by_id, secrets) -> dict[str, Any]:
    dep_names = {d["name"].lower() for d in deps}
    cats_by_rule = {rid: rules_by_id[rid].get("category") for rid in hits_by_rule}

    def refs_for(categories: set[str]) -> list[str]:
        return [rid for rid, c in cats_by_rule.items() if c in categories]

    nodes = [{"id": "internet", "label": "Internet", "type": "root", "risk": [], "evidence": [], "dependencies": [], "paths": []}]
    edges = []

    def add(node_id, label, risk_rules, deps_match, endpoints_list, paths):
        evidence = [e.ref for e in ctx.evidence if e.rule_id in risk_rules][:30]
        nodes.append({"id": node_id, "label": label, "type": "surface", "risk": [rules_by_id[r]["title"] for r in risk_rules],
                      "risk_rules": risk_rules, "evidence": evidence, "dependencies": sorted(deps_match)[:20],
                      "endpoints": [f"{e['method']} {e['path']}" for e in endpoints_list[:30]],
                      "unauthenticated": [f"{e['method']} {e['path']}" for e in endpoints_list if not e["auth_hint"]][:30],
                      "paths": paths})
        edges.append({"source": "internet", "target": node_id})

    api_eps = [e for e in endpoints if "api" in e["kinds"] or "web" in e["kinds"]]
    if endpoints:
        add("api", "API / Web routes", refs_for({"command_execution", "code_injection", "sql_injection", "xss", "redirect", "deserialization"}),
            {n for n in dep_names if n in FRAMEWORK_DEPS}, api_eps,
            ["Internet → route handler → " + c.replace("_", " ") for c in sorted({cats_by_rule[r] for r in refs_for({'command_execution', 'code_injection', 'sql_injection', 'deserialization'})})])
    auth_eps = [e for e in endpoints if "authentication" in e["kinds"]]
    auth_rules = refs_for({"authentication", "configuration"})
    if auth_eps or auth_rules or (dep_names & AUTH_DEPS):
        add("auth", "Authentication", auth_rules, dep_names & AUTH_DEPS, auth_eps,
            ["Internet → login/token endpoint → session forgery" if auth_rules else "Internet → login/token endpoint (credential stuffing / brute force)"])
    up_eps = [e for e in endpoints if "upload" in e["kinds"]]
    up_rules = refs_for({"file_upload", "path_traversal"})
    if up_eps or up_rules:
        add("upload", "File upload / file access", up_rules, set(), up_eps,
            ["Internet → upload → filesystem (web shell / overwrite)"] + (["Internet → path parameter → arbitrary file read"] if up_rules else []))
    admin_eps = [e for e in endpoints if "admin" in e["kinds"]]
    if admin_eps:
        add("admin", "Administration", [], set(), admin_eps,
            ["Internet → admin route without auth hint"] if any(not e["auth_hint"] for e in admin_eps) else ["Internet → admin route (protected)"])
    db_rules = refs_for({"sql_injection"})
    if (dep_names & DB_DEPS) or db_rules:
        add("database", "Database", db_rules, dep_names & DB_DEPS, [],
            ["Internet → route → SQL query built from input → database"] if db_rules else ["Application → database (ORM/driver)"])
    ext_rules = refs_for({"ssrf", "tls"})
    outbound = sorted({i.normalized for i in ctx.iocs.values() if i.type in ("domain", "url") and not i.common})[:30]
    if (dep_names & HTTP_CLIENT_DEPS) or ext_rules or outbound:
        add("external", "External services", ext_rules, dep_names & HTTP_CLIENT_DEPS, [],
            (["Internet → URL parameter → server-side request → internal network (SSRF)"] if any(cats_by_rule[r] == "ssrf" for r in ext_rules) else [])
            + ([f"Application → {o}" for o in outbound[:5]]))
        nodes[-1]["outbound"] = outbound
    if secrets:
        nodes.append({"id": "secrets", "label": "Secrets in code/config", "type": "surface",
                      "risk": sorted({s["title"] for s in secrets}), "risk_rules": sorted({s["rule_id"] for s in secrets}),
                      "evidence": [s["evidence_ref"] for s in secrets][:30], "dependencies": [], "endpoints": [], "unauthenticated": [],
                      "paths": ["Repository/package access → leaked credential → external account takeover"]})
        edges.append({"source": "internet", "target": "secrets"})
    return {"nodes": nodes, "edges": edges}
