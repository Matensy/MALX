"""Declarative heuristic engine.

Rules (``rules/heuristics/*.yaml``) are evaluated against a per-artifact fact base.
Every predicate that contributes to a match is recorded so the resulting evidence
explains *why* it fired. Rules are data — nothing in them is executed.

Combinators: ``all``, ``any``, ``not``, ``at_least: {n, of}``.
Predicates: see ``PREDICATES`` below and docs/rules.md.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable

from backend.rules.loader import RulePack

from .base import AnalysisContext, ArtifactContext

FILE_TYPE_ALIASES = {
    "executable": {"pe", "elf", "macho", "dos", "dex", "class"},
    "document": {"pdf", "ooxml", "ole", "rtf", "odf"},
    "archive": {"zip", "7z", "tar", "gzip", "bzip2", "xz", "rar", "cab", "jar", "apk"},
}


@dataclass
class Facts:
    art: ArtifactContext
    types: set[str]
    imports: set[str]
    exports: set[str]
    strings: list[str]
    string_tags: Counter
    ioc_types: Counter
    ioc_flags: set[str]
    ioc_services: set[str]
    evidence_types: set[str]
    evidence_categories: Counter
    tags: set[str]
    child_types: set[str]
    in_archive: bool
    _joined: str | None = field(default=None, repr=False)

    @property
    def joined(self) -> str:
        if self._joined is None:
            self._joined = "\n".join(self.strings)
        return self._joined


def build_facts(ctx: AnalysisContext, art: ArtifactContext) -> Facts:
    ident = art.ident
    types = {art.detected_type, art.category}
    if ident and ident.details.get("language"):
        types.add(ident.details["language"])
    for alias, members in FILE_TYPE_ALIASES.items():
        if types & members:
            types.add(alias)
    tag_counter: Counter = Counter()
    for s in art.strings:
        for t in s.tags:
            tag_counter[t] += 1
    ioc_types: Counter = Counter()
    flags: set[str] = set()
    services: set[str] = set()
    for ioc in ctx.iocs.values():
        if ioc.artifact_id != art.id:
            continue
        if not ioc.common:
            ioc_types[ioc.type] += 1
        ctxinfo = ioc.enrich or {}
        for k in ("ip_host", "unusual_port", "suspicious_tld"):
            if ctxinfo.get(k):
                flags.add(k)
        if ctxinfo.get("service"):
            services.add(ctxinfo["service"])
    ev = ctx.evidence_for(art.id)
    child_types = set()
    for cid in art.children:
        child = ctx.by_id.get(cid)
        if child:
            child_types.add(child.detected_type)
            child_types.add(child.category)
    return Facts(
        art=art, types={t for t in types if t}, imports=art.imports, exports={e.lower() for e in art.exports},
        strings=art.lower_strings(), string_tags=tag_counter, ioc_types=ioc_types, ioc_flags=flags,
        ioc_services=services, evidence_types={e.type for e in ev},
        evidence_categories=Counter(e.category for e in ev if e.severity.rank >= 1), tags=set(art.tags),
        child_types=child_types, in_archive=art.parent_id is not None,
    )


def _api_hit(name: str, imports: set[str]) -> str | None:
    n = name.lower()
    for cand in (n, n + "a", n + "w"):
        if cand in imports:
            return cand
    return None


def _strings_hits(needles: list[str], f: Facts, limit: int = 3) -> list[str]:
    hits = []
    joined = f.joined
    for needle in needles:
        if needle.lower() in joined:
            hits.append(needle)
            if len(hits) >= limit:
                break
    return hits


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I | re.M)


def _p_file_type(v, f: Facts):
    want = {x.lower() for x in (v if isinstance(v, list) else [v])}
    hit = want & f.types
    return bool(hit), f"type in {sorted(hit)}" if hit else None


def _p_imports_any(v, f: Facts):
    for name in v:
        h = _api_hit(name, f.imports)
        if h:
            return True, f"imports {name}"
    return False, None


def _p_imports_all(v, f: Facts):
    hits = [n for n in v if _api_hit(n, f.imports)]
    return len(hits) == len(v), f"imports {', '.join(hits)}" if len(hits) == len(v) else None


def _p_imports_count_gte(v, f: Facts):
    return len(f.imports) >= int(v), f"{len(f.imports)} imports"


def _p_imports_count_lte(v, f: Facts):
    return len(f.imports) <= int(v), f"{len(f.imports)} imports"


def _p_exports_any(v, f: Facts):
    hit = [x for x in v if x.lower() in f.exports]
    return bool(hit), f"exports {hit[0]}" if hit else None


def _p_strings_any(v, f: Facts):
    hits = _strings_hits(v, f)
    return bool(hits), f"strings contain {hits!r}" if hits else None


def _p_strings_all(v, f: Facts):
    hits = _strings_hits(v, f, limit=len(v))
    return len(hits) == len(v), f"strings contain {hits!r}" if len(hits) == len(v) else None


def _p_strings_count(v, f: Facts):
    hits = _strings_hits(v.get("any", []), f, limit=len(v.get("any", [])))
    ok = len(hits) >= int(v.get("min", 1))
    return ok, f"{len(hits)} of the listed strings: {hits[:5]!r}" if ok else None


def _p_strings_regex(v, f: Facts):
    m = _regex(v).search(f.joined)
    return bool(m), f"regex matched {m.group()[:120]!r}" if m else None


def _p_string_tags_any(v, f: Facts):
    hit = [t for t in v if f.string_tags.get(t)]
    return bool(hit), f"string signatures {hit}" if hit else None


def _p_string_tags_count(v, f: Facts):
    total = sum(f.string_tags.get(t, 0) for t in v.get("any", []))
    ok = total >= int(v.get("min", 1))
    return ok, f"{total} strings tagged {v.get('any')}" if ok else None


def _p_ioc_any(v, f: Facts):
    hit = [t for t in v if f.ioc_types.get(t)]
    return bool(hit), f"IOC types {hit}" if hit else None


def _p_ioc_count(v, f: Facts):
    n = f.ioc_types.get(v.get("type"), 0)
    ok = n >= int(v.get("min", 1))
    return ok, f"{n} {v.get('type')} IOCs" if ok else None


def _p_ioc_flag_any(v, f: Facts):
    hit = [x for x in v if x in f.ioc_flags]
    return bool(hit), f"IOC context {hit}" if hit else None


def _p_ioc_service_any(v, f: Facts):
    hit = [x for x in v if x in f.ioc_services]
    return bool(hit), f"IOC services {hit}" if hit else None


def _p_evidence_any(v, f: Facts):
    hit = [x for x in v if x in f.evidence_types]
    return bool(hit), f"evidence {hit}" if hit else None


def _p_evidence_category_count(v, f: Facts):
    n = f.evidence_categories.get(v.get("category"), 0)
    ok = n >= int(v.get("min", 1))
    return ok, f"{n} {v.get('category')} observations" if ok else None


def _p_tags_any(v, f: Facts):
    hit = [x for x in v if x in f.tags]
    return bool(hit), f"tags {hit}" if hit else None


def _p_tags_all(v, f: Facts):
    ok = all(x in f.tags for x in v)
    return ok, f"tags {v}" if ok else None


def _p_entropy_gte(v, f: Facts):
    e = f.art.entropy or 0.0
    return e >= float(v), f"entropy {e:.2f}"


def _p_size_gte(v, f: Facts):
    return f.art.size >= int(v), f"size {f.art.size}"


def _p_size_lte(v, f: Facts):
    return f.art.size <= int(v), f"size {f.art.size}"


def _p_extension_mismatch(v, f: Facts):
    mm = bool(f.art.ident and f.art.ident.extension_mismatch)
    return mm == bool(v), (f.art.ident.mismatch_reason if mm and f.art.ident else None)


def _p_extension_in(v, f: Facts):
    ext = f.art.ident.extension if f.art.ident else ""
    ok = ext in {x.lower() for x in v}
    return ok, f"extension {ext}" if ok else None


def _p_double_extension(v, f: Facts):
    de = bool(f.art.ident and f.art.ident.details.get("double_extension"))
    return de == bool(v), f"double extension in {f.art.display_name!r}" if de else None


def _p_name_regex(v, f: Facts):
    m = _regex(v).search(f.art.display_name)
    return bool(m), f"name {f.art.display_name!r}" if m else None


def _p_name_issues_any(v, f: Facts):
    hit = [x for x in v if x in f.art.name_issues]
    return bool(hit), f"name issues {hit}" if hit else None


def _p_in_archive(v, f: Facts):
    return f.in_archive == bool(v), "extracted from a container" if f.in_archive else None


def _p_child_type_any(v, f: Facts):
    hit = [x for x in v if x in f.child_types]
    return bool(hit), f"contains {hit}" if hit else None


def _p_metadata(v, f: Facts):
    node: Any = f.art.metadata
    for part in str(v.get("path", "")).split("."):
        node = node.get(part) if isinstance(node, dict) else None
    if "exists" in v:
        return (node is not None) == bool(v["exists"]), f"{v['path']} present"
    if node is None:
        return False, None
    for op, fn in (("gte", lambda a, b: a >= b), ("lte", lambda a, b: a <= b), ("eq", lambda a, b: a == b)):
        if op in v:
            try:
                ok = fn(node, v[op])
            except TypeError:
                return False, None
            return ok, f"{v['path']}={node}"
    if "contains" in v:
        ok = str(v["contains"]).lower() in str(node).lower()
        return ok, f"{v['path']} contains {v['contains']!r}"
    return False, None


PREDICATES: dict[str, Callable[[Any, Facts], tuple[bool, str | None]]] = {
    "file_type": _p_file_type, "imports_any": _p_imports_any, "imports_all": _p_imports_all,
    "imports_count_gte": _p_imports_count_gte, "imports_count_lte": _p_imports_count_lte, "exports_any": _p_exports_any,
    "strings_any": _p_strings_any, "strings_all": _p_strings_all, "strings_count": _p_strings_count,
    "strings_regex": _p_strings_regex, "string_tags_any": _p_string_tags_any, "string_tags_count": _p_string_tags_count,
    "ioc_any": _p_ioc_any, "ioc_count": _p_ioc_count, "ioc_flag_any": _p_ioc_flag_any,
    "ioc_service_any": _p_ioc_service_any, "evidence_any": _p_evidence_any,
    "evidence_category_count": _p_evidence_category_count, "tags_any": _p_tags_any, "tags_all": _p_tags_all,
    "entropy_gte": _p_entropy_gte, "size_gte": _p_size_gte, "size_lte": _p_size_lte,
    "extension_mismatch": _p_extension_mismatch, "extension_in": _p_extension_in,
    "double_extension": _p_double_extension, "name_regex": _p_name_regex, "name_issues_any": _p_name_issues_any,
    "in_archive": _p_in_archive, "child_type_any": _p_child_type_any, "metadata": _p_metadata,
}
COMBINATORS = {"all", "any", "not", "at_least"}


class RuleSyntaxError(ValueError):
    pass


def validate_condition(cond: Any, path: str = "conditions") -> list[str]:
    errors: list[str] = []
    if isinstance(cond, list):
        for i, c in enumerate(cond):
            errors += validate_condition(c, f"{path}[{i}]")
        return errors
    if not isinstance(cond, dict) or not cond:
        return [f"{path}: expected a mapping"]
    for key, val in cond.items():
        if key in ("all", "any"):
            if not isinstance(val, list):
                errors.append(f"{path}.{key}: expected a list")
            else:
                errors += validate_condition(val, f"{path}.{key}")
        elif key == "not":
            errors += validate_condition(val, f"{path}.not")
        elif key == "at_least":
            if not isinstance(val, dict) or "n" not in val or "of" not in val:
                errors.append(f"{path}.at_least: needs n and of")
            else:
                errors += validate_condition(val["of"], f"{path}.at_least.of")
        elif key not in PREDICATES:
            errors.append(f"{path}: unknown predicate {key!r}")
    return errors


def evaluate(cond: Any, f: Facts) -> tuple[bool, list[str]]:
    """Evaluate a condition tree; returns (matched, reasons)."""
    if isinstance(cond, list):
        return evaluate({"all": cond}, f)
    reasons: list[str] = []
    for key, val in cond.items():
        if key == "all":
            for c in val:
                ok, r = evaluate(c, f)
                if not ok:
                    return False, []
                reasons += r
        elif key == "any":
            matched = False
            for c in val:
                ok, r = evaluate(c, f)
                if ok:
                    matched = True
                    reasons += r
                    break
            if not matched:
                return False, []
        elif key == "not":
            ok, _ = evaluate(val, f)
            if ok:
                return False, []
        elif key == "at_least":
            n = int(val["n"])
            got = 0
            sub_reasons = []
            for c in val["of"]:
                ok, r = evaluate(c, f)
                if ok:
                    got += 1
                    sub_reasons += r
            if got < n:
                return False, []
            reasons.append(f"{got} of {len(val['of'])} indicator groups")
            reasons += sub_reasons
        else:
            fn = PREDICATES.get(key)
            if fn is None:
                return False, []
            ok, reason = fn(val, f)
            if not ok:
                return False, []
            if reason:
                reasons.append(reason)
    return True, reasons


def run_heuristics(ctx: AnalysisContext, pack: RulePack) -> int:
    """Two passes so rules can build on evidence produced by other rules."""
    fired = 0
    for _ in range(2):
        for art in ctx.artifacts:
            ctx.check()
            facts = build_facts(ctx, art)
            for rule in pack.heuristics:
                applies = rule.get("applies_to")
                if applies and not (set(applies) & facts.types):
                    continue
                key = ("heuristic", art.id, rule["id"])
                if key in ctx._evidence_keys:
                    continue
                ok, reasons = evaluate(rule["conditions"], facts)
                if not ok:
                    continue
                ev = ctx.add_evidence(
                    type=rule.get("evidence_type", "heuristic_match"), category=rule.get("category", "info"),
                    source="heuristic_engine", artifact=art, title=rule["name"],
                    description=rule["explanation"].strip() + (f" Legitimate context: {rule['legitimate'].strip()}" if rule.get("legitimate") else ""),
                    severity=rule["severity"], confidence=float(rule.get("confidence", 0.5)),
                    reliability=rule.get("reliability", "medium"), value="; ".join(reasons)[:500],
                    rule_id=rule["id"], mitre=list(rule.get("mitre") or []),
                    details={"rule": rule["id"], "matched": reasons[:20], "file": rule.get("_file"),
                             "legitimate": rule.get("legitimate")},
                    dedupe_key=key,
                )
                fired += 1
                ctx.event(f"Heuristic {rule['id']} matched", engine="heuristic_engine", artifact_id=art.id, evidence_ref=ev.ref)
    return fired
