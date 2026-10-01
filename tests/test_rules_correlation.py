"""Rule packs, heuristic engine, correlation, risk, MITRE and classification."""

from collections import Counter

import pytest

from backend.analyzers import correlation, heuristics
from backend.analyzers.base import ExtractedString
from backend.analyzers.heuristics import Facts, evaluate, validate_condition
from tests.conftest import artifact_from_bytes
from tests.samples import factory


def test_rule_pack_is_valid(pack):
    assert not pack.errors
    counts = pack.counts()
    assert counts["heuristic_rules"] >= 60 and counts["correlation_rules"] >= 10
    tags = {p.tag for p in pack.string_patterns} | {"api_name_unimported", "api_name", "dll_name"}
    rule_ids = {r["id"] for r in pack.heuristics}
    for rule in pack.heuristics:
        assert not validate_condition(rule["conditions"]), rule["id"]
        assert rule["severity"] in ("info", "low", "medium", "high", "critical")
        for t in rule.get("mitre", []):
            assert t in pack.mitre, f"{rule['id']} references unknown technique {t}"
        assert rule.get("explanation") and len(rule["explanation"]) > 20
    for corr in pack.correlations:
        for group in corr["requires"] + (corr.get("supporting") or []):
            for rid in group.get("rules", []) or []:
                assert rid in rule_ids or rid.startswith("yara:"), f"{corr['id']} references unknown rule {rid}"
    for s in pack.string_patterns:
        assert s.klass in ("INTERESTING", "SUSPICIOUS", "HIGH_RISK")
    assert all(t in tags for r in pack.heuristics for t in _tags(r["conditions"]))


def _tags(cond):
    if isinstance(cond, list):
        for c in cond:
            yield from _tags(c)
    elif isinstance(cond, dict):
        for k, v in cond.items():
            if k == "string_tags_any":
                yield from v
            elif k == "string_tags_count":
                yield from v["any"]
            elif k == "at_least":
                yield from _tags(v["of"])
            elif isinstance(v, (list, dict)):
                yield from _tags(v)


def _facts(**kw):
    base = dict(art=None, types={"pe", "executable"}, imports=set(), exports=set(), strings=[], string_tags=Counter(),
                ioc_types=Counter(), ioc_flags=set(), ioc_services=set(), evidence_types=set(), evidence_categories=Counter(),
                tags=set(), child_types=set(), in_archive=False)
    base.update(kw)
    return Facts(**base)


def test_condition_combinators():
    f = _facts(imports={"virtualallocex", "writeprocessmemory", "createremotethread"}, strings=["hello login data"])
    ok, reasons = evaluate({"all": [{"imports_any": ["VirtualAllocEx"]}, {"imports_any": ["WriteProcessMemory"]}]}, f)
    assert ok and len(reasons) == 2
    assert evaluate({"any": [{"imports_any": ["Nope"]}, {"strings_any": ["login data"]}]}, f)[0]
    assert not evaluate({"not": {"strings_any": ["login data"]}}, f)[0]
    ok, reasons = evaluate({"at_least": {"n": 2, "of": [{"imports_any": ["VirtualAllocEx"]}, {"imports_any": ["X"]},
                                                         {"strings_any": ["hello"]}]}}, f)
    assert ok and reasons[0].startswith("2 of 3")
    # A/W suffix tolerance
    assert evaluate({"imports_any": ["CreateRemoteThread"]}, _facts(imports={"createremotethreada"}))[0]
    assert validate_condition({"bogus_predicate": 1}) == ["conditions: unknown predicate 'bogus_predicate'"]


def test_heuristics_fire_with_explanations(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "a.exe", factory.benign_pe())
    art.imports |= {"virtualallocex", "writeprocessmemory", "createremotethread"}
    heuristics.run_heuristics(c, pack)
    ev = next(e for e in c.evidence if e.rule_id == "HEUR-INJ-001")
    assert ev.details["matched"] and "imports VirtualAllocEx" in ev.details["matched"][0]
    assert "Legitimate context" in ev.description
    assert ev.mitre == ["T1055", "T1055.002"]


def test_single_heuristic_never_malicious(ctx, pack):
    """Spec §27/§42: one rule firing must not produce a malicious classification."""
    c = ctx()
    art = artifact_from_bytes(c, "a.exe", factory.benign_pe())
    art.imports |= {"virtualallocex", "writeprocessmemory", "createremotethread"}
    heuristics.run_heuristics(c, pack)
    findings = correlation.correlate(c, pack)
    klass, _ = correlation.classify(c, findings)
    assert klass not in ("MALICIOUS_INDICATORS", "HIGHLY_SUSPICIOUS")
    assert all(f["kind"] != "correlated" for f in findings)
    assert any(f["needs_review"] for f in findings)


def test_correlation_builds_multi_evidence_finding(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "stealer.exe", factory.benign_pe())
    art.strings = [ExtractedString(0, "ascii", v) for v in (
        "\\Google\\Chrome\\User Data\\Default\\Login Data", "\\Mozilla\\Firefox\\Profiles", "encrypted_key")]
    from backend.analyzers.strings_engine import StringClassifier
    StringClassifier(pack).classify(art.strings)
    art.imports |= {"cryptunprotectdata", "winhttpopen", "winhttpsendrequest"}
    c.add_evidence(type="network_indicator", category="network", source="ioc_engine", artifact=art, title="URL", description="d",
                   value="https://discord.com/api/webhooks/1/x", severity="medium", confidence=0.6)
    c.add_evidence(type="suspicious_import", category="credential_access", source="pe_analyzer", artifact=art,
                   title="Imports CryptUnprotectData", description="d", value="CryptUnprotectData", severity="medium", confidence=0.55,
                   reliability="high")
    heuristics.run_heuristics(c, pack)
    findings = correlation.correlate(c, pack)
    f = next(x for x in findings if x["rule_id"] == "CORR-CRED-001")
    assert f["kind"] == "correlated" and len(f["evidence"]) >= 3
    assert len(f["sources"]) >= 2
    for key in ("what", "where", "why", "limitations", "confidence"):
        assert f[key], key
    risk = correlation.risk_model(c, findings)
    assert risk["dimensions"]["credential"]["score"] > 0 and risk["dimensions"]["credential"]["reasons"]
    mitre = correlation.map_mitre(c, pack, findings)
    assert any(m["technique_id"] == "T1555.003" and m["evidence"] for m in mitre)
    summary = correlation.investigation_summary(c, findings, *correlation.classify(c, findings))
    assert [s["stage"] for s in summary["chain"]] == ["observations", "interesting", "suspicious", "correlated", "strong", "hypothesis"]


def test_benign_classification(ctx, pack):
    c = ctx()
    artifact_from_bytes(c, "readme.txt", b"hello world, this is a plain text file")
    findings = correlation.correlate(c, pack)
    assert correlation.classify(c, findings)[0] == "BENIGN_INDICATORS"
    c2 = ctx()
    import os
    artifact_from_bytes(c2, "blob", os.urandom(512))
    assert correlation.classify(c2, correlation.correlate(c2, pack))[0] == "UNKNOWN"


@pytest.mark.parametrize("sev,expected", [("info", 0), ("low", 1), ("critical", 4)])
def test_severity_ranks(sev, expected):
    from backend.core.enums import Severity
    assert Severity(sev).rank == expected
