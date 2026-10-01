"""End-to-end analyses through the API (inline worker) on the synthetic test lab."""

import json

import pytest

from tests.conftest import H, analyze, upload, wait
from tests.samples import factory


def findings(client, aid):
    return client.get(f"/api/analyses/{aid}/findings").json()


def evidence_types(client, aid):
    return {e["type"] for e in client.get(f"/api/analyses/{aid}/evidence").json()}


def rules_fired(client, aid):
    return {e["rule_id"] for e in client.get(f"/api/analyses/{aid}/evidence").json() if e["rule_id"]}


def test_definition_of_done_flow(client):
    """Spec §73: upload → quarantine → identify → hash → strings → IOCs → structure → heuristics → YARA →
    correlation → findings → graph → MITRE → report, without executing anything."""
    a = analyze(client, "invoice.pdf", factory.injector_pe())
    aid = a["id"]
    root = next(x for x in a["artifacts"] if x["parent_id"] is None)
    assert root["detected_type"] == "pe" and root["extension_mismatch"]
    art = client.get(f"/api/analyses/{aid}/artifacts/{root['id']}").json()
    assert len(art["hashes"]["sha256"]) == 64 and art["hashes"]["ssdeep"] and art["hashes"]["tlsh"]
    strings = client.get(f"/api/analyses/{aid}/artifacts/{root['id']}/strings").json()
    assert strings["total"] > 0
    iocs = client.get(f"/api/analyses/{aid}/iocs").json()
    assert any(i["value"] == "http://203.0.113.50:8080/stage2.bin" for i in iocs)
    assert art["metadata"]["pe"]["sections"]
    fired = rules_fired(client, aid)
    assert {"HEUR-INJ-001", "HEUR-FILE-001"} <= fired
    assert "yara:malx_core:MALX_Process_Injection_API_Set" in fired
    fs = findings(client, aid)
    assert any(f["kind"] == "correlated" for f in fs)
    graph = client.get(f"/api/analyses/{aid}/graph").json()
    assert {n["type"] for n in graph["nodes"]} >= {"sample", "engine", "evidence", "finding", "mitre", "classification"}
    assert all({"source", "target", "relationship", "evidence_id", "confidence"} <= set(e) for e in graph["edges"])
    mitre = client.get(f"/api/analyses/{aid}/mitre").json()["techniques"]
    assert any(t["technique_id"].startswith("T1055") for t in mitre)
    for fmt in ("html", "md", "json"):
        r = client.get(f"/api/analyses/{aid}/report?format={fmt}")
        assert r.status_code == 200 and len(r.content) > 1000
    timeline = client.get(f"/api/analyses/{aid}/timeline").json()
    assert any(t["event"].startswith("File identified") for t in timeline)
    assert a["summary"]["narrative"][0].startswith("I found")


@pytest.mark.parametrize("name,builder,expect_rule,expect_class", [
    ("suspicious_strings_sample.exe", factory.suspicious_strings_pe, "HEUR-CRED-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS"}),
    ("fake_persistence_sample.bat", factory.fake_persistence_script, "HEUR-PERS-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS"}),
    ("ransom_note.txt", factory.ransom_like_text, "HEUR-IMP-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS", "SUSPICIOUS"}),
    ("encoded.ps1", factory.encoded_powershell, "HEUR-EXEC-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS", "SUSPICIOUS"}),
    ("bd.elf", factory.linux_backdoor_elf, "HEUR-LNX-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS"}),
    ("app.apk", factory.banker_like_apk, "HEUR-MOB-001", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS", "SUSPICIOUS"}),
    ("template.docx", factory.ooxml_template_injection, "HEUR-DOC-003", {"HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS", "SUSPICIOUS"}),
    ("evil.zip", factory.path_traversal_zip, "HEUR-ARC-003", {"SUSPICIOUS", "HIGHLY_SUSPICIOUS"}),
])
def test_synthetic_lab(client, name, builder, expect_rule, expect_class):
    a = analyze(client, name, builder())
    assert expect_rule in rules_fired(client, a["id"])
    assert a["classification"] in expect_class, (a["classification"], [f["title"] for f in findings(client, a["id"])])


def test_benign_pe_stays_benign(client):
    a = analyze(client, "hello.exe", factory.benign_pe())
    assert a["classification"] == "BENIGN_INDICATORS"
    assert not [f for f in findings(client, a["id"]) if f["severity"] in ("high", "critical")]


def test_nested_archive_recursion(client):
    a = analyze(client, "sample.zip", factory.archive_nested_sample())
    names = {x["name"] for x in a["artifacts"]}
    assert {"sample.zip", "document.pdf", "invoice.exe", "image.png", "payload.zip", "loader.dll"} <= names
    loader = next(x for x in a["artifacts"] if x["name"] == "loader.dll")
    assert loader["depth"] == 2 and loader["detected_type"] == "pe"


def test_appsec_project(client, tmp_path, monkeypatch):
    adv = tmp_path / "advisories"
    adv.mkdir()
    (adv / "test.json").write_text(json.dumps(factory.test_advisory()))
    monkeypatch.setenv("MALX_ADVISORIES_DIR", str(adv))
    from backend.analyzers import appsec
    appsec._load_advisories.cache_clear()
    st = client.app.state.malx
    st.settings.rules_dir  # noqa: B018
    orig = st.manager.build_job

    def build_job(a, pw):
        job = orig(a, pw)
        job["advisories_dir"] = str(adv)
        return job

    monkeypatch.setattr(st.manager, "build_job", build_job)
    secret = "super-secret-flask-key-123"
    a = analyze(client, "project.zip", factory.vulnerable_project_zip(secret), mode="appsec")
    ap = client.get(f"/api/analyses/{a['id']}/appsec").json()
    assert "Flask" in ap["frameworks"] and "Express" in ap["frameworks"]
    paths = {e["path"] for e in ap["endpoints"]}
    assert {"/api/users", "/admin/run", "/upload", "/api/item", "/login"} <= paths
    rules = {f["rule_id"] for f in ap["code_findings"]}
    assert {"CODE-SQL-001", "CODE-CMD-001", "CODE-PATH-001", "CODE-SSRF-001", "CODE-DESER-001", "CODE-TLS-001",
            "CODE-AUTH-003", "SECRET-AWS-001"} <= rules
    assert any(v["advisory_id"] == "MALX-TEST-0001" for v in ap["vulnerabilities"])
    deps = {(d["ecosystem"], d["name"]) for d in ap["dependencies"]}
    assert ("PyPI", "flask") in deps and ("npm", "lodash") in deps
    surface = {n["id"] for n in ap["attack_surface"]["nodes"]}
    assert {"internet", "api", "upload", "admin", "database", "external", "secrets"} <= surface
    # secrets are masked everywhere
    blob = json.dumps(ap) + client.get(f"/api/analyses/{a['id']}/report?format=json").text
    assert "AKIAABCDEFGHIJKLMNOP" not in blob
    assert secret not in json.dumps(ap["secrets"])


def test_multi_file_upload_and_listing(client):
    aid = upload(client, [("a.txt", b"hello"), ("b.ps1", factory.encoded_powershell())])
    a = wait(client, aid)
    assert a["status"] == "COMPLETED" and len([x for x in a["artifacts"] if x["parent_id"] is None]) == 2
    lst = client.get("/api/analyses").json()
    assert lst["total"] >= 1 and lst["items"][0]["id"] == aid
    res = client.get("/api/search?q=test-c2.duckdns").json()
    assert res["iocs"]


def test_analyst_workflow(client):
    a = analyze(client, "x.bat", factory.fake_persistence_script())
    aid = a["id"]
    ev = client.get(f"/api/analyses/{aid}/evidence").json()
    ref = ev[0]["id"]
    assert client.patch(f"/api/analyses/{aid}/evidence/{ref}", headers=H, json={"status": "CONFIRMED", "note": "seen"}).status_code == 200
    r = client.post(f"/api/analyses/{aid}/findings", headers=H, json={"title": "Analyst hypothesis", "severity": "high",
                                                                     "evidence": [ref], "status": "INVESTIGATING"})
    assert r.status_code == 201
    fs = findings(client, aid)
    mine = next(f for f in fs if f["kind"] == "analyst")
    assert mine["evidence"][0]["id"] == ref
    board = {"nodes": [{"id": "n1", "type": "hypothesis", "data": {"label": "C2 over HTTP", "state": "SUPPORTED"}, "position": {"x": 1, "y": 2}}],
             "edges": [], "notes": "investigating"}
    assert client.put(f"/api/analyses/{aid}/board", headers=H, json=board).status_code == 200
    assert client.get(f"/api/analyses/{aid}/board").json()["nodes"][0]["data"]["state"] == "SUPPORTED"
    chain = client.get(f"/api/analyses/{aid}/findings/{fs[0]['id']}/chain").json()
    assert [s["stage"] for s in chain["stages"]] == ["Sample", "Parser", "Observation", "Heuristic", "Correlation", "Finding", "Classification"]


def test_ioc_exports(client):
    a = analyze(client, "x.bat", factory.fake_persistence_script())
    aid = a["id"]
    txt = client.get(f"/api/analyses/{aid}/iocs?format=txt&defang=true").text
    assert "198[.]51[.]100[.]7" in txt and "http://" not in txt
    csv_ = client.get(f"/api/analyses/{aid}/iocs?format=csv").text
    assert csv_.startswith("type,value")
    assert client.get(f"/api/analyses/{aid}/iocs?format=stix").status_code == 501
    assert client.get("/api/iocs?format=json").status_code == 200
