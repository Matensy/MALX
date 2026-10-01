"""Security tests (spec §61) and architectural guarantees (spec §2)."""

import ast
import json
import os
import re
from pathlib import Path

import pytest

from backend.core.security import check_member_path, ensure_within, mask_secret, sanitize_display_name
from tests.conftest import H, ROOT, analyze, upload, wait
from tests.samples import factory

BACKEND = ROOT / "backend"


# --------------------------------------------------------------------------- no execution
def test_no_dynamic_execution_primitives_in_backend():
    """MALX must never execute submitted content. Only the allow-listed tool runner may spawn processes,
    and it only launches analysis tools (with the sample path as an argument)."""
    allowed_subprocess = {BACKEND / "services" / "tools.py"}
    offenders = []
    for path in BACKEND.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                owner = getattr(fn.value, "id", "") if isinstance(fn, ast.Attribute) else ""
                if name in ("eval", "exec", "compile") and not owner and isinstance(fn, ast.Name):
                    offenders.append(f"{path}:{node.lineno} {name}()")
                if owner == "os" and name in ("system", "popen", "execv", "execve", "execl", "execlp", "spawnl", "spawnv", "startfile"):
                    offenders.append(f"{path}:{node.lineno} os.{name}()")
                if owner == "subprocess" and path not in allowed_subprocess:
                    offenders.append(f"{path}:{node.lineno} subprocess.{name}()")
                if name in ("import_module", "__import__", "load_module", "exec_module", "spec_from_file_location"):
                    offenders.append(f"{path}:{node.lineno} dynamic import {name}()")
                if owner == "ctypes" and name in ("CDLL", "WinDLL", "LoadLibrary") and path.name != "sandbox.py":
                    offenders.append(f"{path}:{node.lineno} native library load")
    assert not offenders, offenders


def test_tool_runner_refuses_non_allowlisted_binaries():
    from backend.services import tools

    with pytest.raises(PermissionError):
        tools.run_tool(["/bin/sh", "-c", "echo pwned"], timeout=5)


def test_quarantined_files_are_not_executable(client):
    aid = upload(client, [("setup.exe", factory.benign_pe())])
    wait(client, aid)
    st = client.app.state.malx
    for p in (st.storage.root / "quarantine" / aid).iterdir():
        mode = p.stat().st_mode
        assert not mode & 0o111, oct(mode)
        assert re.fullmatch(r"[0-9a-f]{32}\.bin", p.name), "original names are never used as paths"


# --------------------------------------------------------------------------- names / paths
@pytest.mark.parametrize("name,issue", [
    ("../../../../etc/passwd", "path_in_name"),
    ("evil\x00.exe", "null_byte"),
    ("invoice\u202efdp.exe", "bidi_override"),
    ("a" * 600 + ".pdf", "name_too_long"),
    (b"caf\xe9.txt", "malformed_unicode"),
    ("line\nbreak\r.txt", "control_characters"),
])
def test_filename_sanitisation(name, issue):
    s = sanitize_display_name(name)
    assert issue in s.issues
    assert "/" not in s.display and "\\" not in s.display and "\x00" not in s.display
    assert len(s.display) <= 255


def test_member_path_checks():
    assert check_member_path("../../../../etc/passwd").traversal
    assert check_member_path("/etc/passwd").traversal
    assert check_member_path("C:\\Windows\\x").traversal
    ok = check_member_path("dir/sub/file.txt")
    assert not ok.issues and ok.normalized == "dir/sub/file.txt"
    assert "too_deep" in check_member_path("a/" * 100 + "x").issues


def test_ensure_within(tmp_path):
    with pytest.raises(PermissionError):
        ensure_within(tmp_path, tmp_path / ".." / "x")
    link = tmp_path / "link"
    link.symlink_to("/etc")
    with pytest.raises(PermissionError):
        ensure_within(tmp_path, link / "passwd")


def test_secret_masking():
    assert mask_secret("AKIAABCDEFGHIJKLMNOP") == "AKIA************"
    assert "eyJhbGci" not in mask_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", keep=4)


# --------------------------------------------------------------------------- upload limits
def test_oversized_upload_rejected_and_cleaned(client_factory):
    c = client_factory(max_upload_size=1024)
    r = c.post("/api/analyses", headers=H, files=[("files", ("big.bin", b"x" * 5000))])
    assert r.status_code == 413
    q = c.app.state.malx.storage.root / "quarantine"
    assert not any(p.is_file() for p in q.rglob("*")), "partial upload must be removed"


def test_too_many_files_rejected(client_factory):
    c = client_factory(max_files_per_upload=2)
    r = c.post("/api/analyses", headers=H, files=[("files", (f"{i}.txt", b"x")) for i in range(3)])
    assert r.status_code == 413


def test_malformed_and_hostile_filenames_upload(client):
    for name in ("../../../../etc/passwd", "evil\u202egpj.exe", "x" * 3000 + ".exe", "nul\x00byte.txt"):
        aid = upload(client, [(name, factory.benign_pe())])
        a = wait(client, aid)
        assert a["status"] == "COMPLETED"
        for x in a["artifacts"]:
            assert "/" not in x["name"] and len(x["name"]) <= 255


def test_fake_mime_and_extension_mismatch(client):
    r = client.post("/api/analyses", headers=H, files=[("files", ("photo.png", factory.benign_pe(), "image/png"))])
    a = wait(client, r.json()["id"])
    root = a["artifacts"][0]
    assert root["detected_type"] == "pe" and root["extension_mismatch"]
    ev = client.get(f"/api/analyses/{a['id']}/evidence").json()
    assert any(e["type"] == "extension_mismatch" and e["severity"] == "high" for e in ev)


def test_empty_and_null_byte_files(client):
    a = analyze(client, "empty.bin", b"")
    assert a["artifacts"][0]["detected_type"] == "empty"
    a = analyze(client, "nulls.bin", b"\x00" * 10000)
    assert a["status"] == "COMPLETED"


# --------------------------------------------------------------------------- hostile content
@pytest.mark.parametrize("name,builder", [
    ("malformed.exe", lambda: factory.benign_pe()[:700] + os.urandom(300)),
    ("malformed.pdf", factory.malformed_pdf),
    ("corrupted.zip", factory.corrupted_zip),
    ("random.elf", lambda: b"\x7fELF" + os.urandom(2000)),
    ("random.apk", lambda: factory.zip_bytes({"AndroidManifest.xml": os.urandom(500), "classes.dex": b"dex\n035\x00" + os.urandom(200)})),
    ("random.docx", lambda: factory.zip_bytes({"[Content_Types].xml": b"<not xml", "word/document.xml": os.urandom(100)})),
    ("billion_laughs.docx", lambda: factory.zip_bytes({"[Content_Types].xml": b"<?xml version='1.0'?><!DOCTYPE l [<!ENTITY a 'aaaa'><!ENTITY b '&a;&a;&a;&a;'>]><x>&b;</x>",
                                                       "word/_rels/document.xml.rels": b"<?xml version='1.0'?><!DOCTYPE l [<!ENTITY a 'a'>]><Relationships>&a;</Relationships>",
                                                       "word/document.xml": b"<x/>"})),
])
def test_malformed_inputs_do_not_crash(client, name, builder):
    a = analyze(client, name, builder())
    assert a["status"] == "COMPLETED"


def test_zip_bomb_end_to_end(client_factory):
    c = client_factory(max_compression_ratio=100)
    a = analyze(c, "bomb.zip", factory.zip_bomb_sample(16))
    ev = c.get(f"/api/analyses/{a['id']}/evidence").json()
    assert any(e["type"] == "decompression_bomb" for e in ev)
    extracted = c.app.state.malx.storage.root / "extracted" / a["id"]
    total = sum(p.stat().st_size for p in extracted.rglob("*") if p.is_file()) if extracted.exists() else 0
    assert total < 4 * 1024 * 1024


def test_huge_number_of_files(client_factory):
    c = client_factory(max_files_per_archive=50)
    a = analyze(c, "many.zip", factory.many_files_zip(200))
    assert len(a["artifacts"]) == 1
    assert any("extraction incomplete" in l for l in a["limitations"])


def test_deep_nested_archive(client_factory):
    c = client_factory(max_archive_depth=4)
    a = analyze(c, "deep.zip", factory.deep_nested_zip(9))
    assert max(x["depth"] for x in a["artifacts"]) <= 4


def test_resource_exhaustion_timeout(client_factory):
    c = client_factory(max_analysis_time=0)
    aid = upload(c, [("a.exe", factory.benign_pe())])
    a = wait(c, aid)
    assert a["status"] == "FAILED" and "timeout" in a["error"]


def test_report_injection_is_escaped(client):
    payload = b"<script>alert('xss')</script> </td><img src=x onerror=alert(1)> `|break|` ](javascript:alert(1)) " \
              b"http://198.51.100.9/<svg/onload=alert(2)>"
    a = analyze(client, "<img src=x onerror=alert(1)>.txt", payload * 3)
    html = client.get(f"/api/analyses/{a['id']}/report?format=html")
    assert "<script>alert" not in html.text and "<img src=x" not in html.text and "<svg/onload" not in html.text
    assert "script-src" not in html.headers["content-security-policy"] or "'none'" in html.headers["content-security-policy"]
    assert "default-src 'none'" in html.headers["content-security-policy"]
    md = client.get(f"/api/analyses/{a['id']}/report?format=md").text
    assert "<script>" not in md.replace("\\<script\\>", "")


def test_archive_password_never_persisted(client, tmp_path):
    import io

    import pyzipper

    password = "Tr0ub4dor&3-unique-test-password"
    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode())
        z.writestr("inside.txt", b"protected content")
    aid = upload(client, [("protected.zip", bio.getvalue())], password=password)
    a = wait(client, aid)
    assert a["status"] == "COMPLETED"
    assert any(x["name"] == "inside.txt" for x in a["artifacts"])
    root = client.app.state.malx.storage.root
    needle = password.encode()
    for p in root.rglob("*"):
        if p.is_file():
            assert needle not in p.read_bytes(), f"password leaked into {p}"
    for ep in ("", "/evidence", "/findings", "/timeline", "/report?format=json"):
        assert password not in client.get(f"/api/analyses/{aid}{ep}").text


# --------------------------------------------------------------------------- API hardening
def test_csrf_header_required(client):
    r = client.post("/api/analyses", files=[("files", ("a.txt", b"x"))])
    assert r.status_code == 403
    r = client.post("/api/analyses", headers={**H, "Origin": "https://evil.example"}, files=[("files", ("a.txt", b"x"))])
    assert r.status_code == 403


def test_dns_rebinding_host_rejected(client):
    r = client.get("/api/health", headers={"Host": "attacker.example"})
    assert r.status_code == 400


def test_security_headers_and_no_sample_download(client):
    a = analyze(client, "a.exe", factory.benign_pe())
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    art = a["artifacts"][0]
    hexv = client.get(f"/api/analyses/{a['id']}/artifacts/{art['id']}/hex?length=4096").json()
    assert set(hexv) == {"offset", "length", "size", "hex"}  # hex text only, never the raw file
    assert client.get(f"/api/analyses/{a['id']}/artifacts/{art['id']}/hex?length=999999").status_code == 422
    assert client.get("/storage/quarantine").status_code in (404, 200) and b"MZ" not in client.get("/storage/quarantine").content


def test_invalid_ids_and_traversal_in_api(client):
    for bad in ("../../etc/passwd", "%2e%2e%2f%2e%2e%2fetc", "a" * 32, "zzzz"):
        assert client.get(f"/api/analyses/{bad}").status_code == 404


def test_delete_purges_storage(client):
    a = analyze(client, "x.zip", factory.archive_nested_sample())
    root = client.app.state.malx.storage.root
    assert (root / "quarantine" / a["id"]).exists()
    assert client.delete(f"/api/analyses/{a['id']}", headers=H).status_code == 200
    for area in ("quarantine", "extracted", "evidence", "reports"):
        assert not (root / area / a["id"]).exists()


def test_logs_never_contain_password(client, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="malx")
    from backend.core.logging import JsonFormatter, redact

    assert "hunter2" not in redact("archive password=hunter2 token: abc")
    rec = logging.LogRecord("malx.t", logging.INFO, __file__, 1, "password=hunter2", None, None)
    assert "hunter2" not in JsonFormatter().format(rec)


def test_isolated_worker_process(client_factory):
    """The real execution mode: one spawned worker per analysis with rlimits and no network."""
    c = client_factory(mode="process")
    a = analyze(c, "inj.exe", factory.injector_pe())
    hardening = a["engines"]["worker_hardening"]
    assert hardening.get("RLIMIT_AS") and hardening.get("RLIMIT_CORE") == 0
    assert hardening.get("network_namespace") or hardening.get("socket_guard")
    assert a["classification"] in ("SUSPICIOUS", "HIGHLY_SUSPICIOUS", "MALICIOUS_INDICATORS")


def test_worker_memory_limit_is_enforced(client_factory):
    c = client_factory(mode="process", max_memory_per_worker=64 * 1024 * 1024)
    aid = upload(c, [("a.exe", factory.benign_pe())])
    a = wait(c, aid, timeout=120)
    assert a["status"] == "FAILED"
    assert a["error"]
