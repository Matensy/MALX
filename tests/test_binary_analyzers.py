from backend.analyzers import android, documents, elf, pe, reverse, scripts
from backend.analyzers.yara_engine import YaraEngine
from tests.conftest import RULES, artifact_from_bytes
from tests.samples import factory


def types(c):
    return {e.type for e in c.evidence}


def test_pe_parser_benign(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "benign.exe", factory.benign_pe())
    pe.analyze_pe(c, art, pack)
    meta = art.metadata["pe"]
    assert [s["name"] for s in meta["sections"]] == [".text", ".rdata"]
    assert {i["dll"] for i in meta["imports"]} == {"kernel32.dll", "user32.dll"}
    assert "messageboxw" in art.imports
    assert meta["headers"]["bits"] == 64 and meta["imphash"]
    assert meta["entry_point_section"] == ".text"
    assert not {"pe_rwx_section", "packer_detected", "pe_no_imports"} & types(c)


def test_pe_packed_like(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "packed.exe", factory.packed_like_pe())
    pe.analyze_pe(c, art, pack)
    t = types(c)
    assert "pe_rwx_section" in t
    assert "packer_detected" in t
    assert "pe_virtual_only_exec_section" in t
    assert "pe_few_imports" in t
    assert "packed" in art.tags
    assert any(p["name"] == "UPX" for p in art.metadata["pe"]["packers"])


def test_pe_tls_overlay_exports(ctx, pack):
    c = ctx()
    data = factory.build_pe(tls_callbacks=2, overlay=factory.benign_pe(), exports=["ReflectiveLoader", "ServiceMain"], dll=True)
    art = artifact_from_bytes(c, "x.dll", data)
    pe.analyze_pe(c, art, pack)
    t = types(c)
    assert "pe_tls_callbacks" in t
    assert "pe_overlay" in t
    assert "pe_reflective_loader_export" in t
    meta = art.metadata["pe"]
    assert len(meta["tls"]["callbacks"]) == 2
    assert meta["overlay"]["magic"] == "PE/MZ executable"
    assert {e["name"] for e in meta["exports"]} == {"ReflectiveLoader", "ServiceMain"}


def test_pe_suspicious_imports_evidence(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "inj.exe", factory.injector_pe())
    pe.analyze_pe(c, art, pack)
    imports = {e.value for e in c.evidence if e.type == "suspicious_import"}
    assert {"WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"} <= imports
    ev = next(e for e in c.evidence if e.value == "WriteProcessMemory")
    assert "Legitimate uses" in ev.description  # never presented as proof


def test_malformed_pe(ctx, pack):
    c = ctx()
    bad = bytearray(factory.benign_pe())
    bad[0x84:0x86] = b"\x00\x00"
    bad[0x86:0x88] = b"\xff\xff"   # absurd section count
    art = artifact_from_bytes(c, "bad.exe", bytes(bad[:600]))
    pe.analyze_pe(c, art, pack)  # must not raise
    assert art.metadata.get("pe") is not None
    c2 = ctx()
    art2 = artifact_from_bytes(c2, "dos.exe", b"MZ" + b"\x00" * 0x3A + b"\xff\xff\xff\x7f" + b"\x00" * 64)
    assert art2.detected_type == "dos"


def test_elf_parser(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "bd", factory.linux_backdoor_elf())
    elf.analyze_elf(c, art, pack)
    meta = art.metadata["elf"]
    assert meta["needed"] == ["libc.so.6"]
    assert "ptrace" in meta["imported_symbols"]
    assert meta["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert meta["runpath"] == ["/tmp/lib"]
    t = types(c)
    assert {"elf_rwx_segment", "elf_exec_stack", "elf_insecure_rpath"} <= t


def test_reverse_engine_pe(ctx, pack, storage_root):
    c = ctx()
    art = artifact_from_bytes(c, "inj.exe", factory.injector_pe())
    pe.analyze_pe(c, art, pack)
    res = reverse.analyze_reverse(c, art)
    assert res and res["arch"] == "x64"
    names = {f["name"] for f in res["functions"]}
    assert any(n.startswith("entry_") for n in names)
    entry = next(f for f in res["functions"] if f["source"] == "entry_point")
    assert any("WriteProcessMemory" in i for i in entry["imports"])
    assert entry["strings"] and "203.0.113.50" in entry["strings"][0]["value"]
    assert entry["callees"], "helper call should be discovered"
    helper = next(f for f in res["functions"] if f["name"] == entry["callees"][0])
    assert entry["name"] in helper["callers"]
    assert "reverse_api_sequence" in types(c)
    assert (storage_root / art.reverse_path).is_file()


def test_reverse_engine_elf(ctx, pack):
    c = ctx()
    art = artifact_from_bytes(c, "x", factory.build_elf())
    res = reverse.analyze_reverse(c, art)
    assert res and res["function_count"] >= 2


def test_pdf_analyzer(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "doc.pdf", factory.minimal_pdf(js=True))
    documents.analyze_pdf(c, art)
    t = types(c)
    assert "pdf_javascript" in t
    assert any("submitForm" in sn for sn in art.metadata["pdf"]["javascript_snippets"])
    ev = next(e for e in c.evidence if e.type == "pdf_javascript")
    assert ev.severity.value == "high"  # JS + OpenAction
    assert any("198.51.100.21" in s.value for s in art.strings)  # text from a Flate stream


def test_malformed_pdf(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "bad.pdf", factory.malformed_pdf())
    documents.analyze_pdf(c, art)  # must not raise
    assert "pdf_obfuscated_names" in types(c)


def test_ooxml_template_injection_and_dde(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "t.docx", factory.ooxml_template_injection())
    documents.analyze_ooxml(c, art)
    t = types(c)
    assert {"ooxml_template_injection", "office_dde"} <= t
    assert art.metadata["ooxml"]["metadata"]["creator"] == "MALX test"


def test_rtf_and_lnk(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "e.rtf", factory.rtf_exploit_like())
    documents.analyze_rtf(c, art)
    assert "Equation.3" in art.metadata["rtf"]["object_classes"]
    assert {"rtf_embedded_object", "rtf_auto_update"} <= types(c)
    c2 = ctx()
    lnk = artifact_from_bytes(c2, "doc.pdf.lnk", factory.lnk_powershell())
    documents.analyze_lnk(c2, lnk)
    assert {"lnk_lolbin_target", "lnk_padded_arguments", "lnk_minimized"} <= types(c2)


def _ovba_compress(data: bytes) -> bytes:
    """Reference MS-OVBA compressor (greedy) used to test the decompressor."""
    out = bytearray(b"\x01")
    pos = 0
    while pos < len(data):
        chunk = data[pos:pos + 4096]
        body = bytearray()
        i = 0
        while i < len(chunk):
            flag_pos = len(body)
            body.append(0)
            flags = 0
            for bit in range(8):
                if i >= len(chunk):
                    break
                diff = i
                bit_count = max((diff - 1).bit_length(), 4) if diff > 0 else 4
                max_len = (0xFFFF >> bit_count) + 3
                best_len, best_off = 0, 0
                for off in range(1, min(diff, 1 << bit_count) + 1):
                    ln = 0
                    while ln < max_len and i + ln < len(chunk) and chunk[i + ln - off] == chunk[i + ln]:
                        ln += 1
                    if ln > best_len:
                        best_len, best_off = ln, off
                if best_len >= 3:
                    token = ((best_off - 1) << (16 - bit_count)) | (best_len - 3)
                    body += token.to_bytes(2, "little")
                    flags |= 1 << bit
                    i += best_len
                else:
                    body.append(chunk[i])
                    i += 1
            body[flag_pos] = flags
        header = 0xB000 | 0x8000 | ((len(body) + 2 - 3) & 0x0FFF)
        out += header.to_bytes(2, "little") + body
        pos += 4096
    return bytes(out)


def test_vba_decompression_roundtrip():
    src = ('Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n  Set s = CreateObject("WScript.Shell")\r\n'
           '  s.Run "powershell -nop -w hidden -c iex(...)"\r\nEnd Sub\r\n' * 30).encode()
    assert documents.decompress_vba(_ovba_compress(src)) == src


def test_vba_evidence(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "m.bin", b"x")
    code = 'Sub Document_Open()\nSet o = CreateObject("WScript.Shell")\no.Run "cmd /c powershell"\n' \
           'Set x = CreateObject("MSXML2.XMLHTTP")\nEnd Sub\nPrivate Declare PtrSafe Function VirtualAlloc Lib "kernel32" ()\n'
    documents._vba_evidence(c, art, [{"stream": "Macros/VBA/Module1", "code": code}])
    assert {"vba_macro_code", "vba_autoexec", "vba_execution", "vba_download", "vba_shellcode_runner"} <= types(c)


def test_apk_dex_analyzers(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "app.apk", factory.banker_like_apk())
    android.analyze_apk(c, art)
    man = art.metadata["apk"]["manifest"]
    assert man["package"] == "org.malx.synthetic.test"
    assert "android.permission.RECEIVE_SMS" in man["permissions"]
    svc = next(x for x in man["components"] if x["type"] == "service")
    assert svc["permission"].endswith("BIND_ACCESSIBILITY_SERVICE")
    assert {"android_accessibility_service", "android_dangerous_permission", "android_debuggable"} <= types(c)
    c2 = ctx()
    dex = artifact_from_bytes(c2, "classes.dex", factory.build_dex(["Ldalvik/system/DexClassLoader;", "hello"]))
    android.analyze_dex(c2, dex)
    assert "Ldalvik/system/DexClassLoader;" in dex.metadata["dex"]["suspicious_references"]


def test_script_deobfuscation(ctx):
    c = ctx()
    art = artifact_from_bytes(c, "a.ps1", factory.encoded_powershell())
    scripts.analyze_script(c, art)
    assert "powershell_encoded_command_decoded" in types(c)
    assert any("test-c2.duckdns.org" in s.value for s in art.strings)
    c2 = ctx()
    import base64
    payload = b"echo " + base64.b64encode(factory.benign_pe()) + b" > x.b64\n"
    art2 = artifact_from_bytes(c2, "drop.bat", payload)
    scripts.analyze_script(c2, art2)
    assert "encoded_embedded_payload" in types(c2)
    assert any(a.parent_id == art2.id for a in c2.artifacts), "decoded PE must become a child artifact"


def test_yara_engine(ctx):
    engine = YaraEngine(RULES / "yara")
    assert engine.available and engine.rule_count >= 20 and not engine.errors
    c = ctx()
    art = artifact_from_bytes(c, "eicar.com", factory.eicar_like())
    matches = engine.scan(c, art)
    assert [m["rule"] for m in matches] == ["MALX_EICAR_Test_String"]
    ev = next(e for e in c.evidence if e.type == "yara_match")
    assert ev.severity.value == "info" and ev.details["strings"]
    c2 = ctx()
    art2 = artifact_from_bytes(c2, "note.txt", factory.ransom_like_text())
    rules = {m["rule"] for m in engine.scan(c2, art2)}
    assert {"MALX_Ransom_Note_Language", "MALX_Inhibit_System_Recovery"} <= rules
