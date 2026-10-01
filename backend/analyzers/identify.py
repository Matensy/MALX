"""File identification engine.

Identification is based on magic bytes and structural checks. The filename
extension is only auxiliary information used to detect mismatches such as
``invoice.pdf`` that is really a PE32 executable.
"""

from __future__ import annotations

import os
import re
import struct
import zipfile
from pathlib import Path

from .base import Identification

HEAD_SIZE = 64 * 1024

PE_MACHINES = {
    0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARMv7 Thumb-2", 0xAA64: "ARM64",
    0x200: "IA-64", 0x5032: "RISC-V32", 0x5064: "RISC-V64", 0xEBC: "EFI byte code",
}
ELF_MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "ARM64", 0x08: "MIPS", 0x14: "PowerPC",
    0x15: "PowerPC64", 0x2B: "SPARC V9", 0xF3: "RISC-V", 0x16: "S390", 0x02: "SPARC",
    0x32: "IA-64", 0x102: "LoongArch",
}
MACHO_CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 18: "PowerPC", 0x01000012: "PowerPC64"}

SCRIPT_EXTENSIONS = {
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".vbs": "vbscript", ".vbe": "vbscript", ".js": "javascript", ".jse": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".wsf": "wsf", ".bat": "batch", ".cmd": "batch", ".py": "python", ".pyw": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".php": "php", ".pl": "perl",
    ".rb": "ruby", ".hta": "hta", ".lua": "lua", ".applescript": "applescript", ".scpt": "applescript",
}
SOURCE_EXTENSIONS = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".cs": "csharp",
    ".go": "go", ".rs": "rust", ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".swift": "swift", ".m": "objective-c", ".vue": "javascript", ".svelte": "javascript",
    ".dart": "dart", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".groovy": "groovy",
    ".sql": "sql", ".r": "r", ".jl": "julia",
}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "requirements-dev.txt", "poetry.lock", "pyproject.toml", "pipfile", "pipfile.lock", "setup.py",
    "setup.cfg", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum", "cargo.toml",
    "cargo.lock", "composer.json", "composer.lock", "gemfile", "gemfile.lock", "packages.config",
}
CONFIG_EXTENSIONS = {".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "ini", ".cfg": "ini",
                     ".conf": "config", ".env": "dotenv", ".properties": "properties", ".json": "json",
                     ".xml": "xml", ".config": "xml", ".csproj": "xml", ".tf": "terraform",
                     ".dockerfile": "dockerfile"}

# Extension → identification families that are acceptable for it.
EXPECTED = {
    "pe": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".mui", ".com", ".msstyles", ".ax", ".node", ".pyd", ".xll", ".winmd"},
    "dos": {".exe", ".com"},
    "elf": {".so", ".elf", ".o", ".ko", ".bin", ".axf", ".prx", ".mod", ".run"},
    "macho": {".dylib", ".bundle", ".o", ".macho"},
    "pdf": {".pdf", ".ai"},
    "ole": {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".msi", ".msg", ".pub", ".vsd", ".mpp", ".msp", ".db", ".xla", ".wps"},
    "ooxml": {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".xlam", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".vsdx", ".zip"},
    "odf": {".odt", ".ods", ".odp", ".odg", ".zip"},
    "rtf": {".rtf", ".doc"},
    "zip": {".zip", ".jar", ".apk", ".xpi", ".whl", ".nupkg", ".vsix", ".ipa", ".aar", ".war", ".ear", ".epub", ".kmz", ".appx", ".msix", ".crx", ".egg", ".cbz", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"},
    "jar": {".jar", ".war", ".ear", ".zip", ".aar"},
    "apk": {".apk", ".zip", ".aab", ".xapk", ".apks", ".jar"},
    "dex": {".dex", ".odex"},
    "gzip": {".gz", ".tgz", ".gzip", ".svgz", ".z"},
    "bzip2": {".bz2", ".tbz", ".tbz2"},
    "xz": {".xz", ".txz"},
    "zstd": {".zst", ".zstd", ".tzst"},
    "7z": {".7z"},
    "rar": {".rar"},
    "tar": {".tar"},
    "cab": {".cab"},
    "png": {".png"}, "jpeg": {".jpg", ".jpeg", ".jpe", ".jfif"}, "gif": {".gif"}, "bmp": {".bmp", ".dib"},
    "ico": {".ico", ".cur"}, "webp": {".webp"}, "tiff": {".tif", ".tiff"},
    "sqlite": {".db", ".sqlite", ".sqlite3", ".db3"},
    "lnk": {".lnk"},
    "class": {".class"},
    "wasm": {".wasm"},
    "iso": {".iso", ".img"},
}
# Extensions that users treat as "safe to open" — a mismatch with executable content is serious.
LURE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png",
    ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".csv", ".html", ".htm", ".odt", ".zip",
}
EXECUTABLE_TYPES = {"pe", "elf", "macho", "dos", "lnk", "class", "dex", "hta"}
TEXT_LIKE_TYPES = {"text", "script", "source", "config", "html", "xml", "json", "manifest", "svg", "reg", "csv"}


def _ext(name: str) -> str:
    return os.path.splitext(name.lower())[1]


def _is_text(head: bytes) -> tuple[bool, str]:
    if not head:
        return True, "empty"
    if head.startswith(b"\xef\xbb\xbf"):
        return True, "utf-8-bom"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True, "utf-16"
    sample = head[:8192]
    if b"\x00" in sample:
        # UTF-16LE text without BOM: every other byte is zero
        zeros = sample[1::2].count(0)
        if len(sample) > 16 and zeros > 0.9 * (len(sample) // 2) and sample[0::2].count(0) < 0.05 * len(sample):
            return True, "utf-16le"
        return False, ""
    try:
        sample.decode("utf-8")
        return True, "utf-8"
    except UnicodeDecodeError as exc:
        if exc.start > len(sample) - 4:  # truncated multi-byte at buffer edge
            return True, "utf-8"
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / max(1, len(sample)) > 0.92), "latin-1"


def _decode_text(head: bytes, enc: str) -> str:
    if enc in ("utf-16", "utf-16le"):
        try:
            return head.decode("utf-16-le" if enc == "utf-16le" else "utf-16", errors="replace")
        except Exception:
            return ""
    return head.decode("utf-8", errors="replace")


def zip_entry_count(path: Path) -> int | None:
    """Read the declared entry count from the End Of Central Directory record
    *without* parsing the central directory (protects against huge entry tables)."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            tail_len = min(size, 65536 + 22)
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
    except OSError:
        return None
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 22 > len(tail):
        return None
    total = struct.unpack_from("<H", tail, idx + 10)[0]
    if total == 0xFFFF:
        loc = tail.rfind(b"PK\x06\x07", 0, idx)
        if loc >= 0 and loc + 20 <= len(tail):
            z64_off = struct.unpack_from("<Q", tail, loc + 8)[0]
            try:
                with open(path, "rb") as fh:
                    fh.seek(z64_off)
                    rec = fh.read(56)
                if rec[:4] == b"PK\x06\x06":
                    return struct.unpack_from("<Q", rec, 32)[0]
            except OSError:
                return None
    return total


def _identify_pe(head: bytes, details: dict) -> tuple[str, str, str | None, float]:
    if len(head) < 0x40:
        return "dos", "MS-DOS executable (truncated header)", None, 0.6
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew + 24 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return "dos", "MS-DOS executable (no PE header)", None, 0.7
    machine, _nsec, _ts, _p, _n, opt_size, chars = struct.unpack_from("<HHIIIHH", head, e_lfanew + 4)
    arch = PE_MACHINES.get(machine, f"machine 0x{machine:x}")
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", head, opt_off)[0] if opt_off + 2 <= len(head) else 0
    kind = "PE32+" if magic == 0x20B else "PE32"
    is_dll = bool(chars & 0x2000)
    subsystem = None
    dotnet = False
    try:
        sub_off = opt_off + 68
        subsystem = struct.unpack_from("<H", head, sub_off)[0]
        dd_off = opt_off + (112 if magic == 0x20B else 96)
        clr_off = dd_off + 14 * 8
        if clr_off + 8 <= len(head):
            clr_rva, clr_size = struct.unpack_from("<II", head, clr_off)
            dotnet = clr_rva != 0 and clr_size != 0
    except struct.error:
        pass
    role = "DLL" if is_dll else ("driver" if subsystem == 1 else "executable")
    sub_name = {1: "native", 2: "GUI", 3: "console", 10: "EFI application", 11: "EFI boot driver",
                12: "EFI runtime driver", 16: "Windows boot application"}.get(subsystem or -1)
    label = f"{kind} {role}"
    if sub_name:
        label += f" ({sub_name})"
    label += f" {arch}"
    if dotnet:
        label += ", .NET assembly"
    details.update({"pe_kind": kind, "is_dll": is_dll, "subsystem": sub_name, "dotnet": dotnet})
    return "pe", label, arch, 0.99


def _identify_elf(head: bytes, details: dict) -> tuple[str, str, str | None, float]:
    if len(head) < 20:
        return "elf", "ELF (truncated header)", None, 0.6
    cls = {1: "ELF32", 2: "ELF64"}.get(head[4], "ELF")
    endian = "<" if head[5] == 1 else ">"
    e_type, e_machine = struct.unpack_from(endian + "HH", head, 16)
    arch = ELF_MACHINES.get(e_machine, f"machine 0x{e_machine:x}")
    kind = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core dump"}.get(e_type, "unknown type")
    details.update({"elf_class": cls, "elf_type": kind, "endianness": "LSB" if endian == "<" else "MSB"})
    return "elf", f"{cls} {kind} {arch}", arch, 0.99


def _identify_macho(head: bytes, details: dict) -> tuple[str, str, str | None, float]:
    magic = head[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        n = struct.unpack_from(">I", head, 4)[0]
        details["fat_arches"] = n
        return "macho", f"Mach-O universal binary ({n} architectures)", "multi", 0.95
    endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    cputype, _sub, filetype = struct.unpack_from(endian + "iiI", head, 4)
    arch = MACHO_CPU.get(cputype & 0xFFFFFFFF if cputype < 0 else cputype, f"cpu 0x{cputype & 0xFFFFFFFF:x}")
    ftype = {1: "object", 2: "executable", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib stub", 10: "dSYM", 11: "kext"}.get(filetype, "file")
    return "macho", f"Mach-O {bits}-bit {ftype} {arch}", arch, 0.98


def _classify_zip(path: Path, details: dict, max_entries: int) -> tuple[str, str, str, str, float]:
    count = zip_entry_count(path)
    details["declared_entries"] = count
    if count is not None and count > max_entries:
        details["too_many_entries"] = True
        return "zip", "ZIP archive (entry count exceeds limit)", "archive", "application/zip", 0.9
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception as exc:  # corrupted / malformed
        details["zip_error"] = str(exc)[:200]
        return "zip", "ZIP archive (corrupted or unsupported)", "archive", "application/zip", 0.7
    lower = {n.lower() for n in names}
    if "androidmanifest.xml" in lower and any(n.endswith(".dex") for n in lower):
        return "apk", "Android application package (APK)", "apk", "application/vnd.android.package-archive", 0.98
    if "[content_types].xml" in lower:
        doc = "OOXML document"
        mime = "application/vnd.openxmlformats-officedocument"
        if any(n.startswith("word/") for n in lower):
            doc, mime = "Microsoft Word document (OOXML)", mime + ".wordprocessingml.document"
        elif any(n.startswith("xl/") for n in lower):
            doc, mime = "Microsoft Excel workbook (OOXML)", mime + ".spreadsheetml.sheet"
        elif any(n.startswith("ppt/") for n in lower):
            doc, mime = "Microsoft PowerPoint presentation (OOXML)", mime + ".presentationml.presentation"
        if any(n.endswith("vbaproject.bin") for n in lower):
            doc += " with VBA macros"
            details["has_vba"] = True
        return "ooxml", doc, "office", mime, 0.97
    if "mimetype" in lower:
        try:
            with zipfile.ZipFile(path) as zf:
                info = zf.getinfo([n for n in names if n.lower() == "mimetype"][0])
                if info.file_size < 200:
                    mt = zf.read(info).decode("ascii", "replace").strip()
                    if mt.startswith("application/vnd.oasis.opendocument"):
                        return "odf", f"OpenDocument ({mt.rsplit('.', 1)[-1]})", "office", mt, 0.95
                    if mt == "application/epub+zip":
                        return "zip", "EPUB e-book", "archive", mt, 0.95
        except Exception:
            pass
    if "meta-inf/manifest.mf" in lower or any(n.endswith(".class") for n in lower):
        return "jar", "Java archive (JAR)", "jar", "application/java-archive", 0.95
    if any(n.startswith("payload/") and ".app/" in n for n in lower):
        return "zip", "iOS application archive (IPA)", "archive", "application/octet-stream", 0.9
    if any(n.endswith(".dist-info/record") for n in lower):
        return "zip", "Python wheel", "archive", "application/zip", 0.9
    if "manifest.json" in lower and any(n.endswith(".js") for n in lower):
        details["browser_extension_like"] = True
    return "zip", "ZIP archive", "archive", "application/zip", 0.97


def _identify_ole(path: Path, details: dict) -> tuple[str, str]:
    try:
        import olefile

        with olefile.OleFileIO(str(path)) as ole:
            streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)]
    except Exception as exc:
        details["ole_error"] = str(exc)[:200]
        return "ole", "OLE2 compound document (unparseable)"
    low = [s.lower() for s in streams]
    details["ole_streams"] = streams[:200]
    has_macros = any(s.startswith(("macros/", "_vba_project_cur/", "vba/")) or s.endswith("/vba") or "vba_project" in s for s in low)
    details["has_vba"] = has_macros
    suffix = " with VBA macros" if has_macros else ""
    if "worddocument" in low:
        return "ole", "Microsoft Word 97-2003 document" + suffix
    if "workbook" in low or "book" in low:
        return "ole", "Microsoft Excel 97-2003 workbook" + suffix
    if "powerpoint document" in low:
        return "ole", "Microsoft PowerPoint 97-2003 presentation" + suffix
    if any(s.startswith("__substg1.0_") for s in low):
        return "ole", "Outlook message (MSG)"
    if any("\x05summaryinformation" in s for s in low) and any(len(s) > 0 and ord(s[0]) > 0x3800 for s in streams):
        return "ole", "Windows Installer package (MSI)"
    return "ole", "OLE2 compound document" + suffix


def _identify_text(head: bytes, enc: str, ext: str, name: str, details: dict) -> tuple[str, str, str, str, float]:
    text = _decode_text(head[:16384], enc)
    low = text.lower()
    stripped = low.lstrip("﻿ \t\r\n")
    base = os.path.basename(name.lower())
    if base in MANIFEST_NAMES:
        details["manifest"] = base
        return "manifest", f"Dependency manifest ({base})", "source", "text/plain", 0.9
    if stripped.startswith("#!"):
        line = stripped.splitlines()[0]
        lang = "shell"
        for key, val in (("python", "python"), ("perl", "perl"), ("ruby", "ruby"), ("node", "javascript"),
                         ("pwsh", "powershell"), ("powershell", "powershell"), ("php", "php"), ("lua", "lua")):
            if key in line:
                lang = val
                break
        details["language"] = lang
        details["shebang"] = line[:200]
        return "script", f"{lang} script (shebang)", "script", "text/x-script", 0.9
    if stripped.startswith("<?php") or "<?php" in low[:2000]:
        details["language"] = "php"
        return "script", "PHP script", "script", "text/x-php", 0.9
    if "<hta:application" in low:
        details["language"] = "hta"
        return "hta", "HTML Application (HTA)", "script", "application/hta", 0.95
    if stripped.startswith("windows registry editor") or stripped.startswith("regedit4"):
        return "reg", "Windows registry script (.reg)", "script", "text/plain", 0.95
    if stripped.startswith("{\\rtf"):
        return "rtf", "Rich Text Format document", "document", "application/rtf", 0.95
    if stripped.startswith("<svg") or ("<svg" in low[:1000] and stripped.startswith("<?xml")):
        return "svg", "SVG image (XML, may contain script)", "image", "image/svg+xml", 0.9
    if stripped.startswith(("<!doctype html", "<html")) or ("<script" in low[:4000] and "<" in stripped[:1]):
        return "html", "HTML document", "text", "text/html", 0.85
    if stripped.startswith("<?xml"):
        return "xml", "XML document", "text", "application/xml", 0.85
    if ext in SCRIPT_EXTENSIONS:
        lang = SCRIPT_EXTENSIONS[ext]
        details["language"] = lang
        return "script", f"{lang} script", "script", "text/x-script", 0.75
    if ext in SOURCE_EXTENSIONS:
        lang = SOURCE_EXTENSIONS[ext]
        details["language"] = lang
        return "source", f"{lang} source code", "source", "text/x-source", 0.75
    # Content-based script guesses for extension-less / renamed text files
    scores = {
        "powershell": sum(low.count(k) for k in ("invoke-expression", "iex ", "new-object", "$env:", "-executionpolicy", "[convert]::", "write-host", "get-")),
        "vbscript": sum(low.count(k) for k in ("createobject(", "wscript.", "dim ", "end sub", "end function", "on error resume next")),
        "batch": sum(low.count(k) for k in ("@echo off", "\nset ", "goto ", "%~dp0", "\nrem ", "errorlevel")),
        "javascript": sum(low.count(k) for k in ("function(", "function ", "var ", "activexobject", "document.", "=> {", "eval(")),
        "python": sum(low.count(k) for k in ("import ", "def ", "print(", "__name__", "self.")),
        "shell": sum(low.count(k) for k in ("#!/bin/", "chmod +x", "wget ", "curl ", "fi\n", "then\n", "/dev/null")),
    }
    best = max(scores, key=scores.get)
    if scores[best] >= 3:
        details["language"] = best
        details["language_guess"] = True
        return "script", f"{best} script (content heuristics)", "script", "text/x-script", 0.6
    if ext in CONFIG_EXTENSIONS or base in {"dockerfile", ".env", ".htaccess", "web.config"}:
        return "config", f"{CONFIG_EXTENSIONS.get(ext, base)} configuration", "source", "text/plain", 0.7
    if stripped.startswith(("{", "[")):
        return "json", "JSON / structured text", "text", "application/json", 0.6
    return "text", f"Text ({enc})", "text", "text/plain", 0.7


def identify(path: Path, display_name: str, max_zip_entries: int = 10_000) -> Identification:
    with open(path, "rb") as fh:
        head = fh.read(HEAD_SIZE)
    size = path.stat().st_size
    ext = _ext(display_name)
    details: dict = {}
    magic_hex = head[:16].hex()
    det, label, cat, mime, conf, parser, arch = "unknown", "Unknown binary data", "unknown", "application/octet-stream", 0.3, "none", None

    def set_(d, lbl, c, m, cf, p, a=None):
        nonlocal det, label, cat, mime, conf, parser, arch
        det, label, cat, mime, conf, parser, arch = d, lbl, c, m, cf, p, a

    if size == 0:
        set_("empty", "Empty file", "empty", "inode/x-empty", 1.0, "none")
    elif head[:2] == b"MZ":
        d, lbl, a, cf = _identify_pe(head, details)
        set_(d, lbl, "pe" if d == "pe" else "executable", "application/vnd.microsoft.portable-executable", cf,
             "pe_analyzer" if d == "pe" else "none", a)
    elif head[:4] == b"\x7fELF":
        d, lbl, a, cf = _identify_elf(head, details)
        set_(d, lbl, "elf", "application/x-elf", cf, "elf_analyzer", a)
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        d, lbl, a, cf = _identify_macho(head, details)
        set_(d, lbl, "macho", "application/x-mach-binary", cf, "macho_analyzer", a)
    elif head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        n = struct.unpack_from(">I", head, 4)[0]
        if 0 < n < 20:
            d, lbl, a, cf = _identify_macho(head, details)
            set_(d, lbl, "macho", "application/x-mach-binary", cf, "macho_analyzer", a)
        else:
            set_("class", "Java class file", "jar", "application/java-vm", 0.95, "java_analyzer")
    elif head[:4] == b"dex\n" and len(head) >= 8 and head[7:8] == b"\x00":
        set_("dex", f"Android DEX bytecode (version {head[4:7].decode('ascii', 'replace')})", "dex", "application/x-dex", 0.98, "dex_analyzer")
    elif head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        d, lbl, c, m, cf = _classify_zip(path, details, max_zip_entries)
        parser = {"apk": "apk_analyzer", "ooxml": "ooxml_analyzer", "odf": "archive_analyzer", "jar": "java_analyzer"}.get(d, "archive_analyzer")
        set_(d, lbl, c, m, cf, parser)
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        d, lbl = _identify_ole(path, details)
        set_(d, lbl, "office", "application/x-ole-storage", 0.95, "ole_analyzer")
    elif b"%PDF-" in head[:1024]:
        pos = head.find(b"%PDF-")
        details["header_offset"] = pos
        ver = head[pos + 5:pos + 8].decode("ascii", "replace")
        set_("pdf", f"PDF document, version {ver}", "pdf", "application/pdf", 0.97 if pos == 0 else 0.85, "pdf_analyzer")
    elif head[:5] == b"{\\rtf":
        set_("rtf", "Rich Text Format document", "document", "application/rtf", 0.95, "rtf_analyzer")
    elif head[:2] == b"\x1f\x8b":
        set_("gzip", "gzip compressed data", "archive", "application/gzip", 0.95, "archive_analyzer")
    elif head[:3] == b"BZh":
        set_("bzip2", "bzip2 compressed data", "archive", "application/x-bzip2", 0.9, "archive_analyzer")
    elif head[:6] == b"\xfd7zXZ\x00":
        set_("xz", "XZ compressed data", "archive", "application/x-xz", 0.95, "archive_analyzer")
    elif head[:4] == b"\x28\xb5\x2f\xfd":
        set_("zstd", "Zstandard compressed data", "archive", "application/zstd", 0.9, "none")
    elif head[:6] == b"7z\xbc\xaf\x27\x1c":
        set_("7z", "7-Zip archive", "archive", "application/x-7z-compressed", 0.97, "archive_analyzer")
    elif head[:7] == b"Rar!\x1a\x07":
        set_("rar", "RAR archive", "archive", "application/vnd.rar", 0.97, "none")
    elif head[:4] == b"MSCF":
        set_("cab", "Microsoft Cabinet archive", "archive", "application/vnd.ms-cab-compressed", 0.95, "none")
    elif len(head) > 262 and head[257:262] == b"ustar":
        set_("tar", "POSIX tar archive", "archive", "application/x-tar", 0.95, "archive_analyzer")
    elif head[:8] == b"!<arch>\n":
        set_("ar", "ar archive (static library / .deb)", "archive", "application/x-archive", 0.9, "none")
    elif head[:8] == b"\x89PNG\r\n\x1a\n":
        set_("png", "PNG image", "image", "image/png", 0.98, "image_analyzer")
    elif head[:3] == b"\xff\xd8\xff":
        set_("jpeg", "JPEG image", "image", "image/jpeg", 0.97, "image_analyzer")
    elif head[:6] in (b"GIF87a", b"GIF89a"):
        set_("gif", "GIF image", "image", "image/gif", 0.98, "image_analyzer")
    elif head[:2] == b"BM" and len(head) > 14 and struct.unpack_from("<I", head, 2)[0] in (size, size - 1, size + 1):
        set_("bmp", "BMP image", "image", "image/bmp", 0.9, "image_analyzer")
    elif head[:4] == b"\x00\x00\x01\x00" and len(head) > 6 and 0 < struct.unpack_from("<H", head, 4)[0] < 64:
        set_("ico", "Windows icon", "image", "image/vnd.microsoft.icon", 0.8, "image_analyzer")
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        set_("webp", "WebP image", "image", "image/webp", 0.95, "image_analyzer")
    elif head[:4] in (b"II*\x00", b"MM\x00*"):
        set_("tiff", "TIFF image", "image", "image/tiff", 0.9, "image_analyzer")
    elif head[:16] == b"SQLite format 3\x00":
        set_("sqlite", "SQLite 3 database", "database", "application/vnd.sqlite3", 0.99, "none")
    elif head[:20] == b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46":
        set_("lnk", "Windows shortcut (LNK)", "lnk", "application/x-ms-shortcut", 0.99, "lnk_analyzer")
    elif head[:4] == b"\x00asm":
        set_("wasm", "WebAssembly module", "executable", "application/wasm", 0.95, "none")
    elif head[:4] == b"regf":
        set_("registry_hive", "Windows registry hive", "database", "application/octet-stream", 0.95, "none")
    elif head[:8] == b"ElfFile\x00":
        set_("evtx", "Windows event log (EVTX)", "database", "application/octet-stream", 0.95, "none")
    elif head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        set_("pcap", "Packet capture", "database", "application/vnd.tcpdump.pcap", 0.9, "none")
    elif head[:4] == b"ITSF":
        set_("chm", "Compiled HTML Help (CHM)", "document", "application/vnd.ms-htmlhelp", 0.95, "none")
    elif head[4:8] == b"ftyp":
        set_("mp4", "ISO media (MP4/MOV)", "media", "video/mp4", 0.9, "none")
    elif head[:3] == b"ID3" or head[:4] in (b"OggS", b"fLaC"):
        set_("audio", "Audio file", "media", "audio/mpeg", 0.85, "none")
    elif head[:4] == b"Cr24":
        set_("crx", "Chrome extension package (CRX)", "archive", "application/x-chrome-extension", 0.95, "none")
    else:
        is_text, enc = _is_text(head)
        if is_text:
            d, lbl, c, m, cf = _identify_text(head, enc, ext, display_name, details)
            p = {"script": "script_analyzer", "hta": "script_analyzer", "reg": "script_analyzer",
                 "html": "script_analyzer", "svg": "script_analyzer", "rtf": "rtf_analyzer"}.get(d, "text_analyzer")
            set_(d, lbl, c, m, cf, p)
            details["encoding"] = enc
        elif size >= 0x8006 and _iso_check(path):
            set_("iso", "ISO 9660 disk image", "archive", "application/x-iso9660-image", 0.9, "none")

    ident = Identification(
        detected_type=det, label=label, category=cat, mime=mime, confidence=conf, parser=parser,
        magic_hex=magic_hex, extension=ext, architecture=arch, details=details,
    )
    _check_mismatch(ident, display_name)
    return ident


def _iso_check(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0x8001)
            return fh.read(5) == b"CD001"
    except OSError:
        return False


_DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp[34]|zip|rtf|csv|html?)\.(exe|scr|com|bat|cmd|js|jse|vbs|vbe|ps1|hta|lnk|pif|cpl|msi|jar|wsf)$", re.I)


def _check_mismatch(ident: Identification, display_name: str) -> None:
    if _DOUBLE_EXT_RE.search(display_name or ""):
        ident.details["double_extension"] = True
    ext = ident.extension
    if not ext:
        return
    det = ident.detected_type
    if det in ("unknown", "empty"):
        return
    expected = EXPECTED.get(det)
    if det in TEXT_LIKE_TYPES or det in ("hta", "rtf", "manifest", "config"):
        # Text content: only flag when the extension promises a binary format
        binary_exts = set().union(*[v for k, v in EXPECTED.items() if k not in ("rtf",)]) - {".zip", ".db", ".bin", ".doc", ".com"}
        if ext in binary_exts and ext not in SCRIPT_EXTENSIONS and ext not in SOURCE_EXTENSIONS:
            ident.extension_mismatch = True
            ident.mismatch_reason = f"Extension {ext} suggests a binary format but the content is {ident.label}."
        return
    if expected is None:
        return
    if ext not in expected:
        ident.extension_mismatch = True
        ident.mismatch_reason = f"Extension {ext} does not match detected format: {ident.label}."
