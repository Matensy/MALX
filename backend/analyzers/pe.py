"""Windows PE analyzer (static, via pefile).

Produces structured metadata (``artifact.metadata["pe"]``) and evidence. No single
indicator here classifies a file: each observation documents legitimate uses.
"""

from __future__ import annotations

import mmap
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pefile

from backend.core.enums import Severity
from backend.rules.loader import RulePack

from .base import AnalysisContext, ArtifactContext, ExtractedString
from .entropy import shannon

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".rsrc", ".reloc", ".tls", ".crt",
    ".CRT", ".debug", ".xdata", ".didat", ".gfids", ".00cfg", ".textbss", ".sdata", ".srdata", ".itext",
    "CODE", "DATA", "BSS", ".code", ".rodata", ".eh_fram", ".init", ".fini", ".ctors", ".dtors", ".text$mn",
    ".giats", ".gehcont", ".retplne", ".voltbl", ".fptable", "INIT", "PAGE", ".mrdata", ".orpc", ".sxdata",
    "_RDATA", ".wixburn", ".ndata", ".symtab", ".buildid", ".edata", ".imrsiv", ".detourc", ".detourd",
    ".stab", ".stabstr", ".rossym", ".msvcjmc", "/4", "/14", "/29", "/41", "/55", "/67", "/80", "/91", "/102",
}
RESOURCE_TYPES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR",
    8: "RT_FONT", 9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
    21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML", 24: "RT_MANIFEST",
}
SUSPICIOUS_PDB_WORDS = re.compile(r"(?i)(stealer|grabber|keylog|inject|payload|crypter|loader|ransom|rat[\\/_.]|backdoor|rootkit|exploit|bypass|dropper|miner|botnet|shellcode|hvnc)")
DLL_CHARS = {
    0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE (ASLR)", 0x0080: "FORCE_INTEGRITY", 0x0100: "NX_COMPAT (DEP)",
    0x0200: "NO_ISOLATION", 0x0400: "NO_SEH", 0x0800: "NO_BIND", 0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE",
}
FILE_CHARS = {
    0x0001: "RELOCS_STRIPPED", 0x0002: "EXECUTABLE_IMAGE", 0x0020: "LARGE_ADDRESS_AWARE", 0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED", 0x1000: "SYSTEM", 0x2000: "DLL",
}
MAX_IMPORT_FUNCS = 4000
MAX_RESOURCES = 2000


def _dec(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _magic_of(data: bytes) -> str | None:
    if data[:2] == b"MZ":
        return "PE/MZ executable"
    if data[:4] == b"\x7fELF":
        return "ELF executable"
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7-Zip archive"
    if data[:7] == b"Rar!\x1a\x07":
        return "RAR archive"
    if data[:4] == b"MSCF":
        return "CAB archive"
    if data[:2] == b"\x1f\x8b":
        return "gzip data"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE document"
    if data[:5] == b"%PDF-":
        return "PDF document"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if data[:3] == b"BZh":
        return "bzip2 data"
    if data[:4] == b"\xef\xbe\xad\xde":
        return "NSIS data"
    return None


def detect_packers(pack: RulePack, path: Path, size: int, section_names: list[str]) -> list[dict[str, Any]]:
    found = []
    names = set(section_names)
    window = 8 * 1024 * 1024
    with open(path, "rb") as fh:
        if size == 0:
            return found
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            regions = [(0, min(size, window))]
            if size > window:
                regions.append((max(window, size - window), size))
            for p in pack.packers:
                hits: list[str] = []
                sec_hit = [s for s in p.get("section_names", []) if s in names]
                if sec_hit:
                    hits += [f"section {s}" for s in sec_hit]
                marker_hits = []
                for marker in p.get("markers", []):
                    needle = marker.encode("latin-1")
                    for a, b in regions:
                        if mm.find(needle, a, b) != -1:
                            marker_hits.append(marker)
                            break
                hits += [f"marker {m!r}" for m in marker_hits[:3]]
                if not hits:
                    continue
                if p.get("require_marker") and not marker_hits:
                    continue
                found.append({"name": p["name"], "kind": p.get("kind", "packer"), "matches": hits})
    return found


def _parse_certificates(data: bytes) -> list[dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except Exception:  # pragma: no cover
        return []
    try:
        certs = pkcs7.load_der_pkcs7_certificates(data)
    except Exception:
        return []
    out = []
    now = datetime.now(timezone.utc)
    for c in certs[:10]:
        try:
            nb = c.not_valid_before_utc
            na = c.not_valid_after_utc
        except AttributeError:  # pragma: no cover - older cryptography
            nb = c.not_valid_before.replace(tzinfo=timezone.utc)
            na = c.not_valid_after.replace(tzinfo=timezone.utc)
        out.append({
            "subject": c.subject.rfc4514_string()[:400],
            "issuer": c.issuer.rfc4514_string()[:400],
            "serial": format(c.serial_number, "x"),
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "self_signed": c.subject == c.issuer,
            "expired": na < now,
        })
    return out


def _dotnet_metadata(pe: pefile.PE, data: bytes) -> dict[str, Any] | None:
    """Minimal CLI metadata parser: runtime version, flags, #Strings and #US heaps."""
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not clr_dir.VirtualAddress:
            return None
        cor = pe.get_offset_from_rva(clr_dir.VirtualAddress)
        _cb, _maj, _min, md_rva, md_size, flags = struct.unpack_from("<IHHIII", data, cor)
        md = pe.get_offset_from_rva(md_rva)
        if data[md:md + 4] != b"BSJB":
            return {"flags": flags, "error": "metadata signature missing"}
        ver_len = struct.unpack_from("<I", data, md + 12)[0]
        version = data[md + 16: md + 16 + min(ver_len, 255)].split(b"\x00", 1)[0].decode("ascii", "replace")
        pos = md + 16 + ver_len
        n_streams = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        streams = {}
        for _ in range(min(n_streams, 16)):
            off, size = struct.unpack_from("<II", data, pos)
            pos += 8
            end = data.index(b"\x00", pos, pos + 32)
            name = data[pos:end].decode("ascii", "replace")
            pos = (end + 4) & ~3
            streams[name] = (md + off, size)
        result: dict[str, Any] = {
            "runtime_version": version, "flags": flags,
            "il_only": bool(flags & 0x1), "requires_32bit": bool(flags & 0x2),
            "strong_name_signed": bool(flags & 0x8), "streams": sorted(streams),
        }
        names: list[str] = []
        if "#Strings" in streams:
            o, s = streams["#Strings"]
            blob = data[o:o + min(s, 4 * 1024 * 1024)]
            names = [x.decode("utf-8", "replace") for x in blob.split(b"\x00") if 3 <= len(x) <= 512]
        us: list[str] = []
        if "#US" in streams:
            o, s = streams["#US"]
            end = o + min(s, 8 * 1024 * 1024)
            i = o + 1
            while i < end and len(us) < 50000:
                b0 = data[i]
                if b0 & 0x80 == 0:
                    ln, hl = b0, 1
                elif b0 & 0xC0 == 0x80:
                    ln, hl = ((b0 & 0x3F) << 8) | data[i + 1], 2
                else:
                    ln, hl = ((b0 & 0x1F) << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3], 4
                i += hl
                if ln == 0:
                    continue
                raw = data[i:i + ln - 1]
                i += ln
                text = raw.decode("utf-16-le", "replace")
                if len(text) >= 3:
                    us.append(text)
        result["member_names"] = names[:20000]
        result["user_strings"] = us
        return result
    except Exception as exc:
        return {"error": f"metadata parse failed: {str(exc)[:120]}"}


def analyze_pe(ctx: AnalysisContext, art: ArtifactContext, pack: RulePack) -> None:
    data_len = art.size
    try:
        pe = pefile.PE(str(art.path), fast_load=True)
    except pefile.PEFormatError as exc:
        art.errors.append(f"pe: {exc}")
        art.metadata["pe"] = {"error": str(exc)[:300]}
        ctx.add_evidence(
            type="malformed_pe", category="structure", source="pe_analyzer", artifact=art,
            title="Malformed PE structure", description=f"The PE parser rejected the file ({str(exc)[:160]}). "
            "Corrupted headers can be accidental or crafted to break analysis tools.",
            severity="low", confidence=0.5, reliability="medium", value=str(exc)[:200],
        )
        return
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except Exception as exc:  # pefile is defensive but hostile inputs exist
        art.errors.append(f"pe directories: {str(exc)[:200]}")
    with open(art.path, "rb") as fh:
        data = fh.read() if data_len <= 512 * 1024 * 1024 else fh.read(512 * 1024 * 1024)
    meta: dict[str, Any] = {}
    fh_ = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    is64 = oh.Magic == 0x20B
    ts = fh_.TimeDateStamp
    ts_iso = None
    ts_flag = None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ts_iso = dt.isoformat()
        now = datetime.now(timezone.utc)
        if ts == 0:
            ts_flag = "zero"
        elif dt > now + timedelta(days=2):
            ts_flag = "future"
        elif dt.year < 1995:
            ts_flag = "before_1995"
    except (OverflowError, OSError, ValueError):
        ts_flag = "invalid"
    meta["headers"] = {
        "machine": f"0x{fh_.Machine:04x}",
        "bits": 64 if is64 else 32,
        "timestamp": ts, "timestamp_iso": ts_iso, "timestamp_anomaly": ts_flag,
        "characteristics": [n for b, n in FILE_CHARS.items() if fh_.Characteristics & b],
        "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, oh.Subsystem),
        "dll_characteristics": [n for b, n in DLL_CHARS.items() if oh.DllCharacteristics & b],
        "image_base": f"0x{oh.ImageBase:x}",
        "entry_point_rva": f"0x{oh.AddressOfEntryPoint:x}",
        "entry_point_va": f"0x{oh.ImageBase + oh.AddressOfEntryPoint:x}",
        "size_of_image": oh.SizeOfImage,
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "checksum_stored": oh.CheckSum,
        "number_of_sections": fh_.NumberOfSections,
        "is_dll": pe.is_dll(), "is_driver": pe.is_driver(),
    }
    if ts_iso and ts_flag is None:
        ctx.event("PE compile timestamp", engine="pe_analyzer", artifact_id=art.id, lane="artifact", ts=ts_iso)
    if oh.CheckSum and data_len <= 32 * 1024 * 1024:
        try:
            computed = pe.generate_checksum()
            meta["headers"]["checksum_computed"] = computed
            meta["headers"]["checksum_valid"] = computed == oh.CheckSum
        except Exception:
            pass

    # --- sections -----------------------------------------------------------------
    sections = []
    ep = oh.AddressOfEntryPoint
    ep_section = None
    for s in pe.sections:
        name = _dec(s.Name)
        chars = s.Characteristics
        r, w, x = bool(chars & 0x40000000), bool(chars & 0x80000000), bool(chars & 0x20000000)
        code = bool(chars & 0x00000020)
        raw = s.get_data()[: 64 * 1024 * 1024]
        ent = shannon(raw) if raw else 0.0
        info = {
            "name": name, "virtual_address": f"0x{s.VirtualAddress:x}", "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData, "raw_offset": s.PointerToRawData, "entropy": ent,
            "permissions": ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-"),
            "contains_code": code, "characteristics": f"0x{chars:08x}",
        }
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_section = name
            info["entry_point"] = True
        sections.append(info)
    meta["sections"] = sections
    meta["entry_point_section"] = ep_section
    names = [s["name"] for s in sections]

    for s in sections:
        if "w" in s["permissions"] and "x" in s["permissions"]:
            ctx.add_evidence(
                type="pe_rwx_section", category="packing", source="pe_analyzer", artifact=art,
                title=f"Writable and executable section {s['name']!r}",
                description="A section that is both writable and executable allows code to modify itself at runtime. "
                            "Common in packed/self-unpacking executables; rare in compiler output.",
                severity="medium", confidence=0.7, reliability="high", value=s["name"],
                details={"section": s}, mitre=["T1027.002"],
            )
        if s["entropy"] >= 7.2 and s["raw_size"] >= 4096:
            ctx.add_evidence(
                type="pe_high_entropy_section", category="packing", source="pe_analyzer", artifact=art,
                title=f"High-entropy section {s['name']!r} ({s['entropy']:.2f})",
                description="Entropy above 7.2 bits/byte indicates compressed or encrypted data. Expected for resources "
                            "and installers; in code sections it suggests packing.",
                severity="medium" if "x" in s["permissions"] else "low", confidence=0.6, reliability="medium",
                value=f"{s['name']}={s['entropy']:.2f}", details={"section": s},
            )
        if "x" in s["permissions"] and s["raw_size"] == 0 and s["virtual_size"] > 0:
            ctx.add_evidence(
                type="pe_virtual_only_exec_section", category="packing", source="pe_analyzer", artifact=art,
                title=f"Executable section {s['name']!r} has no data on disk",
                description="The section only exists in memory and is filled at runtime — a typical unpacking-stub layout.",
                severity="medium", confidence=0.65, reliability="high", value=s["name"], mitre=["T1027.002"],
            )
        elif "x" in s["permissions"] and s["raw_size"] and s["virtual_size"] > 8 * s["raw_size"] and s["virtual_size"] > 65536:
            ctx.add_evidence(
                type="pe_size_mismatch", category="packing", source="pe_analyzer", artifact=art,
                title=f"Section {s['name']!r} virtual size ≫ raw size",
                description="Large in-memory size compared to on-disk data leaves room for unpacked code.",
                severity="low", confidence=0.5, reliability="medium", value=f"{s['virtual_size']}/{s['raw_size']}",
            )
    unusual = [n for n in names if n and n not in STANDARD_SECTIONS]
    nonprint = [n for n in names if any(ord(c) < 32 or ord(c) > 126 for c in n) or not n]
    if unusual:
        meta["unusual_section_names"] = unusual
    if nonprint:
        ctx.add_evidence(
            type="pe_malformed_section_names", category="packing", source="pe_analyzer", artifact=art,
            title="Section names contain non-printable characters or are empty",
            description="Compilers emit printable section names; garbage names are typical of packers and crafted files.",
            severity="low", confidence=0.55, reliability="medium", value=repr(nonprint[:5]),
        )
    if ep_section is None and ep != 0:
        ctx.add_evidence(
            type="pe_entrypoint_outside_sections", category="packing", source="pe_analyzer", artifact=art,
            title="Entry point lies outside every section",
            description="The entry point does not fall within any section — an anomaly used to confuse tools.",
            severity="medium", confidence=0.7, reliability="high", value=meta["headers"]["entry_point_rva"],
        )
    else:
        ep_info = next((s for s in sections if s.get("entry_point")), None)
        if ep_info and "x" not in ep_info["permissions"]:
            ctx.add_evidence(
                type="pe_entrypoint_non_exec", category="packing", source="pe_analyzer", artifact=art,
                title=f"Entry point in non-executable section {ep_info['name']!r}",
                description="Execution starts in a section not marked executable; loaders often tolerate it, compilers never produce it.",
                severity="medium", confidence=0.65, reliability="high", value=ep_info["name"],
            )
        elif ep_info and len(sections) > 2 and ep_info is sections[-1] and ep_info["name"] not in (".text", "CODE"):
            ctx.add_evidence(
                type="pe_entrypoint_last_section", category="packing", source="pe_analyzer", artifact=art,
                title=f"Entry point in last section {ep_info['name']!r}",
                description="Packers and file infectors commonly append a stub section and redirect the entry point to it.",
                severity="low", confidence=0.5, reliability="medium", value=ep_info["name"],
            )

    # --- imports ------------------------------------------------------------------
    imports: dict[str, list[str]] = {}
    nfuncs = 0
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []) or []:
            dll = _dec(entry.dll)
            funcs = imports.setdefault(dll, [])
            for imp in entry.imports:
                if nfuncs >= MAX_IMPORT_FUNCS:
                    break
                fname = _dec(imp.name) if imp.name else f"ord_{imp.ordinal}"
                funcs.append(fname)
                nfuncs += 1
                art.imports.add(fname.lower())
                # Strip A/W suffixes so catalog lookups work for both variants
            art.import_dlls.add(dll.lower())
    meta["imports"] = [{"dll": k, "functions": v} for k, v in imports.items()]
    meta["import_count"] = nfuncs
    try:
        art.imphash = pe.get_imphash() or None
    except Exception:
        art.imphash = None
    meta["imphash"] = art.imphash

    # --- exports ------------------------------------------------------------------
    exports = []
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        for sym in exp.symbols[:3000]:
            name = _dec(sym.name) if sym.name else None
            exports.append({"name": name, "ordinal": sym.ordinal, "rva": f"0x{sym.address:x}" if sym.address else None,
                            "forwarder": _dec(sym.forwarder) if sym.forwarder else None})
            if name:
                art.exports.add(name)
        meta["export_dll_name"] = _dec(exp.name) if getattr(exp, "name", None) else None
    meta["exports"] = exports

    # --- .NET -----------------------------------------------------------------------
    dotnet = _dotnet_metadata(pe, data)
    if dotnet:
        meta["dotnet"] = {k: v for k, v in dotnet.items() if k not in ("member_names", "user_strings")}
        meta["dotnet"]["member_name_count"] = len(dotnet.get("member_names", []))
        meta["dotnet"]["user_string_count"] = len(dotnet.get("user_strings", []))
        art.tags.add("dotnet")
        api_like = [n for n in dotnet.get("member_names", []) if n.lower() in pack.apis]
        meta["dotnet"]["pinvoke_candidates"] = sorted(set(api_like))[:300]
        for n in api_like:
            art.imports.add(n.lower())
        for n in dotnet.get("member_names", [])[:20000]:
            if len(n) >= 5:
                art.strings.append(ExtractedString(0, "dotnet-strings", n, origin="dotnet"))
        for u in dotnet.get("user_strings", []):
            if len(u) >= 4:
                art.strings.append(ExtractedString(0, "dotnet-us", u[:4096], origin="dotnet"))
        art.invalidate_strings()

    # --- import-based evidence ------------------------------------------------------
    if not dotnet:
        if nfuncs == 0 and not pe.is_driver():
            ctx.add_evidence(
                type="pe_no_imports", category="packing", source="pe_analyzer", artifact=art,
                title="No import table",
                description="A native executable without imports must resolve every API at runtime — typical of packed or shellcode-like loaders.",
                severity="medium", confidence=0.65, reliability="high", value="0 imports", mitre=["T1027.002"],
            )
        elif 0 < nfuncs <= 10:
            dynamic = {"loadlibrarya", "loadlibraryw", "getprocaddress", "loadlibraryexa", "loadlibraryexw", "ldrloaddll"} & art.imports
            ctx.add_evidence(
                type="pe_few_imports", category="packing", source="pe_analyzer", artifact=art,
                title=f"Very small import table ({nfuncs} functions)",
                description="Few imports" + (" combined with dynamic API resolution (LoadLibrary/GetProcAddress)" if dynamic else "")
                + " is a common trait of packed executables. Small utilities can also look like this.",
                severity="medium" if dynamic else "low", confidence=0.6 if dynamic else 0.4, reliability="medium",
                value=", ".join(sorted(dynamic)) if dynamic else str(nfuncs),
                mitre=["T1027.002"] if dynamic else [],
            )
    for fname in sorted(art.imports):
        base = fname
        info = pack.apis.get(base)
        if info is None and base.endswith(("a", "w")):
            info = pack.apis.get(base[:-1])
        if info is None or Severity.parse(info.severity).rank < Severity.LOW.rank:
            continue
        ctx.add_evidence(
            type="suspicious_import", category=info.category, source="pe_analyzer", artifact=art,
            title=f"Imports {info.name}" if base == info.name.lower() else f"Imports {fname}",
            description=f"{info.description} Legitimate uses: {info.legit}",
            severity=info.severity, confidence=0.55, reliability="high", value=info.name,
            details={"api": info.name, "legitimate_uses": info.legit, "via": "dotnet metadata" if dotnet else "import table"},
        )

    # --- export evidence -----------------------------------------------------------
    for name in art.exports:
        low = name.lower()
        if "reflectiveloader" in low:
            ctx.add_evidence(
                type="pe_reflective_loader_export", category="injection", source="pe_analyzer", artifact=art,
                title="Exports a ReflectiveLoader function",
                description="The ReflectiveLoader export is the hallmark of reflective DLL injection frameworks.",
                severity="high", confidence=0.85, reliability="high", value=name, mitre=["T1620", "T1055.001"],
            )
        elif low in ("servicemain", "svchostpushserviceglobals"):
            ctx.add_evidence(
                type="pe_service_dll_export", category="persistence", source="pe_analyzer", artifact=art,
                title=f"Exports {name} (service DLL entry point)",
                description="DLL designed to run as a Windows service inside svchost. Legitimate for service components.",
                severity="low", confidence=0.5, reliability="high", value=name,
            )

    # --- resources ------------------------------------------------------------------
    resources = []
    rsrc = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    manifest_text = None
    if rsrc is not None:
        try:
            for type_entry in rsrc.entries:
                rtype = RESOURCE_TYPES.get(type_entry.id, _dec(type_entry.name.string) if type_entry.name else str(type_entry.id))
                for name_entry in getattr(type_entry, "directory", None).entries if hasattr(type_entry, "directory") else []:
                    rname = _dec(name_entry.name.string) if name_entry.name else str(name_entry.id)
                    for lang_entry in getattr(name_entry, "directory", None).entries if hasattr(name_entry, "directory") else []:
                        if len(resources) >= MAX_RESOURCES:
                            break
                        d = lang_entry.data.struct
                        try:
                            off = pe.get_offset_from_rva(d.OffsetToData)
                        except Exception:
                            off = None
                        blob = data[off:off + min(d.Size, 16 * 1024 * 1024)] if off is not None else b""
                        res = {
                            "type": rtype, "name": rname, "lang": lang_entry.data.lang, "size": d.Size,
                            "offset": off, "entropy": shannon(blob) if blob else None,
                            "magic": _magic_of(blob[:16]) if blob else None,
                        }
                        resources.append(res)
                        if rtype == "RT_MANIFEST" and blob and manifest_text is None:
                            manifest_text = blob[:65536].decode("utf-8", "replace")
                        if res["magic"] == "PE/MZ executable":
                            ctx.add_evidence(
                                type="pe_embedded_executable_resource", category="packing", source="pe_analyzer", artifact=art,
                                title=f"Executable embedded in resource {rtype}/{rname}",
                                description="A resource contains a complete PE image — a dropper pattern, also used by installers and self-extracting tools.",
                                severity="medium", confidence=0.7, reliability="high", value=f"{rtype}/{rname}", offset=off,
                                details={"resource": res},
                            )
                        elif res["entropy"] and res["entropy"] >= 7.4 and d.Size >= 32 * 1024 and rtype in ("RT_RCDATA", str(type_entry.id)) and not res["magic"]:
                            ctx.add_evidence(
                                type="pe_encrypted_resource", category="packing", source="pe_analyzer", artifact=art,
                                title=f"Large high-entropy resource {rtype}/{rname}",
                                description="Unidentified high-entropy data in a resource can be an encrypted payload or configuration.",
                                severity="low", confidence=0.5, reliability="medium", value=f"{rtype}/{rname} H={res['entropy']:.2f}",
                                offset=off, details={"resource": res},
                            )
        except Exception as exc:
            art.errors.append(f"pe resources: {str(exc)[:200]}")
    meta["resources"] = resources
    if manifest_text:
        meta["manifest"] = manifest_text[:8000]
        m = re.search(r'requestedExecutionLevel[^>]*level\s*=\s*"([^"]+)"', manifest_text)
        if m:
            meta["requested_execution_level"] = m.group(1)
            if m.group(1) == "requireAdministrator":
                ctx.add_evidence(
                    type="pe_requires_admin", category="privilege", source="pe_analyzer", artifact=art,
                    title="Manifest requests administrator privileges",
                    description="The application asks for elevation at start. Normal for installers and system tools.",
                    severity="low", confidence=0.5, reliability="high", value="requireAdministrator",
                )

    # --- version information -------------------------------------------------------
    try:
        version = {}
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                if getattr(entry, "Key", b"") == b"StringFileInfo":
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            version[_dec(k)] = _dec(v)[:300]
        if version:
            meta["version_info"] = version
            orig = (version.get("OriginalFilename") or "").lower()
            if orig and art.display_name.lower() != orig and orig.rsplit(".", 1)[-1] in ("exe", "dll"):
                meta["original_filename_mismatch"] = version.get("OriginalFilename")
    except Exception:
        pass

    # --- TLS ------------------------------------------------------------------------
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        callbacks = []
        try:
            cb_va = tls.struct.AddressOfCallBacks
            if cb_va:
                rva = cb_va - oh.ImageBase
                width = 8 if is64 else 4
                for i in range(32):
                    raw = pe.get_data(rva + i * width, width)
                    val = int.from_bytes(raw, "little")
                    if val == 0:
                        break
                    callbacks.append(f"0x{val:x}")
        except Exception:
            pass
        meta["tls"] = {"callbacks": callbacks}
        if callbacks:
            ctx.add_evidence(
                type="pe_tls_callbacks", category="anti_analysis", source="pe_analyzer", artifact=art,
                title=f"{len(callbacks)} TLS callback(s)",
                description="TLS callbacks run before the entry point and are used to execute code before a debugger breaks. "
                            "Some runtimes (Rust, Delphi, MinGW) also emit them.",
                severity="low", confidence=0.5, reliability="high", value=", ".join(callbacks[:4]),
                details={"callbacks": callbacks},
            )

    # --- debug / PDB ----------------------------------------------------------------
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        entry = getattr(dbg, "entry", None)
        if entry is not None and hasattr(entry, "PdbFileName"):
            pdb = _dec(entry.PdbFileName)[:400]
            meta["pdb_path"] = pdb
            if SUSPICIOUS_PDB_WORDS.search(pdb):
                ctx.add_evidence(
                    type="pe_suspicious_pdb_path", category="structure", source="pe_analyzer", artifact=art,
                    title="Debug path contains suspicious keywords",
                    description="The PDB path left by the compiler reveals project naming such as loader/stealer/injector.",
                    severity="medium", confidence=0.6, reliability="medium", value=pdb,
                )
    meta["has_relocations"] = bool(oh.DATA_DIRECTORY[5].VirtualAddress and oh.DATA_DIRECTORY[5].Size)

    # --- Authenticode -----------------------------------------------------------------
    sec = oh.DATA_DIRECTORY[4]
    signature = {"present": False}
    if sec.VirtualAddress and sec.Size and sec.VirtualAddress + 8 <= data_len:
        signature["present"] = True
        signature["offset"] = sec.VirtualAddress
        signature["size"] = sec.Size
        try:
            length, revision, ctype = struct.unpack_from("<IHH", data, sec.VirtualAddress)
            signature["certificate_type"] = {1: "X509", 2: "PKCS_SIGNED_DATA", 4: "TS_STACK_SIGNED"}.get(ctype, ctype)
            der = data[sec.VirtualAddress + 8: sec.VirtualAddress + min(length, sec.Size)]
            signature["certificates"] = _parse_certificates(der)
        except struct.error:
            signature["certificates"] = []
        signature["verified"] = False
        signature["note"] = "Signature structure parsed; cryptographic Authenticode verification is not performed by MALX."
        certs = signature.get("certificates") or []
        if certs:
            signer = certs[0]
            for c in certs:
                if not c["self_signed"]:
                    signer = c
                    break
            signature["signer"] = signer["subject"]
            ctx.add_evidence(
                type="pe_signed", category="signature", source="pe_analyzer", artifact=art,
                title="Authenticode signature present",
                description=f"Signer: {signer['subject'][:160]}. Presence of a signature is context, not trust: "
                            "MALX does not verify the signature, and certificates can be stolen or abused.",
                severity="info", confidence=0.8, reliability="medium", value=signer["subject"][:200],
                details={"certificates": certs},
            )
            if all(c["self_signed"] for c in certs):
                ctx.add_evidence(
                    type="pe_self_signed", category="signature", source="pe_analyzer", artifact=art,
                    title="Self-signed code signing certificate",
                    description="The signature chains to no public CA; anyone can create such a certificate.",
                    severity="low", confidence=0.6, reliability="high", value=certs[0]["subject"][:200],
                )
            for c in certs:
                ctx.event("Certificate validity start", engine="pe_analyzer", artifact_id=art.id, lane="artifact", ts=c["not_before"], detail=c["subject"][:120])
    meta["signature"] = signature

    # --- overlay --------------------------------------------------------------------
    try:
        ov = pe.get_overlay_data_start_offset()
    except Exception:
        ov = None
    if ov is not None and ov < data_len:
        ov_size = data_len - ov
        sig_end = (sec.VirtualAddress + sec.Size) if signature["present"] else None
        only_signature = signature["present"] and ov == sec.VirtualAddress and ov_size <= sec.Size + 8
        if not only_signature:
            blob = data[ov: ov + min(ov_size, 16 * 1024 * 1024)]
            ov_info = {"offset": ov, "size": ov_size, "entropy": shannon(blob), "magic": _magic_of(blob[:16]),
                       "after_signature": bool(sig_end and ov >= sig_end)}
            meta["overlay"] = ov_info
            sev = "low"
            desc = "Data appended after the last section. Installers and self-extractors store payloads this way; droppers do too."
            if ov_info["magic"] == "PE/MZ executable":
                sev = "medium"
                desc = "An executable image is appended after the PE — a dropper/binder pattern (also used by some installers)."
            elif ov_info["after_signature"]:
                sev = "medium"
                desc = "Data appended after the Authenticode signature does not invalidate it in some verifiers — a known abuse to smuggle payloads into signed files."
            ctx.add_evidence(
                type="pe_overlay", category="packing", source="pe_analyzer", artifact=art,
                title=f"Overlay of {ov_size} bytes" + (f" ({ov_info['magic']})" if ov_info["magic"] else ""),
                description=desc, severity=sev, confidence=0.55, reliability="high",
                value=f"offset=0x{ov:x} size={ov_size} H={ov_info['entropy']:.2f}", offset=ov, details={"overlay": ov_info},
            )

    # --- rich header ------------------------------------------------------------------
    try:
        rich = pe.parse_rich_header()
        if rich and rich.get("values"):
            vals = rich["values"]
            entries = [{"prod_id": vals[i] >> 16, "build": vals[i] & 0xFFFF, "count": vals[i + 1]} for i in range(0, len(vals) - 1, 2)]
            meta["rich_header"] = {"entries": entries[:64], "checksum": f"0x{rich.get('checksum', 0):x}"}
    except Exception:
        pass

    # --- timestamps, mitigations ----------------------------------------------------------
    if ts_flag in ("future", "zero", "before_1995", "invalid"):
        ctx.add_evidence(
            type="pe_timestamp_anomaly", category="structure", source="pe_analyzer", artifact=art,
            title=f"Compile timestamp anomaly ({ts_flag})",
            description="The TimeDateStamp is zero, in the future or implausibly old. Often forged to mislead analysts; "
                        "reproducible builds (e.g. modern Windows binaries) also emit hash-like timestamps.",
            severity="info" if ts_flag != "future" else "low", confidence=0.4, reliability="low", value=ts_iso or str(ts),
        )
    meta["mitigations"] = {
        "aslr": bool(oh.DllCharacteristics & 0x40), "dep": bool(oh.DllCharacteristics & 0x100),
        "cfg": bool(oh.DllCharacteristics & 0x4000), "high_entropy_va": bool(oh.DllCharacteristics & 0x20),
        "no_seh": bool(oh.DllCharacteristics & 0x400),
    }

    # --- packers / compilers ---------------------------------------------------------------
    found = detect_packers(pack, art.path, data_len, names)
    meta["packers"] = found
    for p in found:
        art.tags.add(f"{p['kind']}:{p['name']}")
        if p["kind"] in ("packer", "protector"):
            art.tags.add("packed")
            ctx.add_evidence(
                type="packer_detected", category="packing", source="pe_analyzer", artifact=art,
                title=f"{p['kind'].capitalize()} detected: {p['name']}",
                description=f"Fingerprint matched ({'; '.join(p['matches'][:3])}). Packing hides code from static analysis; "
                            "commercial software is also packed or protected for size or IP reasons.",
                severity="medium" if p["kind"] == "protector" else "low", confidence=0.75, reliability="high",
                value=p["name"], mitre=["T1027.002"], details=p,
            )
        else:
            art.tags.add(p["kind"])
    art.architecture = art.ident.architecture if art.ident else None
    meta["summary"] = {
        "sections": len(sections), "imports": nfuncs, "dlls": len(imports), "exports": len(exports),
        "resources": len(resources), "signed": signature["present"], "dotnet": bool(dotnet),
        "overlay": "overlay" in meta,
    }
    art.metadata["pe"] = meta
    pe.close()
