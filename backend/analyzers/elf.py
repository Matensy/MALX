"""ELF analyzer (static, via pyelftools) and a minimal Mach-O parser."""

from __future__ import annotations

import struct
from typing import Any

from backend.rules.loader import RulePack

from .base import AnalysisContext, ArtifactContext
from .entropy import shannon
from .pe import detect_packers

SUSPICIOUS_ELF_SYMBOLS = {
    "ptrace": ("anti_analysis", "Self-tracing is a common Linux anti-debugging trick; debuggers/tracers use it legitimately."),
    "execve": ("execution", "Executes programs."),
    "execl": ("execution", "Executes programs."),
    "execvp": ("execution", "Executes programs."),
    "system": ("execution", "Runs shell commands."),
    "popen": ("execution", "Runs shell commands with a pipe."),
    "fork": ("execution", "Creates processes (daemonisation)."),
    "setsid": ("persistence", "Detaches from the terminal (daemonisation)."),
    "daemon": ("persistence", "Daemonises the process."),
    "prctl": ("defense_evasion", "Can rename the process (PR_SET_NAME) to masquerade."),
    "socket": ("network", "Raw networking."),
    "connect": ("network", "Outbound connections."),
    "bind": ("network", "Listens for connections."),
    "inet_addr": ("network", "Parses hardcoded IP addresses."),
    "gethostbyname": ("network", "DNS resolution."),
    "getaddrinfo": ("network", "DNS resolution."),
    "setuid": ("privilege", "Changes user identity."),
    "setgid": ("privilege", "Changes group identity."),
    "mprotect": ("injection", "Changes memory protections (can make data executable)."),
    "dlopen": ("packing", "Loads shared objects at runtime."),
    "unlink": ("file_manipulation", "Deletes files (self-deletion pattern)."),
    "kill": ("impact", "Sends signals to processes."),
    "chmod": ("file_manipulation", "Changes file permissions."),
    "opendir": ("discovery", "Enumerates directories."),
    "getpwnam": ("discovery", "Queries user database."),
    "uname": ("discovery", "Queries system information."),
}


def analyze_elf(ctx: AnalysisContext, art: ArtifactContext, pack: RulePack) -> None:
    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except Exception:  # pragma: no cover
        ctx.limitation("pyelftools not installed; ELF structure not analysed.")
        return
    meta: dict[str, Any] = {}
    try:
        fh = open(art.path, "rb")
        elf = ELFFile(fh)
    except Exception as exc:
        art.errors.append(f"elf: {exc}")
        art.metadata["elf"] = {"error": str(exc)[:300]}
        ctx.add_evidence(
            type="malformed_elf", category="structure", source="elf_analyzer", artifact=art,
            title="Malformed ELF structure", description=f"The ELF parser rejected the file ({str(exc)[:160]}).",
            severity="low", confidence=0.5, reliability="medium", value=str(exc)[:200],
        )
        return
    with fh:
        h = elf.header
        meta["header"] = {
            "class": elf.elfclass, "endianness": "little" if elf.little_endian else "big",
            "osabi": h["e_ident"]["EI_OSABI"], "type": h["e_type"], "machine": h["e_machine"],
            "entry": f"0x{h['e_entry']:x}", "sections": h["e_shnum"], "segments": h["e_phnum"], "flags": h["e_flags"],
        }
        sections = []
        has_symtab = False
        try:
            for sec in elf.iter_sections():
                flags = sec["sh_flags"]
                size = sec["sh_size"]
                ent = None
                if sec["sh_type"] != "SHT_NOBITS" and 0 < size <= 64 * 1024 * 1024:
                    try:
                        ent = shannon(sec.data())
                    except Exception:
                        ent = None
                sections.append({
                    "name": sec.name[:64], "type": sec["sh_type"], "address": f"0x{sec['sh_addr']:x}",
                    "offset": sec["sh_offset"], "size": size, "entropy": ent,
                    "flags": ("A" if flags & 0x2 else "") + ("W" if flags & 0x1 else "") + ("X" if flags & 0x4 else ""),
                })
                if sec["sh_type"] == "SHT_SYMTAB":
                    has_symtab = True
                if len(sections) >= 500:
                    break
        except (ELFError, Exception) as exc:
            art.errors.append(f"elf sections: {str(exc)[:200]}")
        meta["sections"] = sections
        segments = []
        interp = None
        exec_stack = None
        relro = False
        has_dynamic = False
        try:
            for seg in elf.iter_segments():
                f = seg["p_flags"]
                perms = ("r" if f & 4 else "-") + ("w" if f & 2 else "-") + ("x" if f & 1 else "-")
                segments.append({"type": seg["p_type"], "vaddr": f"0x{seg['p_vaddr']:x}", "offset": seg["p_offset"],
                                 "filesz": seg["p_filesz"], "memsz": seg["p_memsz"], "permissions": perms})
                if seg["p_type"] == "PT_INTERP":
                    try:
                        interp = seg.get_interp_name()
                    except Exception:
                        interp = "?"
                elif seg["p_type"] == "PT_GNU_STACK":
                    exec_stack = bool(f & 1)
                elif seg["p_type"] == "PT_GNU_RELRO":
                    relro = True
                elif seg["p_type"] == "PT_DYNAMIC":
                    has_dynamic = True
                if len(segments) >= 200:
                    break
        except Exception as exc:
            art.errors.append(f"elf segments: {str(exc)[:200]}")
        meta["segments"] = segments
        meta["interpreter"] = interp
        needed, rpath, runpath, soname = [], [], [], None
        imported, exported = [], []
        try:
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
                        elif tag.entry.d_tag == "DT_RPATH":
                            rpath.append(tag.rpath)
                        elif tag.entry.d_tag == "DT_RUNPATH":
                            runpath.append(tag.runpath)
                        elif tag.entry.d_tag == "DT_SONAME":
                            soname = tag.soname
                if isinstance(sec, SymbolTableSection) and sec.name == ".dynsym":
                    for i, sym in enumerate(sec.iter_symbols()):
                        if i > 20000:
                            break
                        name = sym.name
                        if not name:
                            continue
                        name = name.split("@", 1)[0]
                        if sym["st_shndx"] == "SHN_UNDEF":
                            imported.append(name)
                        elif sym["st_info"]["type"] == "STT_FUNC":
                            exported.append(name)
        except Exception as exc:
            art.errors.append(f"elf dynamic: {str(exc)[:200]}")
        meta["needed"] = needed
        meta["rpath"] = rpath
        meta["runpath"] = runpath
        meta["soname"] = soname
        meta["imported_symbols"] = sorted(set(imported))[:3000]
        meta["exported_symbols"] = sorted(set(exported))[:3000]
        art.imports.update(s.lower() for s in imported)
        art.import_dlls.update(n.lower() for n in needed)
        art.exports.update(exported[:3000])
        static = interp is None and not has_dynamic
        stripped = not has_symtab
        meta["properties"] = {
            "statically_linked": static, "stripped": stripped, "pie": h["e_type"] == "ET_DYN" and interp is not None,
            "nx": exec_stack is False, "relro": relro,
            "stack_canary": "__stack_chk_fail" in imported, "fortify": any(s.endswith("_chk") for s in imported),
        }
        names = [s["name"] for s in sections]

    for seg in segments:
        if seg["type"] == "PT_LOAD" and seg["permissions"] == "rwx":
            ctx.add_evidence(
                type="elf_rwx_segment", category="packing", source="elf_analyzer", artifact=art,
                title="Loadable segment is readable, writable and executable",
                description="RWX load segments allow self-modifying code — typical of packed ELF files (e.g. UPX) and hand-crafted loaders.",
                severity="medium", confidence=0.7, reliability="high", value=seg["vaddr"], details={"segment": seg},
                mitre=["T1027.002"],
            )
    if exec_stack:
        ctx.add_evidence(
            type="elf_exec_stack", category="structure", source="elf_analyzer", artifact=art,
            title="Executable stack (PT_GNU_STACK RWX)",
            description="The binary requests an executable stack, disabling a basic exploit mitigation. Some legacy/assembly code needs it.",
            severity="low", confidence=0.5, reliability="high", value="PT_GNU_STACK=rwx",
        )
    if h["e_shnum"] == 0 and h["e_type"] in ("ET_EXEC", "ET_DYN"):
        ctx.add_evidence(
            type="elf_no_section_headers", category="anti_analysis", source="elf_analyzer", artifact=art,
            title="ELF without section headers",
            description="Section headers are optional at runtime; removing them hampers disassemblers and is common in packed malware.",
            severity="medium", confidence=0.6, reliability="high", value="e_shnum=0",
        )
    for p in rpath + runpath:
        for part in p.split(":"):
            if part and (part.startswith(("/tmp", "/var/tmp", "/dev/shm", ".")) or part == ""):
                ctx.add_evidence(
                    type="elf_insecure_rpath", category="persistence", source="elf_analyzer", artifact=art,
                    title=f"Library search path points to a writable/relative location ({part})",
                    description="RPATH/RUNPATH entries in world-writable or relative directories enable library hijacking.",
                    severity="low", confidence=0.6, reliability="high", value=part, mitre=["T1574.006"],
                )
    big_entropy = [s for s in sections if s.get("entropy") and s["entropy"] >= 7.2 and s["size"] >= 4096 and "X" in s["flags"]]
    for s in big_entropy:
        ctx.add_evidence(
            type="elf_high_entropy_section", category="packing", source="elf_analyzer", artifact=art,
            title=f"High-entropy executable section {s['name']!r}", description="Compressed/encrypted code suggests packing.",
            severity="medium", confidence=0.55, reliability="medium", value=f"{s['name']}={s['entropy']:.2f}",
        )
    for sym in sorted({s.lower() for s in imported} & set(SUSPICIOUS_ELF_SYMBOLS)):
        cat, desc = SUSPICIOUS_ELF_SYMBOLS[sym]
        if sym in ("ptrace", "mprotect", "prctl"):
            ctx.add_evidence(
                type="suspicious_import", category=cat, source="elf_analyzer", artifact=art,
                title=f"Imports {sym}", description=desc, severity="low", confidence=0.5, reliability="high", value=sym,
            )
    found = detect_packers(pack, art.path, art.size, names)
    meta["packers"] = found
    for p in found:
        if p["kind"] in ("packer", "protector"):
            art.tags.add("packed")
            ctx.add_evidence(
                type="packer_detected", category="packing", source="elf_analyzer", artifact=art,
                title=f"{p['kind'].capitalize()} detected: {p['name']}",
                description="Packing hides code from static analysis; it is also used to shrink legitimate binaries.",
                severity="low", confidence=0.75, reliability="high", value=p["name"], mitre=["T1027.002"], details=p,
            )
        else:
            art.tags.add(p["kind"])
    if static:
        art.tags.add("static")
    if stripped:
        art.tags.add("stripped")
    art.metadata["elf"] = meta


# ------------------------------------------------------------------------------- Mach-O
LC_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER", 0x19: "LC_SEGMENT_64", 0x1B: "LC_UUID", 0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO", 0x2C: "LC_ENCRYPTION_INFO_64", 0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_RPATH", 0x80000028: "LC_MAIN", 0x80000022: "LC_DYLD_INFO_ONLY", 0x32: "LC_BUILD_VERSION",
    0x8000001F: "LC_REEXPORT_DYLIB", 0x24: "LC_VERSION_MIN_MACOSX",
}


def analyze_macho(ctx: AnalysisContext, art: ArtifactContext) -> None:
    with open(art.path, "rb") as fh:
        data = fh.read(min(art.size, 64 * 1024 * 1024))
    meta: dict[str, Any] = {}
    off = 0
    if data[:4] in (b"\xca\xfe\xba\xbe",):
        n = struct.unpack_from(">I", data, 4)[0]
        arches = []
        for i in range(min(n, 20)):
            cpu, sub, o, size, align = struct.unpack_from(">iiIII", data, 8 + i * 20)
            arches.append({"cputype": cpu, "offset": o, "size": size})
        meta["fat_arches"] = arches
        if arches:
            off = arches[0]["offset"]
    magic = data[off:off + 4]
    if magic not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        art.metadata["macho"] = {**meta, "error": "slice magic not recognised"}
        return
    e = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    cputype, sub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(e + "iiIIII", data, off + 4)
    pos = off + (32 if is64 else 28)
    commands, dylibs, segments, rpaths = [], [], [], []
    signed = False
    encrypted = False
    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            break
        cmd, size = struct.unpack_from(e + "II", data, pos)
        if size < 8:
            break
        name = LC_NAMES.get(cmd, f"0x{cmd:x}")
        commands.append(name)
        if cmd in (0xC, 0x80000018, 0x8000001F, 0xD):
            str_off = struct.unpack_from(e + "I", data, pos + 8)[0]
            raw = data[pos + str_off: pos + size].split(b"\x00", 1)[0]
            dylibs.append(raw.decode("utf-8", "replace"))
        elif cmd == 0x8000001C:
            str_off = struct.unpack_from(e + "I", data, pos + 8)[0]
            rpaths.append(data[pos + str_off: pos + size].split(b"\x00", 1)[0].decode("utf-8", "replace"))
        elif cmd in (0x1, 0x19):
            segname = data[pos + 8: pos + 24].split(b"\x00", 1)[0].decode("ascii", "replace")
            if is64:
                maxprot, initprot = struct.unpack_from(e + "ii", data, pos + 56)
            else:
                maxprot, initprot = struct.unpack_from(e + "ii", data, pos + 40)
            perms = ("r" if initprot & 1 else "-") + ("w" if initprot & 2 else "-") + ("x" if initprot & 4 else "-")
            segments.append({"name": segname, "permissions": perms})
            if perms == "rwx":
                ctx.add_evidence(
                    type="macho_rwx_segment", category="packing", source="macho_analyzer", artifact=art,
                    title=f"RWX segment {segname!r}", description="Writable and executable segment (self-modifying code).",
                    severity="medium", confidence=0.65, reliability="high", value=segname,
                )
        elif cmd == 0x1D:
            signed = True
        elif cmd in (0x21, 0x2C):
            cryptid = struct.unpack_from(e + "I", data, pos + 16)[0]
            encrypted = cryptid != 0
        pos += size
    meta.update({
        "cputype": cputype, "filetype": filetype, "ncmds": ncmds, "flags": flags, "commands": commands[:200],
        "dylibs": dylibs[:500], "rpaths": rpaths, "segments": segments, "code_signature": signed, "encrypted": encrypted,
    })
    art.import_dlls.update(d.lower() for d in dylibs)
    if not signed:
        ctx.add_evidence(
            type="macho_unsigned", category="signature", source="macho_analyzer", artifact=art,
            title="Mach-O binary without code signature",
            description="Unsigned binaries cannot run on Apple Silicon without ad-hoc signing; common for developer builds.",
            severity="info", confidence=0.6, reliability="high", value="no LC_CODE_SIGNATURE",
        )
    art.metadata["macho"] = meta
