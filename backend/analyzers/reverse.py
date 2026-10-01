"""Built-in reverse-engineering engine (static disassembly with Capstone).

Recursive-descent function discovery from entry points/exports/TLS callbacks/symbols,
call graph (callers/callees), import and string cross-references, and per-function
API-sequence observations. Pseudo-code requires an external decompiler (Ghidra /
radare2 with r2ghidra or r2dec) — see ``backend.services.tools``.
"""

from __future__ import annotations

import json
import os
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import AnalysisContext, ArtifactContext
from .entropy import shannon

try:
    import capstone  # type: ignore
    from capstone import x86_const  # type: ignore
except Exception:  # pragma: no cover
    capstone = None

MAX_INSNS_PER_FUNCTION = 3000
MAX_STORED_INSNS = 500
MAX_TOTAL_INSNS = 400_000

API_SEQUENCES = [
    {"id": "remote_injection", "category": "injection", "severity": "high", "mitre": ["T1055"],
     "title": "Remote process injection sequence",
     "all": [["virtualallocex", "ntallocatevirtualmemory"], ["writeprocessmemory", "ntwritevirtualmemory"],
             ["createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc"]]},
    {"id": "hollowing", "category": "injection", "severity": "high", "mitre": ["T1055.012"],
     "title": "Process hollowing sequence",
     "all": [["ntunmapviewofsection", "zwunmapviewofsection"], ["setthreadcontext", "wow64setthreadcontext", "ntsetcontextthread"],
             ["resumethread", "ntresumethread"]]},
    {"id": "download_execute", "category": "network", "severity": "medium", "mitre": ["T1105"],
     "title": "Download then execute in the same function",
     "all": [["urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata"],
             ["shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "winexec", "createprocessa", "createprocessw"]]},
    {"id": "keyboard_hook", "category": "collection", "severity": "medium", "mitre": ["T1056.001"],
     "title": "Keyboard hook installation",
     "all": [["setwindowshookexa", "setwindowshookexw"], ["callnexthookex", "getmessagea", "getmessagew"]]},
    {"id": "debugger_check", "category": "anti_analysis", "severity": "low", "mitre": ["T1622"],
     "title": "Debugger checks in the same routine",
     "all": [["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"],
             ["exitprocess", "terminateprocess", "sleep", "outputdebugstringa", "outputdebugstringw"]]},
    {"id": "credential_decrypt", "category": "credential_access", "severity": "medium", "mitre": ["T1555.003"],
     "title": "DPAPI decryption next to file reading",
     "all": [["cryptunprotectdata"], ["createfilea", "createfilew", "readfile", "copyfilea", "copyfilew"]]},
    {"id": "service_install", "category": "persistence", "severity": "medium", "mitre": ["T1543.003"],
     "title": "Service creation and start",
     "all": [["openscmanagera", "openscmanagerw"], ["createservicea", "createservicew"], ["startservicea", "startservicew"]]},
    {"id": "run_key_write", "category": "persistence", "severity": "medium", "mitre": ["T1547.001"],
     "title": "Registry write with autorun key reference",
     "all": [["regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"]],
     "strings": ["currentversion\\run"]},
]


@dataclass
class Segment:
    start: int
    data: bytes
    executable: bool
    name: str

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class Func:
    address: int
    name: str
    source: str
    insns: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    end: int = 0
    callees: set[int] = field(default_factory=set)
    callers: set[int] = field(default_factory=set)
    call_sites: dict[int, list[int]] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)
    strings: dict[int, str] = field(default_factory=dict)
    truncated: bool = False


class Memory:
    def __init__(self, segments: list[Segment]):
        self.segments = sorted(segments, key=lambda s: s.start)
        self.starts = [s.start for s in self.segments]

    def find(self, va: int) -> Segment | None:
        i = bisect_right(self.starts, va) - 1
        if i >= 0:
            seg = self.segments[i]
            if seg.start <= va < seg.end:
                return seg
        return None

    def read(self, va: int, n: int) -> bytes:
        seg = self.find(va)
        if seg is None:
            return b""
        off = va - seg.start
        return seg.data[off:off + n]

    def string_at(self, va: int) -> str | None:
        raw = self.read(va, 512)
        if len(raw) < 4:
            return None
        if raw[1:2] == b"\x00" and 32 <= raw[0] < 127:  # UTF-16LE
            out = []
            for i in range(0, len(raw) - 1, 2):
                c = raw[i] | (raw[i + 1] << 8)
                if c == 0:
                    break
                if not (32 <= c < 127 or c in (9, 10, 13)):
                    return None
                out.append(chr(c))
            s = "".join(out)
            return s if len(s) >= 4 else None
        end = raw.find(b"\x00")
        if end < 4:
            return None
        chunk = raw[:end]
        if all(32 <= b < 127 or b in (9, 10, 13) for b in chunk):
            return chunk.decode("ascii")
        return None


def _pe_model(art: ArtifactContext):
    import pefile

    pe = pefile.PE(str(art.path), fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
    ])
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = pe.FILE_HEADER.Machine
    segs = []
    for s in pe.sections:
        name = s.Name.split(b"\x00", 1)[0].decode("latin-1", "replace")
        data = s.get_data()[: 32 * 1024 * 1024]
        vsize = max(s.Misc_VirtualSize, len(data))
        data = data + b"\x00" * min(max(0, vsize - len(data)), 1024 * 1024)
        segs.append(Segment(base + s.VirtualAddress, data, bool(s.Characteristics & 0x20000000), name))
    imports: dict[int, str] = {}
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []) or []:
            dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
            for imp in entry.imports:
                if imp.address:
                    nm = imp.name.decode("latin-1", "replace") if imp.name else f"ord_{imp.ordinal}"
                    imports[imp.address] = f"{dll}!{nm}"
    starts: list[tuple[int, str, str]] = [(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint, "entry", "entry_point")]
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        for sym in exp.symbols[:2000]:
            if sym.address and not sym.forwarder:
                starts.append((base + sym.address, sym.name.decode("latin-1", "replace") if sym.name else f"export_ord_{sym.ordinal}", "export"))
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None and tls.struct.AddressOfCallBacks:
        width = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
        rva = tls.struct.AddressOfCallBacks - base
        for i in range(16):
            try:
                v = int.from_bytes(pe.get_data(rva + i * width, width), "little")
            except Exception:
                break
            if not v:
                break
            starts.append((v, f"tls_callback_{i}", "tls_callback"))
    arch = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "arm"}.get(machine)
    pe.close()
    return arch, segs, imports, starts, {}


def _elf_model(art: ArtifactContext):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection

    with open(art.path, "rb") as fh:
        elf = ELFFile(fh)
        arch = {"EM_X86_64": "x64", "EM_386": "x86", "EM_AARCH64": "arm64", "EM_ARM": "arm"}.get(elf["e_machine"])
        segs = []
        plt_secs = []
        for sec in elf.iter_sections():
            if sec["sh_addr"] and sec["sh_type"] != "SHT_NOBITS" and sec["sh_size"] and (sec["sh_flags"] & 0x2):
                data = sec.data()[: 32 * 1024 * 1024]
                segs.append(Segment(sec["sh_addr"], data, bool(sec["sh_flags"] & 0x4), sec.name))
                if sec.name in (".plt", ".plt.sec", ".plt.got"):
                    plt_secs.append((sec.name, sec["sh_addr"], data))
        if not segs:  # no section headers: fall back to segments
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    segs.append(Segment(seg["p_vaddr"], seg.data()[: 32 * 1024 * 1024], bool(seg["p_flags"] & 1), "LOAD"))
        got_names: dict[int, str] = {}
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                try:
                    symtab = elf.get_section(sec["sh_link"])
                    for rel in sec.iter_relocations():
                        idx = rel["r_info_sym"]
                        if idx and isinstance(symtab, SymbolTableSection):
                            name = symtab.get_symbol(idx).name
                            if name:
                                got_names[rel["r_offset"]] = name.split("@")[0]
                except Exception:
                    continue
        names: dict[int, str] = {}
        starts: list[tuple[int, str, str]] = [(elf["e_entry"], "entry", "entry_point")] if elf["e_entry"] else []
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for i, sym in enumerate(sec.iter_symbols()):
                    if i > 50000:
                        break
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] and sym["st_shndx"] != "SHN_UNDEF" and sym.name:
                        names[sym["st_value"]] = sym.name
                        starts.append((sym["st_value"], sym.name, "symbol"))
    imports: dict[int, str] = {}
    if capstone is not None and arch in ("x64", "x86"):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32)
        md.detail = True
        for name, addr, data in plt_secs:
            for insn in md.disasm(data, addr):
                if insn.mnemonic in ("jmp", "bnd jmp") and insn.operands and insn.operands[0].type == x86_const.X86_OP_MEM:
                    mem = insn.operands[0].mem
                    target = insn.address + insn.size + mem.disp if mem.base == x86_const.X86_REG_RIP else mem.disp
                    if target in got_names:
                        stub = insn.address - ((insn.address - addr) % 16)
                        imports[stub] = got_names[target]
        for slot, name in got_names.items():
            imports.setdefault(slot, name)
    return arch, segs, imports, starts, names


def _cs(arch: str):
    if arch == "x64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if arch == "x86":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if arch == "arm64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    if arch == "arm":
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    return None


def analyze_reverse(ctx: AnalysisContext, art: ArtifactContext) -> dict[str, Any] | None:
    if capstone is None:
        ctx.limitation("Capstone not installed: built-in disassembly unavailable (pip install capstone).")
        return None
    if "dotnet" in art.tags:
        art.metadata.setdefault("reverse", {})["note"] = ".NET assembly: IL is not disassembled by the built-in engine (use ILSpy/dnSpy)."
        return None
    try:
        if art.detected_type == "pe":
            arch, segs, imports, starts, names = _pe_model(art)
        elif art.detected_type == "elf":
            arch, segs, imports, starts, names = _elf_model(art)
        else:
            return None
    except Exception as exc:
        art.errors.append(f"reverse model: {str(exc)[:200]}")
        return None
    md = _cs(arch) if arch else None
    if md is None:
        ctx.limitation(f"{art.display_name}: architecture not supported by the built-in disassembler.")
        return None
    md.detail = True
    md.skipdata = False
    mem = Memory(segs)
    x86 = arch in ("x86", "x64")
    max_funcs = ctx.limits.max_reverse_functions
    funcs: dict[int, Func] = {}
    queue: list[int] = []
    for addr, name, src in starts:
        seg = mem.find(addr)
        if seg is None or not seg.executable:
            continue
        if addr not in funcs:
            funcs[addr] = Func(addr, name if name != "entry" else f"entry_{addr:x}", src)
            queue.append(addr)
    total = 0
    while queue and total < MAX_TOTAL_INSNS:
        ctx.check()
        fa = queue.pop(0)
        f = funcs[fa]
        blocks = [fa]
        seen_blocks: set[int] = set()
        max_addr = fa
        while blocks and f.count < MAX_INSNS_PER_FUNCTION:
            b = blocks.pop()
            if b in seen_blocks:
                continue
            seen_blocks.add(b)
            seg = mem.find(b)
            if seg is None or not seg.executable:
                continue
            def visit(insn) -> bool:
                nonlocal total, max_addr
                f.count += 1
                total += 1
                max_addr = max(max_addr, insn.address + insn.size)
                rec: dict[str, Any] = {"a": insn.address, "b": insn.bytes.hex(), "m": insn.mnemonic, "o": insn.op_str}
                mnem = insn.mnemonic
                target = None
                mem_target = None
                if x86:
                    for op in insn.operands:
                        if op.type == x86_const.X86_OP_IMM and mnem.startswith(("call", "j")):
                            target = op.imm
                        elif op.type == x86_const.X86_OP_MEM:
                            m = op.mem
                            if m.base == x86_const.X86_REG_RIP:
                                mem_target = insn.address + insn.size + m.disp
                            elif m.base == 0 and m.index == 0:
                                mem_target = m.disp & 0xFFFFFFFFFFFFFFFF
                        elif op.type == x86_const.X86_OP_IMM and mnem in ("push", "mov", "lea"):
                            if mem.find(op.imm) is not None:
                                mem_target = op.imm
                else:
                    if mnem in ("bl", "b", "blx") and insn.operands and insn.operands[0].type == 2:  # IMM
                        target = insn.operands[0].imm
                    elif mnem == "adrp" or mnem == "adr":
                        for op in insn.operands:
                            if op.type == 2:
                                mem_target = op.imm
                ref_name = None
                if mem_target is not None:
                    if mem_target in imports:
                        ref_name = imports[mem_target]
                        f.imports.add(ref_name)
                        rec["imp"] = ref_name
                    else:
                        s = mem.string_at(mem_target)
                        if s:
                            f.strings[mem_target] = s[:200]
                            rec["str"] = s[:120]
                if target is not None:
                    if target in imports:
                        f.imports.add(imports[target])
                        rec["imp"] = imports[target]
                    elif mnem.startswith("call") or mnem in ("bl", "blx"):
                        tseg = mem.find(target)
                        if tseg is not None and tseg.executable:
                            if target not in funcs and len(funcs) < max_funcs:
                                funcs[target] = Func(target, names.get(target, f"sub_{target:x}"), "call")
                                queue.append(target)
                            if target in funcs:
                                f.callees.add(target)
                                funcs[target].callers.add(fa)
                                funcs[target].call_sites.setdefault(fa, []).append(insn.address)
                                rec["call"] = funcs[target].name
                    elif mnem.startswith("j") or mnem == "b":
                        if target in funcs and target != fa:
                            f.callees.add(target)
                            funcs[target].callers.add(fa)
                            rec["call"] = funcs[target].name
                        elif 0 <= target - fa < 0x100000 or 0 <= fa - target < 0x10000:
                            blocks.append(target)
                if len(f.insns) < MAX_STORED_INSNS:
                    f.insns.append(rec)
                if x86 and (mnem in ("ret", "retn", "retf", "hlt", "int3", "ud2") or mnem == "jmp"):
                    return True
                if not x86 and (mnem == "ret" or (mnem == "b" and target is not None)):
                    return True
                return False

            cursor = b
            stop = False
            while not stop and f.count < MAX_INSNS_PER_FUNCTION:
                code = seg.data[cursor - seg.start: cursor - seg.start + 1024]
                if not code:
                    break
                last = None
                for insn in md.disasm(code, cursor, 96):
                    last = insn
                    if f.count >= MAX_INSNS_PER_FUNCTION:
                        f.truncated = True
                        stop = True
                        break
                    stop = visit(insn)
                    if stop:
                        break
                if last is None:
                    break
                cursor = last.address + last.size
                if cursor >= seg.end:
                    break
        f.end = max_addr
        f.insns.sort(key=lambda r: r["a"])

    # API sequence observations per function
    observations = []
    for f in funcs.values():
        apis = {i.split("!")[-1].lower() for i in f.imports}
        strs = " ".join(f.strings.values()).lower()
        for seq in API_SEQUENCES:
            if all(any(a in apis for a in group) for group in seq["all"]) and all(s in strs for s in seq.get("strings", [])):
                observations.append((seq, f))
    for seq, f in observations[:30]:
        ctx.add_evidence(
            type="reverse_api_sequence", category=seq["category"], source="reverse_engine", artifact=art,
            title=f"{seq['title']} in {f.name}",
            description="The APIs are referenced together inside one function, which is stronger than their mere presence in the import table. "
                        "Legitimate tools (debuggers, installers, security software) can implement the same sequences.",
            severity=seq["severity"], confidence=0.75, reliability="high", value=f.name, mitre=seq["mitre"],
            details={"function": f.name, "address": f"0x{f.address:x}", "apis": sorted({i for i in f.imports})[:30]},
            dedupe_key=("reverse_api_sequence", art.id, seq["id"], f.name),
        )
    entry_seg = mem.find(starts[0][0]) if starts else None
    result = {
        "artifact_id": art.id, "arch": arch, "engine": f"capstone {capstone.__version__}",
        "function_count": len(funcs), "instruction_count": total, "truncated": total >= MAX_TOTAL_INSNS or len(funcs) >= max_funcs,
        "segments": [{"name": s.name, "start": f"0x{s.start:x}", "size": len(s.data), "executable": s.executable,
                      "entropy": shannon(s.data[:4 * 1024 * 1024])} for s in mem.segments],
        "entry": f"0x{starts[0][0]:x}" if starts else None,
        "entry_segment": entry_seg.name if entry_seg else None,
        "functions": [
            {
                "address": f"0x{f.address:x}", "name": f.name, "source": f.source, "size": max(0, f.end - f.address),
                "instructions": f.count, "truncated": f.truncated,
                "callers": [funcs[c].name for c in sorted(f.callers)][:200],
                "callees": [funcs[c].name for c in sorted(f.callees)][:200],
                "xrefs": [f"0x{a:x}" for sites in f.call_sites.values() for a in sites][:200],
                "imports": sorted(f.imports)[:200],
                "strings": [{"address": f"0x{a:x}", "value": v} for a, v in sorted(f.strings.items())][:200],
                "segment": (mem.find(f.address).name if mem.find(f.address) else None),
                "assembly": [{"address": f"0x{r['a']:x}", "bytes": r["b"], "mnemonic": r["m"], "operands": r["o"],
                              **({"import": r["imp"]} if "imp" in r else {}), **({"string": r["str"]} if "str" in r else {}),
                              **({"call": r["call"]} if "call" in r else {})} for r in f.insns],
            }
            for f in sorted(funcs.values(), key=lambda x: x.address)
        ],
    }
    out_dir = ctx.storage_root / "evidence" / ctx.analysis_id / "reverse"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{art.id}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    os.chmod(path, 0o600)
    art.reverse_path = str(Path("evidence") / ctx.analysis_id / "reverse" / f"{art.id}.json")
    art.metadata["reverse"] = {"functions": len(funcs), "instructions": total, "arch": arch, "engine": result["engine"],
                               "observations": [f"{s['title']} in {f.name}" for s, f in observations[:30]]}
    ctx.event(f"Disassembled {len(funcs)} functions", engine="reverse_engine", artifact_id=art.id)
    return result
