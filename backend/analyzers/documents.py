"""Static document analysis: PDF, OOXML, OLE/VBA, RTF and Windows LNK.

Documents are parsed as bytes. Nothing is rendered, opened by a default
application, or executed — macros are decompressed and *read*, never run.
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import AnalysisContext, ArtifactContext, ExtractedString
from .strings_engine import strings_from_text

MAX_STREAM_OUT = 8 * 1024 * 1024
MAX_TOTAL_PDF_OUT = 64 * 1024 * 1024
MAX_XML = 4 * 1024 * 1024

# ======================================================================================
# PDF
# ======================================================================================
PDF_KEYWORDS = ["obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "/Page", "/Encrypt",
                "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm", "/JBIG2Decode", "/RichMedia",
                "/Launch", "/EmbeddedFile", "/EmbeddedFiles", "/XFA", "/URI", "/SubmitForm", "/GoToR", "/GoToE",
                "/ImportData", "/Filespec"]
_PDF_NAME_RE = re.compile(rb"/[A-Za-z0-9#_.\-]+")
_PDF_STREAM_RE = re.compile(rb"stream\r?\n")
_PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]{1,2048})\)")
_PDF_JS_LITERAL_RE = re.compile(rb"/JS\s*\((.{1,65536}?)(?<!\\)\)", re.S)
_PDF_INFO_RE = re.compile(rb"/(Author|Creator|Producer|Title|Subject|CreationDate|ModDate)\s*\(([^)]{0,512})\)")
_PDF_DATE_RE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")


def _pdf_name_decode(raw: bytes) -> tuple[str, bool]:
    if b"#" not in raw:
        return raw.decode("latin-1"), False
    out = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)
    return out.decode("latin-1"), out != raw


def _pdf_date(value: str) -> str | None:
    m = _PDF_DATE_RE.search(value)
    if not m:
        return None
    parts = [int(p) if p else d for p, d in zip(m.groups(), (1970, 1, 1, 0, 0, 0))]
    try:
        return datetime(*parts, tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def analyze_pdf(ctx: AnalysisContext, art: ArtifactContext) -> None:
    with open(art.path, "rb") as fh:
        data = fh.read(min(art.size, ctx.limits.max_deep_scan_size))
    counts = {k: 0 for k in PDF_KEYWORDS}
    obfuscated: set[str] = set()
    for m in _PDF_NAME_RE.finditer(data):
        name, was_obf = _pdf_name_decode(m.group())
        if name in counts:
            counts[name] += 1
            if was_obf:
                obfuscated.add(name)
    for kw in ("obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref"):
        counts[kw] = len(re.findall(rb"\b" + kw.encode() + rb"\b", data))
    header_off = data.find(b"%PDF-")
    eof_positions = [m.start() for m in re.finditer(rb"%%EOF", data)]
    trailing = len(data) - (eof_positions[-1] + 5) if eof_positions else 0
    meta: dict[str, Any] = {"keywords": counts, "header_offset": header_off, "eof_markers": len(eof_positions),
                            "trailing_bytes": max(0, trailing), "obfuscated_names": sorted(obfuscated)}

    # Decompress Flate streams (bounded) and collect their text
    total = 0
    streams_decoded = 0
    stream_errors = 0
    js_snippets: list[str] = []
    decoded_texts: list[str] = []
    for m in _PDF_STREAM_RE.finditer(data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        dict_start = data.rfind(b"<<", max(0, m.start() - 2048), m.start())
        header = data[dict_start:m.start()] if dict_start >= 0 else b""
        raw = data[start:end]
        if b"/FlateDecode" in header or b"/Fl " in header or b"/Fl/" in header:
            try:
                d = zlib.decompressobj()
                out = d.decompress(raw, MAX_STREAM_OUT)
                total += len(out)
                streams_decoded += 1
            except zlib.error:
                stream_errors += 1
                continue
        else:
            out = raw[:MAX_STREAM_OUT]
        if total > MAX_TOTAL_PDF_OUT:
            ctx.limitation(f"{art.display_name}: PDF stream decompression budget exhausted.")
            break
        text = out.decode("latin-1", "replace")
        low = text.lower()
        if any(k in low for k in ("app.alert", "eval(", "unescape(", "this.exportdataobject", "util.printf", "getannots",
                                    "spray", "string.fromcharcode", "app.launchurl", "this.submitform")):
            js_snippets.append(text[:4000])
        for name_m in _PDF_NAME_RE.finditer(out[:2 * 1024 * 1024]):
            name, was_obf = _pdf_name_decode(name_m.group())
            if name in counts and name not in ("/Page",):
                counts[name] += 1
                if was_obf:
                    obfuscated.add(name)
        printable = re.findall(r"[\x20-\x7e]{6,}", text[:2 * 1024 * 1024])
        if printable:
            decoded_texts.extend(printable[:5000])
    meta["streams_decoded"] = streams_decoded
    meta["stream_errors"] = stream_errors
    uris = sorted({u.decode("latin-1", "replace") for u in _PDF_URI_RE.findall(data)})[:500]
    meta["uris"] = uris
    for jm in _PDF_JS_LITERAL_RE.finditer(data[:16 * 1024 * 1024]):
        js_snippets.append(jm.group(1).decode("latin-1", "replace")[:4000])
    meta["javascript_snippets"] = [s[:2000] for s in js_snippets[:20]]
    info: dict[str, str] = {}
    for k, v in _PDF_INFO_RE.findall(data[:4 * 1024 * 1024]):
        info.setdefault(k.decode(), v.decode("latin-1", "replace")[:300])
    meta["info"] = info
    for k in ("CreationDate", "ModDate"):
        if k in info:
            iso = _pdf_date(info[k])
            if iso:
                ctx.event(f"PDF {k}", engine="pdf_analyzer", artifact_id=art.id, lane="artifact", ts=iso)
    art.metadata["pdf"] = meta
    extra = [ExtractedString(0, "pdf-stream", t, origin="decoded") for t in decoded_texts]
    extra += [ExtractedString(0, "pdf-uri", u, origin="decoded") for u in uris]
    for snippet in js_snippets:
        extra += strings_from_text(snippet, origin="pdf_js")
    art.strings.extend(extra)
    art.invalidate_strings()

    has_js = counts["/JS"] + counts["/JavaScript"] > 0 or bool(js_snippets)
    auto = counts["/OpenAction"] + counts["/AA"] > 0
    if has_js:
        art.tags.add("pdf_javascript")
        ctx.add_evidence(
            type="pdf_javascript", category="document", source="pdf_analyzer", artifact=art,
            title="PDF contains JavaScript" + (" triggered automatically" if auto else ""),
            description="JavaScript in PDFs is used by interactive forms, and by exploits/phishing lures. "
                        + ("An /OpenAction or /AA entry runs code when the document is opened or on events." if auto else ""),
            severity="high" if auto else "medium", confidence=0.75 if auto else 0.6, reliability="high",
            value=f"/JS={counts['/JS']} /JavaScript={counts['/JavaScript']} /OpenAction={counts['/OpenAction']} /AA={counts['/AA']}",
            mitre=["T1059.007"], details={"snippets": meta["javascript_snippets"][:3]},
        )
    elif auto:
        ctx.add_evidence(
            type="pdf_auto_action", category="document", source="pdf_analyzer", artifact=art,
            title="PDF defines automatic actions (/OpenAction or /AA)",
            description="Automatic actions run when the document is opened (often just 'go to page 1').",
            severity="low", confidence=0.4, reliability="medium", value=f"/OpenAction={counts['/OpenAction']} /AA={counts['/AA']}",
        )
    if counts["/Launch"]:
        ctx.add_evidence(
            type="pdf_launch_action", category="execution", source="pdf_analyzer", artifact=art,
            title="PDF /Launch action", description="/Launch actions can start external programs — rarely legitimate in distributed documents.",
            severity="high", confidence=0.75, reliability="high", value=f"/Launch={counts['/Launch']}", mitre=["T1204.002"],
        )
    if counts["/EmbeddedFile"] or counts["/EmbeddedFiles"]:
        ctx.add_evidence(
            type="pdf_embedded_file", category="document", source="pdf_analyzer", artifact=art,
            title="PDF carries embedded files", description="Attachments inside PDFs can deliver secondary payloads; also used for invoices and portfolios.",
            severity="medium", confidence=0.55, reliability="high", value=f"/EmbeddedFile={counts['/EmbeddedFile']}",
        )
    if obfuscated:
        ctx.add_evidence(
            type="pdf_obfuscated_names", category="packing", source="pdf_analyzer", artifact=art,
            title="Hex-obfuscated PDF names", description=f"Names such as {sorted(obfuscated)[:4]} are written with #xx escapes — used to evade keyword scanners.",
            severity="medium", confidence=0.7, reliability="high", value=", ".join(sorted(obfuscated)), mitre=["T1027"],
        )
    if counts["/XFA"] or counts["/RichMedia"] or counts["/JBIG2Decode"]:
        ctx.add_evidence(
            type="pdf_risky_features", category="document", source="pdf_analyzer", artifact=art,
            title="PDF uses historically exploited features",
            description="XFA forms, RichMedia (Flash) and JBIG2 streams have repeatedly been exploit vectors. They also have legitimate uses.",
            severity="low", confidence=0.45, reliability="medium",
            value=f"/XFA={counts['/XFA']} /RichMedia={counts['/RichMedia']} /JBIG2Decode={counts['/JBIG2Decode']}",
        )
    if counts["/SubmitForm"] or counts["/GoToR"] or counts["/GoToE"] or counts["/ImportData"]:
        ctx.add_evidence(
            type="pdf_external_actions", category="network", source="pdf_analyzer", artifact=art,
            title="PDF submits data or opens remote documents",
            description="/SubmitForm, /GoToR, /GoToE or /ImportData send data to or load content from outside the document (phishing/credential harvesting pattern).",
            severity="low", confidence=0.45, reliability="medium",
            value=f"/SubmitForm={counts['/SubmitForm']} /GoToR={counts['/GoToR']}",
        )
    if header_off > 0 or trailing > 1024:
        ctx.add_evidence(
            type="pdf_polyglot", category="structure", source="pdf_analyzer", artifact=art,
            title="Data before the PDF header or after %%EOF",
            description=f"{header_off} byte(s) precede the header and {max(0, trailing)} follow the last %%EOF. "
                        "Polyglot files hide another format inside a PDF.",
            severity="medium" if header_off > 0 else "low", confidence=0.55, reliability="medium",
            value=f"header_offset={header_off} trailing={max(0, trailing)}",
        )
    if counts["/Encrypt"]:
        ctx.add_evidence(
            type="pdf_encrypted", category="defense_evasion", source="pdf_analyzer", artifact=art,
            title="Encrypted PDF", description="Encryption limits static inspection of streams.",
            severity="low", confidence=0.5, reliability="high", value="/Encrypt",
        )
    if counts["obj"] == 0 or counts["/Page"] == 0:
        ctx.add_evidence(
            type="pdf_malformed", category="structure", source="pdf_analyzer", artifact=art,
            title="PDF structure incomplete or malformed",
            description="No objects or pages were found; the file may be truncated or crafted.",
            severity="low", confidence=0.4, reliability="medium", value=f"obj={counts['obj']} /Page={counts['/Page']}",
        )


# ======================================================================================
# OOXML (docx/xlsx/pptx)
# ======================================================================================
def _xml(zf: zipfile.ZipFile, name: str):
    from defusedxml import ElementTree as ET

    info = zf.getinfo(name)
    if info.file_size > MAX_XML:
        return None
    with zf.open(info) as fh:
        raw = fh.read(MAX_XML + 1)
    try:
        return ET.fromstring(raw)
    except Exception:
        return None


def analyze_ooxml(ctx: AnalysisContext, art: ArtifactContext) -> None:
    meta: dict[str, Any] = {"external_relationships": [], "embeddings": [], "activex": [], "dde": [], "metadata": {}}
    try:
        zf = zipfile.ZipFile(art.path)
    except Exception as exc:
        art.errors.append(f"ooxml: {exc}")
        return
    with zf:
        names = zf.namelist()[:20000]
        low = [n.lower() for n in names]
        meta["has_vba"] = any(n.endswith("vbaproject.bin") for n in low)
        meta["xlm_macrosheets"] = [n for n in names if n.lower().startswith("xl/macrosheets/")]
        meta["embeddings"] = [n for n in names if "/embeddings/" in n.lower()][:200]
        meta["activex"] = [n for n in names if "/activex/" in n.lower()][:200]
        for name in names:
            if not name.lower().endswith(".rels"):
                continue
            root = _xml(zf, name)
            if root is None:
                continue
            for rel in root.iter():
                if not rel.tag.endswith("Relationship"):
                    continue
                if (rel.get("TargetMode") or "").lower() == "external":
                    rtype = (rel.get("Type") or "").rsplit("/", 1)[-1]
                    meta["external_relationships"].append({"source": name, "type": rtype, "target": (rel.get("Target") or "")[:2048]})
        for name in names:
            ln = name.lower()
            if ln in ("word/document.xml", "word/footnotes.xml", "word/endnotes.xml", "word/header1.xml") or (ln.startswith("xl/") and ln.endswith(".xml") and "sheet" in ln):
                try:
                    info = zf.getinfo(name)
                    if info.file_size > MAX_XML * 4:
                        continue
                    text = zf.read(info).decode("utf-8", "replace")
                except Exception:
                    continue
                for m in re.finditer(r"(?i)(DDEAUTO|\bDDE\b)[^<]{0,300}", text):
                    meta["dde"].append({"part": name, "field": m.group()[:300]})
        for core in ("docProps/core.xml", "docProps/app.xml"):
            if core in names:
                root = _xml(zf, core)
                if root is not None:
                    for el in root:
                        tag = el.tag.rsplit("}", 1)[-1]
                        if el.text and tag in ("creator", "lastModifiedBy", "created", "modified", "title", "Application", "Company", "AppVersion", "Template", "subject", "description"):
                            meta["metadata"][tag] = el.text[:300]
    for k in ("created", "modified"):
        v = meta["metadata"].get(k)
        if v:
            ctx.event(f"Document {k}", engine="ooxml_analyzer", artifact_id=art.id, lane="artifact", ts=v)
    art.metadata["ooxml"] = meta
    targets = [r["target"] for r in meta["external_relationships"]]
    art.strings.extend(ExtractedString(0, "ooxml-rel", t, origin="decoded") for t in targets)
    art.invalidate_strings()

    for rel in meta["external_relationships"]:
        t = rel["type"].lower()
        if t in ("attachedtemplate", "subdocument", "frame"):
            ctx.add_evidence(
                type="ooxml_template_injection", category="document", source="ooxml_analyzer", artifact=art,
                title=f"Remote {rel['type']} loaded from an external URL",
                description="The document fetches a template/frame from outside when opened — the remote template injection technique.",
                severity="high", confidence=0.8, reliability="high", value=rel["target"][:500], mitre=["T1221"], details=rel,
            )
        elif t == "oleobject":
            ctx.add_evidence(
                type="ooxml_external_ole", category="document", source="ooxml_analyzer", artifact=art,
                title="External OLE object link", description="An OLE object is linked from a remote location (e.g. CVE-2017-0199-style lures).",
                severity="high", confidence=0.75, reliability="high", value=rel["target"][:500], mitre=["T1221", "T1203"], details=rel,
            )
        elif t not in ("hyperlink",):
            ctx.add_evidence(
                type="ooxml_external_reference", category="document", source="ooxml_analyzer", artifact=art,
                title=f"External {rel['type']} reference", description="The document references external content.",
                severity="low", confidence=0.4, reliability="medium", value=rel["target"][:500], details=rel,
            )
    if meta["has_vba"]:
        art.tags.add("macros")
        ctx.add_evidence(
            type="office_macros_present", category="document", source="ooxml_analyzer", artifact=art,
            title="Document contains a VBA project", description="Macros can automate legitimate workflows and are a top malware delivery method. "
            "The VBA project is extracted and inspected separately.",
            severity="medium", confidence=0.6, reliability="high", value="vbaProject.bin",
        )
    if meta["xlm_macrosheets"]:
        ctx.add_evidence(
            type="office_xlm_macros", category="document", source="ooxml_analyzer", artifact=art,
            title="Excel 4.0 (XLM) macro sheets", description="Legacy XLM macros are rarely used legitimately today and widely abused.",
            severity="high", confidence=0.7, reliability="high", value=", ".join(meta["xlm_macrosheets"][:5]), mitre=["T1059"],
        )
    if meta["dde"]:
        ctx.add_evidence(
            type="office_dde", category="execution", source="ooxml_analyzer", artifact=art,
            title="DDE field in document", description="Dynamic Data Exchange fields can launch commands when the document updates fields.",
            severity="high", confidence=0.7, reliability="high", value=meta["dde"][0]["field"][:300], mitre=["T1559.002"],
        )
    if meta["embeddings"] or meta["activex"]:
        ctx.add_evidence(
            type="office_embedded_objects", category="document", source="ooxml_analyzer", artifact=art,
            title="Embedded OLE objects / ActiveX controls",
            description="Embedded objects are extracted and analysed as separate artifacts. Common in legitimate documents (charts, spreadsheets).",
            severity="low", confidence=0.45, reliability="high", value=", ".join((meta["embeddings"] + meta["activex"])[:5]),
        )


# ======================================================================================
# OLE / VBA
# ======================================================================================
def decompress_vba(data: bytes, limit: int = 4 * 1024 * 1024) -> bytes:
    """MS-OVBA 2.4.1 decompression."""
    if not data or data[0] != 1:
        raise ValueError("not a compressed VBA container")
    out = bytearray()
    pos = 1
    n = len(data)
    while pos + 2 <= n:
        header = int.from_bytes(data[pos:pos + 2], "little")
        chunk_start = pos
        pos += 2
        size = (header & 0x0FFF) + 3
        chunk_end = min(n, chunk_start + size)
        dstart = len(out)
        if not header & 0x8000:
            out += data[pos:pos + 4096]
            pos += 4096
        else:
            while pos < chunk_end:
                flags = data[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[pos])
                        pos += 1
                    else:
                        if pos + 2 > chunk_end:
                            pos = chunk_end
                            break
                        token = int.from_bytes(data[pos:pos + 2], "little")
                        pos += 2
                        diff = len(out) - dstart
                        bit_count = max((diff - 1).bit_length(), 4) if diff > 0 else 4
                        length_mask = 0xFFFF >> bit_count
                        length = (token & length_mask) + 3
                        offset = ((token & (~length_mask & 0xFFFF)) >> (16 - bit_count)) + 1
                        src = len(out) - offset
                        if src < 0:
                            raise ValueError("invalid copy token")
                        for i in range(length):
                            out.append(out[src + i])
        if len(out) > limit:
            break
    return bytes(out[:limit])


_ATTRIB_RE = re.compile(rb"\x00Attribut")
VBA_AUTOEXEC = ["autoopen", "auto_open", "document_open", "workbook_open", "autoexec", "autoclose", "auto_close",
                "document_close", "document_beforeclose", "workbook_beforeclose", "workbook_activate", "document_contentcontrolonenter",
                "frame1_layout", "inkpicture1_painted", "app_documentopen", "workbook_windowactivate"]
VBA_SUSPICIOUS = {
    "shell": "execution", "wscript.shell": "execution", "shell.application": "execution", ".run": "execution",
    "createobject": "execution", "getobject": "execution", "powershell": "execution", "cmd.exe": "execution",
    "urldownloadtofile": "network", "msxml2.xmlhttp": "network", "winhttp.winhttprequest": "network",
    "msxml2.serverxmlhttp": "network", "adodb.stream": "file_manipulation", "savetofile": "file_manipulation",
    "environ": "discovery", "callbyname": "packing", "strreverse": "packing", "chrw(": "packing", "chr(": "packing",
    "frombase64": "packing", "lib \"kernel32\"": "injection", "virtualalloc": "injection", "rtlmovememory": "injection",
    "createthread": "injection", "writeprocessmemory": "injection", "winmgmts": "execution", "win32_process": "execution",
    "schedule.service": "persistence", "regwrite": "persistence", "kill ": "file_manipulation", "xmlhttp": "network",
}


def _extract_vba_from_ole(ole) -> list[dict[str, Any]]:
    modules = []
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        lowp = path.lower()
        if "vba" not in lowp or entry[-1].lower() in ("dir", "_vba_project", "project", "projectwm", "projectlk") or entry[-1].startswith("__SRP_"):
            continue
        try:
            raw = ole.openstream(entry).read(16 * 1024 * 1024)
        except Exception:
            continue
        m = _ATTRIB_RE.search(raw)
        if not m:
            continue
        start = m.start() - 3
        if start < 0 or raw[start] != 1:
            continue
        try:
            code = decompress_vba(raw[start:]).decode("latin-1", "replace")
        except Exception:
            continue
        modules.append({"stream": path, "code": code})
        if len(modules) >= 64:
            break
    return modules


def analyze_ole(ctx: AnalysisContext, art: ArtifactContext) -> None:
    try:
        import olefile
    except Exception:  # pragma: no cover
        ctx.limitation("olefile not installed; OLE documents not analysed.")
        return
    meta: dict[str, Any] = {}
    try:
        ole = olefile.OleFileIO(str(art.path))
    except Exception as exc:
        art.errors.append(f"ole: {exc}")
        ctx.add_evidence(type="malformed_ole", category="structure", source="ole_analyzer", artifact=art,
                         title="Malformed OLE structure", description=f"olefile could not parse the container ({str(exc)[:120]}).",
                         severity="low", confidence=0.45, reliability="medium", value=str(exc)[:200])
        return
    with ole:
        streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)][:2000]
        meta["streams"] = streams
        try:
            md = ole.get_metadata()
            info = {}
            for attr in ("author", "last_saved_by", "title", "subject", "company", "creating_application", "create_time", "last_saved_time", "codepage"):
                v = getattr(md, attr, None)
                if v:
                    info[attr] = v.decode("latin-1", "replace") if isinstance(v, bytes) else (v.isoformat() if hasattr(v, "isoformat") else v)
            meta["metadata"] = info
            for k in ("create_time", "last_saved_time"):
                if isinstance(info.get(k), str):
                    ts = info[k] if "+" in info[k] else info[k] + "+00:00"
                    ctx.event(f"OLE {k.replace('_', ' ')}", engine="ole_analyzer", artifact_id=art.id, lane="artifact", ts=ts)
        except Exception:
            meta["metadata"] = {}
        modules = _extract_vba_from_ole(ole)
        lows = [s.lower() for s in streams]
        equation = False
        for s in streams:
            if s.lower().endswith("compobj") or s.lower().endswith("\x01compobj"):
                try:
                    raw = ole.openstream(s).read(4096)
                    if b"Equation.3" in raw or b"Microsoft Equation" in raw:
                        equation = True
                except Exception:
                    pass
        if any("equation native" in s for s in lows):
            equation = True
        ole_native = [s for s in streams if s.lower().endswith("\x01ole10native")]
        native_info = []
        for s in ole_native[:10]:
            try:
                raw = ole.openstream(s).read(1024 * 1024)
                parts = raw[6:6 + 1024].split(b"\x00")
                native_info.append({"stream": s, "label": parts[0].decode("latin-1", "replace")[:200] if parts else "",
                                    "path": parts[1].decode("latin-1", "replace")[:300] if len(parts) > 1 else ""})
            except Exception:
                pass
        meta["ole10native"] = native_info
    meta["vba_modules"] = [{"stream": m["stream"], "size": len(m["code"]), "code": m["code"][:200_000]} for m in modules]
    art.metadata["ole"] = meta
    if equation:
        ctx.add_evidence(
            type="ole_equation_editor", category="document", source="ole_analyzer", artifact=art,
            title="Equation Editor object", description="Equation Editor 3.0 objects are the vector of widely exploited vulnerabilities (e.g. CVE-2017-11882).",
            severity="high", confidence=0.7, reliability="high", value="Equation.3", mitre=["T1203"],
        )
    for n in native_info:
        ctx.add_evidence(
            type="ole_packager_object", category="document", source="ole_analyzer", artifact=art,
            title=f"Embedded Packager object: {n['label'] or n['path']}",
            description="OLE Packager (Ole10Native) objects embed arbitrary files (often scripts or executables) inside documents.",
            severity="medium", confidence=0.65, reliability="high", value=(n["path"] or n["label"])[:300], mitre=["T1204.002"], details=n,
        )
    if modules:
        _vba_evidence(ctx, art, modules)


def _vba_evidence(ctx: AnalysisContext, art: ArtifactContext, modules: list[dict[str, Any]]) -> None:
    art.tags.add("macros")
    code = "\n".join(m["code"] for m in modules)
    low = code.lower()
    autoexec = sorted({k for k in VBA_AUTOEXEC if re.search(r"\b" + re.escape(k) + r"\b", low)})
    hits: dict[str, list[str]] = {}
    for kw, cat in VBA_SUSPICIOUS.items():
        if kw in low:
            hits.setdefault(cat, []).append(kw)
    art.strings.extend(strings_from_text(code, origin="vba", encoding="vba"))
    art.invalidate_strings()
    ctx.add_evidence(
        type="vba_macro_code", category="document", source="ole_analyzer", artifact=art,
        title=f"VBA macro source recovered ({len(modules)} module(s))",
        description="Macro source code was decompressed statically (never executed) and added to the string set.",
        severity="low", confidence=0.9, reliability="high", value=", ".join(m["stream"] for m in modules[:5]),
        details={"modules": [m["stream"] for m in modules], "keywords": hits},
    )
    if autoexec:
        ctx.add_evidence(
            type="vba_autoexec", category="execution", source="ole_analyzer", artifact=art,
            title="Macro runs automatically", description=f"Auto-execution entry points: {', '.join(autoexec)}. Code runs when the document opens/closes once macros are enabled.",
            severity="medium", confidence=0.75, reliability="high", value=", ".join(autoexec), mitre=["T1204.002"],
        )
    if hits.get("execution"):
        ctx.add_evidence(
            type="vba_execution", category="execution", source="ole_analyzer", artifact=art,
            title="Macro can execute commands or create COM objects",
            description=f"Keywords: {', '.join(hits['execution'][:8])}.",
            severity="high" if autoexec else "medium", confidence=0.7, reliability="high",
            value=", ".join(hits["execution"][:8]), mitre=["T1059.005"],
        )
    if hits.get("network"):
        ctx.add_evidence(
            type="vba_download", category="network", source="ole_analyzer", artifact=art,
            title="Macro performs HTTP requests / downloads", description=f"Keywords: {', '.join(hits['network'][:6])}.",
            severity="high" if autoexec else "medium", confidence=0.7, reliability="high",
            value=", ".join(hits["network"][:6]), mitre=["T1105"],
        )
    if hits.get("injection"):
        ctx.add_evidence(
            type="vba_shellcode_runner", category="injection", source="ole_analyzer", artifact=art,
            title="Macro declares Windows memory APIs", description="VBA calling VirtualAlloc/RtlMoveMemory/CreateThread is the classic macro shellcode-runner pattern.",
            severity="high", confidence=0.8, reliability="high", value=", ".join(hits["injection"]), mitre=["T1055", "T1106"],
        )
    if len(hits.get("packing", [])) >= 2:
        ctx.add_evidence(
            type="vba_obfuscation", category="packing", source="ole_analyzer", artifact=art,
            title="Macro uses string obfuscation helpers", description=f"Keywords: {', '.join(hits['packing'])}.",
            severity="medium", confidence=0.55, reliability="medium", value=", ".join(hits["packing"]), mitre=["T1027"],
        )


# ======================================================================================
# RTF
# ======================================================================================
def analyze_rtf(ctx: AnalysisContext, art: ArtifactContext) -> None:
    with open(art.path, "rb") as fh:
        data = fh.read(min(art.size, ctx.limits.max_deep_scan_size))
    low = data.lower()
    meta: dict[str, Any] = {
        "objects": low.count(b"\\object"), "objdata": low.count(b"\\objdata"), "objupdate": low.count(b"\\objupdate"),
        "objautlink": low.count(b"\\objautlink"), "template": low.count(b"\\*\\template"),
        "max_group_depth": 0,
    }
    depth = maxd = 0
    for b in data[:16 * 1024 * 1024]:
        if b == 0x7B:
            depth += 1
            maxd = max(maxd, depth)
        elif b == 0x7D:
            depth = max(0, depth - 1)
    meta["max_group_depth"] = maxd
    classes = sorted({m.decode("latin-1", "replace") for m in re.findall(rb"\\objclass\s+([^}\\]{1,64})", data)})
    for m in re.finditer(rb"\\objdata\s*([0-9a-fA-F\s]{32,4096})", data):
        hexdata = re.sub(rb"\s", b"", m.group(1))
        try:
            raw = bytes.fromhex(hexdata[: len(hexdata) // 2 * 2].decode())
        except ValueError:
            continue
        if len(raw) > 12 and raw[4:8] == b"\x02\x00\x00\x00":
            ln = struct.unpack_from("<I", raw, 8)[0]
            if 0 < ln < 64:
                classes.append(raw[12:12 + ln].split(b"\x00")[0].decode("latin-1", "replace"))
    meta["object_classes"] = sorted(set(classes))
    templates = [t.decode("latin-1", "replace") for t in re.findall(rb"\\\*\\template\s+([^}]{1,1024})", data)]
    meta["templates"] = templates
    art.metadata["rtf"] = meta
    art.strings.extend(ExtractedString(0, "rtf", t, origin="decoded") for t in templates)
    art.invalidate_strings()
    risky = [c for c in meta["object_classes"] if c.lower().startswith(("equation", "package", "ole2link", "htmlfile", "word.document"))]
    if meta["objdata"]:
        ctx.add_evidence(
            type="rtf_embedded_object", category="document", source="rtf_analyzer", artifact=art,
            title=f"RTF embeds {meta['objdata']} OLE object(s)" + (f" ({', '.join(risky)})" if risky else ""),
            description="Embedded OLE objects in RTF are the delivery mechanism for many document exploits; they also carry legitimate objects.",
            severity="high" if risky else "medium", confidence=0.7 if risky else 0.5, reliability="high",
            value=", ".join(meta["object_classes"][:5]) or str(meta["objdata"]), mitre=["T1203"] if risky else [],
        )
    if meta["objupdate"] or meta["objautlink"]:
        ctx.add_evidence(
            type="rtf_auto_update", category="document", source="rtf_analyzer", artifact=art,
            title="RTF object auto-update (\\objupdate / \\objautlink)",
            description="Forces embedded/linked objects to load without interaction — used by exploit documents.",
            severity="high", confidence=0.7, reliability="high", value=f"objupdate={meta['objupdate']}", mitre=["T1203"],
        )
    if templates:
        ctx.add_evidence(
            type="rtf_template_injection", category="document", source="rtf_analyzer", artifact=art,
            title="RTF references a remote template", description="\\*\\template loads a template from an external location.",
            severity="high", confidence=0.7, reliability="high", value=templates[0][:300], mitre=["T1221"],
        )
    if maxd > 200:
        ctx.add_evidence(
            type="rtf_deep_nesting", category="anti_analysis", source="rtf_analyzer", artifact=art,
            title=f"Abnormally deep RTF group nesting ({maxd})", description="Extreme nesting is used to break RTF parsers and scanners.",
            severity="medium", confidence=0.6, reliability="medium", value=str(maxd),
        )


# ======================================================================================
# LNK
# ======================================================================================
LNK_LOLBINS = ("cmd.exe", "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil",
               "bitsadmin", "msiexec", "conhost", "forfiles", "curl.exe", "wmic", "schtasks", "explorer.exe")


def _filetime(v: int) -> str | None:
    if not v:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)).isoformat()
    except (OverflowError, ValueError):
        return None


def analyze_lnk(ctx: AnalysisContext, art: ArtifactContext) -> None:
    with open(art.path, "rb") as fh:
        data = fh.read(min(art.size, 4 * 1024 * 1024))
    if len(data) < 76:
        return
    flags, attrs, ctime, atime, wtime, fsize, icon_index, show = struct.unpack_from("<IIQQQIiI", data, 20)
    pos = 76
    meta: dict[str, Any] = {"flags": f"0x{flags:x}", "show_command": show, "file_size": fsize, "icon_index": icon_index,
                            "times": {"created": _filetime(ctime), "accessed": _filetime(atime), "modified": _filetime(wtime)}}
    try:
        if flags & 0x1:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        if flags & 0x2:  # HasLinkInfo
            li_size = struct.unpack_from("<I", data, pos)[0]
            li = data[pos:pos + li_size]
            if len(li) >= 28:
                lbp_off = struct.unpack_from("<I", li, 16)[0]
                if 0 < lbp_off < len(li):
                    meta["local_base_path"] = li[lbp_off:].split(b"\x00", 1)[0].decode("latin-1", "replace")
            pos += li_size
        unicode = bool(flags & 0x80)
        names = [("name", 0x4), ("relative_path", 0x8), ("working_dir", 0x10), ("arguments", 0x20), ("icon_location", 0x40)]
        for key, bit in names:
            if flags & bit:
                count = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if unicode:
                    meta[key] = data[pos:pos + count * 2].decode("utf-16-le", "replace")
                    pos += count * 2
                else:
                    meta[key] = data[pos:pos + count].decode("latin-1", "replace")
                    pos += count
        while pos + 8 <= len(data):
            bsize, sig = struct.unpack_from("<II", data, pos)
            if bsize < 8:
                break
            block = data[pos:pos + bsize]
            if sig == 0xA0000001 and len(block) >= 788:  # EnvironmentVariableDataBlock
                meta["env_target"] = block[8:268].split(b"\x00", 1)[0].decode("latin-1", "replace")
            elif sig == 0xA0000003 and len(block) >= 96:  # TrackerDataBlock
                meta["tracker_machine_id"] = block[16:32].split(b"\x00", 1)[0].decode("latin-1", "replace")
            pos += bsize
    except struct.error:
        art.errors.append("lnk: truncated structure")
    for k, v in meta["times"].items():
        if v:
            ctx.event(f"LNK target {k}", engine="lnk_analyzer", artifact_id=art.id, lane="artifact", ts=v)
    art.metadata["lnk"] = meta
    target = " ".join(str(meta.get(k, "")) for k in ("local_base_path", "relative_path", "env_target")).lower()
    args = meta.get("arguments", "") or ""
    art.strings.extend(ExtractedString(0, "lnk", s, origin="decoded") for s in
                       [meta.get("local_base_path", ""), meta.get("relative_path", ""), meta.get("env_target", ""),
                        args, meta.get("icon_location", "")] if s and len(s) >= 4)
    art.invalidate_strings()
    lol = next((b for b in LNK_LOLBINS if b in target), None)
    if lol:
        ctx.add_evidence(
            type="lnk_lolbin_target", category="execution", source="lnk_analyzer", artifact=art,
            title=f"Shortcut launches {lol}" + (" with arguments" if args else ""),
            description="Shortcuts that start interpreters/LOLBins with arguments are a common initial-access technique.",
            severity="high" if args else "medium", confidence=0.75, reliability="high",
            value=(target.strip() + " " + args)[:500], mitre=["T1204.002"],
        )
    if len(args) > 260 or re.search(r"\s{40,}", args):
        ctx.add_evidence(
            type="lnk_padded_arguments", category="defense_evasion", source="lnk_analyzer", artifact=art,
            title="Very long or whitespace-padded shortcut arguments",
            description="Padding pushes the real command out of view in the Properties dialog.",
            severity="medium", confidence=0.65, reliability="high", value=args[:300], mitre=["T1027"],
        )
    if show == 7:
        ctx.add_evidence(
            type="lnk_minimized", category="defense_evasion", source="lnk_analyzer", artifact=art,
            title="Shortcut starts minimized (SW_SHOWMINNOACTIVE)", description="Hides the launched window from the user.",
            severity="low", confidence=0.5, reliability="high", value="show_command=7",
        )
    icon = (meta.get("icon_location") or "").lower()
    if lol and any(x in icon for x in (".pdf", ".doc", ".jpg", "shell32.dll", "imageres.dll", "acrobat", "winword")):
        ctx.add_evidence(
            type="lnk_icon_masquerade", category="defense_evasion", source="lnk_analyzer", artifact=art,
            title="Shortcut icon disguises the target", description="The icon suggests a document while the target is an interpreter.",
            severity="medium", confidence=0.6, reliability="medium", value=icon[:200], mitre=["T1036"],
        )
