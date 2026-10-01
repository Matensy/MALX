"""Script analyzer: static deobfuscation of PowerShell / JS / VBS / batch / shell / HTML.

Decoding is purely textual (base64, hex, char-code arrays, string concatenation,
PowerShell backticks). Decoded text is added to the string set so the IOC and
heuristic engines can see through common obfuscation; decoded binaries become child
artifacts. Script code is never evaluated.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from .base import AnalysisContext, ArtifactContext
from .entropy import shannon
from .strings_engine import strings_from_text

MAX_SCRIPT = 16 * 1024 * 1024
MAX_DECODES = 40
MAX_DECODED_CHILDREN = 8

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){32,}(?![0-9a-fA-F])")
_PS_ENC_RE = re.compile(r"(?i)-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+['\"]?([A-Za-z0-9+/]{16,}={0,2})")
_CHARCODE_RE = re.compile(r"(?i)(?:fromcharcode\s*\(([\d\s,]{8,})\))|((?:\[char\]\s*\d{2,3}\s*\+?\s*){4,})|((?:chrw?\s*\(\s*\d{2,3}\s*\)\s*&?\s*){4,})")
_CONCAT_RE = re.compile(r"[\"']\s*(?:\+|&|\.\.)\s*[\"']")
_BACKTICK_RE = re.compile(r"`(?=[a-zA-Z])")
_SMUGGLING_RE = re.compile(r"(?i)(mssaveoropenblob|createobjecturl\s*\(\s*new\s+blob|\.download\s*=|download=\s*[\"'][^\"']+\.(exe|zip|iso|img|js|hta|lnk|msi|dll)[\"'])")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text)


def _decode_b64(blob: str) -> bytes | None:
    try:
        pad = blob + "=" * (-len(blob) % 4)
        return base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return None


def _as_text(raw: bytes) -> str | None:
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        try:
            t = raw.decode("utf-16-le")
            if _printable_ratio(t) > 0.85:
                return t
        except UnicodeDecodeError:
            pass
    try:
        t = raw.decode("utf-8")
        if _printable_ratio(t) > 0.85:
            return t
    except UnicodeDecodeError:
        pass
    return None


def analyze_script(ctx: AnalysisContext, art: ArtifactContext) -> None:
    from .archive import add_decoded_child

    with open(art.path, "rb") as fh:
        raw = fh.read(min(art.size, MAX_SCRIPT))
    enc = (art.ident.details.get("encoding") if art.ident else None) or "utf-8"
    if enc in ("utf-16", "utf-16le") or raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    lang = art.ident.details.get("language") if art.ident else None
    meta: dict[str, Any] = {
        "language": lang or art.detected_type, "lines": len(lines), "max_line_length": max((len(l) for l in lines), default=0),
        "entropy": shannon(raw[:1024 * 1024]), "decoded": [],
    }
    decoded_texts: list[tuple[str, str]] = []
    children = 0

    def handle_bytes(data: bytes, how: str, where: int) -> None:
        nonlocal children
        if len(meta["decoded"]) >= MAX_DECODES:
            return
        as_text = _as_text(data)
        if as_text and len(as_text.strip()) >= 8:
            decoded_texts.append((how, as_text))
            meta["decoded"].append({"method": how, "offset": where, "kind": "text", "preview": as_text[:300]})
        elif data[:2] == b"MZ" or data[:4] in (b"\x7fELF", b"PK\x03\x04") or data[:5] == b"%PDF-":
            meta["decoded"].append({"method": how, "offset": where, "kind": "binary", "size": len(data), "magic": data[:4].hex()})
            ctx.add_evidence(
                type="encoded_embedded_payload", category="packing", source="script_analyzer", artifact=art,
                title=f"{how} blob decodes to a binary file ({data[:2].hex()}…)",
                description="An executable/archive is embedded as encoded text inside the script — a dropper pattern.",
                severity="high" if data[:2] == b"MZ" or data[:4] == b"\x7fELF" else "medium", confidence=0.8, reliability="high",
                value=f"{how}@{where} size={len(data)}", offset=where, mitre=["T1027", "T1140"],
            )
            if children < MAX_DECODED_CHILDREN:
                child = add_decoded_child(ctx, art, data, f"decoded_{how}_{where}.bin")
                if child is not None:
                    children += 1
                    ctx.event("Decoded embedded payload materialised as artifact", engine="script_analyzer", artifact_id=child.id)

    for m in _PS_ENC_RE.finditer(text):
        data = _decode_b64(m.group(1))
        if data:
            t = _as_text(data)
            if t:
                decoded_texts.append(("powershell-encodedcommand", t))
                meta["decoded"].append({"method": "powershell -EncodedCommand", "offset": m.start(), "kind": "text", "preview": t[:300]})
                ctx.add_evidence(
                    type="powershell_encoded_command_decoded", category="execution", source="script_analyzer", artifact=art,
                    title="PowerShell -EncodedCommand decoded",
                    description="The encoded command was decoded statically and its content added to the analysis.",
                    severity="medium", confidence=0.8, reliability="high", value=t[:300], mitre=["T1059.001", "T1027"],
                )
    for m in list(_B64_RE.finditer(text))[:200]:
        data = _decode_b64(m.group())
        if data and len(data) >= 24:
            handle_bytes(data, "base64", m.start())
    for m in list(_HEX_RE.finditer(text))[:100]:
        try:
            handle_bytes(bytes.fromhex(m.group()), "hex", m.start())
        except ValueError:
            pass
    charcode_hits = 0
    for m in _CHARCODE_RE.finditer(text):
        nums = [int(n) for n in re.findall(r"\d{2,3}", m.group())]
        if len(nums) >= 4:
            try:
                s = "".join(chr(n) for n in nums if 0 < n < 0x110000)
            except ValueError:
                continue
            charcode_hits += 1
            decoded_texts.append(("charcode", s))
            meta["decoded"].append({"method": "char codes", "offset": m.start(), "kind": "text", "preview": s[:300]})
    concat_count = len(_CONCAT_RE.findall(text))
    if concat_count >= 5:
        joined = _CONCAT_RE.sub("", text)
        decoded_texts.append(("concat", joined))
    if lang == "powershell" or "`" in text:
        bt = len(_BACKTICK_RE.findall(text))
        if bt >= 5:
            decoded_texts.append(("backtick", _BACKTICK_RE.sub("", text)))
            meta["backticks"] = bt
    for how, t in decoded_texts:
        art.strings.extend(strings_from_text(t[:2 * 1024 * 1024], origin=f"decoded:{how}"))
    art.invalidate_strings()

    obf_score = 0
    reasons = []
    if meta["max_line_length"] > 2000:
        obf_score += 1
        reasons.append(f"line of {meta['max_line_length']} characters")
    if charcode_hits >= 2:
        obf_score += 1
        reasons.append(f"{charcode_hits} char-code sequences")
    if concat_count >= 20:
        obf_score += 1
        reasons.append(f"{concat_count} string concatenations")
    if meta.get("backticks", 0) >= 10:
        obf_score += 1
        reasons.append(f"{meta['backticks']} PowerShell backtick escapes")
    if meta["entropy"] > 5.6 and art.size > 2048:
        obf_score += 1
        reasons.append(f"text entropy {meta['entropy']:.2f}")
    meta["obfuscation_score"] = obf_score
    meta["obfuscation_reasons"] = reasons
    if obf_score >= 2:
        ctx.add_evidence(
            type="script_obfuscation", category="packing", source="script_analyzer", artifact=art,
            title="Script shows multiple obfuscation traits",
            description="; ".join(reasons) + ". Minified or generated code can look similar; obfuscation hides intent from reviewers and scanners.",
            severity="medium" if obf_score >= 3 else "low", confidence=0.5 + 0.1 * min(obf_score, 4), reliability="medium",
            value=", ".join(reasons), mitre=["T1027"],
        )
    if art.detected_type in ("html", "svg", "hta") or lang == "javascript":
        smug = _SMUGGLING_RE.findall(text)
        if smug and (meta["decoded"] or "base64" in text.lower()):
            ctx.add_evidence(
                type="html_smuggling", category="defense_evasion", source="script_analyzer", artifact=art,
                title="HTML smuggling pattern",
                description="The page builds a file from embedded data in the browser and triggers a download, bypassing network inspection.",
                severity="high", confidence=0.7, reliability="medium", value=str(smug[0])[:200], mitre=["T1027.006"],
            )
        if art.detected_type == "svg" and re.search(r"(?i)<script|onload\s*=|javascript:", text):
            ctx.add_evidence(
                type="svg_script", category="document", source="script_analyzer", artifact=art,
                title="SVG image contains script", description="Scripted SVGs are used for phishing redirects and smuggling.",
                severity="medium", confidence=0.6, reliability="high", value="<script> in SVG", mitre=["T1059.007"],
            )
    if art.detected_type == "hta":
        ctx.add_evidence(
            type="hta_application", category="execution", source="script_analyzer", artifact=art,
            title="HTML Application (HTA)", description="HTAs run with full user privileges through mshta.exe; rarely distributed legitimately.",
            severity="medium", confidence=0.6, reliability="high", value="HTA", mitre=["T1218.005"],
        )
    art.metadata["script"] = meta
