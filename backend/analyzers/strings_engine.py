"""String engine: ASCII / UTF-8 / UTF-16LE extraction and classification.

Classification levels: NORMAL → INTERESTING → SUSPICIOUS → HIGH_RISK, driven by
the declarative signatures in ``rules/signatures/strings.yaml``.
"""

from __future__ import annotations

import mmap
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from backend.core.enums import StringClass
from backend.rules.loader import RulePack

from .base import ExtractedString

MIN_LEN = 5
MAX_STRING_CHARS = 4096
MAX_SCAN_STRINGS = 250_000

_ASCII_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_LEN)
_UTF8_RE = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){%d,}" % MIN_LEN)
_HAS_MULTIBYTE = re.compile(rb"[\xc2-\xf4]")

_JUNK_RE = re.compile(r"^(.)\1{5,}$|^[^a-zA-Z0-9]{5,}$")


def extract_strings(path: Path, size: int, max_scan: int) -> tuple[list[ExtractedString], bool]:
    """Return extracted strings and whether the scan was truncated."""
    truncated = size > max_scan
    out: list[ExtractedString] = []
    if size == 0:
        return out, False
    end = min(size, max_scan)
    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for m in _ASCII_RE.finditer(mm, 0, end):
                out.append(ExtractedString(m.start(), "ascii", m.group()[:MAX_STRING_CHARS].decode("ascii")))
                if len(out) >= MAX_SCAN_STRINGS:
                    return out, True
            for m in _UTF16_RE.finditer(mm, 0, end):
                out.append(ExtractedString(m.start(), "utf-16le", m.group()[: MAX_STRING_CHARS * 2].decode("utf-16-le", "replace")))
                if len(out) >= MAX_SCAN_STRINGS:
                    return out, True
            for m in _UTF8_RE.finditer(mm, 0, end):
                raw = m.group()
                if _HAS_MULTIBYTE.search(raw):
                    out.append(ExtractedString(m.start(), "utf-8", raw.decode("utf-8", "replace")[:MAX_STRING_CHARS]))
                    if len(out) >= MAX_SCAN_STRINGS:
                        return out, True
    return out, truncated


def strings_from_text(text: str, origin: str = "decoded", encoding: str = "decoded") -> list[ExtractedString]:
    out = []
    offset = 0
    for line in text.splitlines():
        line_s = line.strip()
        if len(line_s) >= MIN_LEN:
            out.append(ExtractedString(offset, encoding, line_s[:MAX_STRING_CHARS], origin=origin))
        offset += len(line) + 1
    return out


class StringClassifier:
    def __init__(self, pack: RulePack):
        self.patterns = pack.string_patterns
        self.api_names = {k for k in pack.apis}
        # One combined pass rejects the vast majority of strings before the
        # individual signatures are evaluated.
        self._master = re.compile(
            "|".join(f"(?:{p.regex.pattern})" for p in self.patterns), re.I
        ) if self.patterns else None

    def classify(self, strings: Iterable[ExtractedString], imports: set[str] | None = None) -> Counter:
        stats: Counter = Counter()
        imports = imports or set()
        for s in strings:
            value = s.value
            if _JUNK_RE.match(value):
                stats[StringClass.NORMAL.value] += 1
                continue
            best = StringClass.NORMAL
            tags: list[str] = []
            if self._master is not None and self._master.search(value):
                for pat in self.patterns:
                    if pat.regex.search(value):
                        tags.append(pat.tag)
                        klass = StringClass(pat.klass)
                        if klass.rank > best.rank:
                            best = klass
            low = value.lower() if len(value) <= 64 else ""
            if low and low in self.api_names:
                if low not in imports:
                    tags.append("api_name_unimported")
                    if best.rank < StringClass.INTERESTING.rank:
                        best = StringClass.INTERESTING
                else:
                    tags.append("api_name")
            elif low and low.endswith((".dll", ".sys", ".drv")) and " " not in value:
                tags.append("dll_name")
            s.tags = tags
            s.classification = best
            stats[best.value] += 1
        return stats


def select_for_storage(strings: list[ExtractedString], limit: int) -> list[ExtractedString]:
    """Keep every non-NORMAL string (up to the limit) and fill with the first NORMAL ones."""
    flagged = [s for s in strings if s.classification != StringClass.NORMAL]
    flagged.sort(key=lambda s: (-s.classification.rank, s.offset))
    if len(flagged) >= limit:
        return flagged[:limit]
    normal = [s for s in strings if s.classification == StringClass.NORMAL and len(s.value) >= 6]
    return flagged + normal[: limit - len(flagged)]
