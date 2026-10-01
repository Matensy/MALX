"""Security primitives: name sanitisation, path containment, archive member validation.

Golden rule: names that come from uploads or archives are *data*, never paths.
Everything stored on disk uses an internal UUID-based name.
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

_UUID_RE = re.compile(r"^[0-9a-f]{32}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:")
_BIDI_CONTROL = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}

# Files in quarantine: owner read only, never executable.
QUARANTINE_FILE_MODE = stat.S_IRUSR
QUARANTINE_DIR_MODE = stat.S_IRWXU


def new_id() -> str:
    return uuid.uuid4().hex


def is_valid_id(value: str) -> bool:
    return bool(_UUID_RE.fullmatch(value or ""))


def internal_name() -> str:
    return f"{uuid.uuid4().hex}.bin"


@dataclass
class SanitizedName:
    display: str
    issues: list[str] = field(default_factory=list)
    had_rtlo: bool = False


def sanitize_display_name(raw: object, max_length: int = 255) -> SanitizedName:
    """Turn an untrusted filename into something safe to *display* (never to open).

    Records what was wrong with it so the observation can become evidence
    (e.g. right-to-left override tricks such as ``invoice‮exe.pdf``).
    """
    issues: list[str] = []
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
        if "�" in text:
            issues.append("malformed_unicode")
    else:
        text = str(raw if raw is not None else "")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", errors="replace").decode("utf-8")
        issues.append("malformed_unicode")
    if "\x00" in text:
        issues.append("null_byte")
    had_rtlo = any(ch in _BIDI_CONTROL for ch in text)
    if had_rtlo:
        issues.append("bidi_override")
        text = "".join(ch for ch in text if ch not in _BIDI_CONTROL)
    text = unicodedata.normalize("NFC", text)
    if _CONTROL_RE.search(text):
        if "control_characters" not in issues:
            issues.append("control_characters")
        text = _CONTROL_RE.sub("", text)
    # Keep only the last component for display; remember that a path was supplied.
    if "/" in text or "\\" in text:
        issues.append("path_in_name")
        text = re.split(r"[\\/]", text)[-1]
    text = text.strip().strip(".") or "unnamed"
    if len(text) > max_length:
        issues.append("name_too_long")
        stem, ext = os.path.splitext(text)
        ext = ext[:16]
        text = stem[: max(1, max_length - len(ext) - 1)] + "…" + ext
    return SanitizedName(display=text, issues=issues, had_rtlo=had_rtlo)


def ensure_within(base: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` and guarantee it stays under ``base``."""
    base_resolved = base.resolve()
    resolved = candidate.resolve()
    if resolved != base_resolved and base_resolved not in resolved.parents:
        raise PermissionError("path escapes storage root")
    return resolved


@dataclass
class MemberPathCheck:
    normalized: str
    issues: list[str]

    @property
    def traversal(self) -> bool:
        return any(i in self.issues for i in ("parent_reference", "absolute_path", "drive_letter"))


def check_member_path(name: str, max_length: int = 1024, max_depth: int = 64) -> MemberPathCheck:
    """Validate an archive member name. The result is *only* used for display and
    evidence: extraction always writes to a fresh internal name."""
    issues: list[str] = []
    if "\x00" in name:
        issues.append("null_byte")
        name = name.replace("\x00", "")
    if len(name) > max_length:
        issues.append("name_too_long")
    unified = name.replace("\\", "/")
    if "\\" in name:
        issues.append("backslash_separator")
    if unified.startswith("/"):
        issues.append("absolute_path")
    if _WINDOWS_DRIVE_RE.match(unified):
        issues.append("drive_letter")
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        issues.append("parent_reference")
    if len(parts) > max_depth:
        issues.append("too_deep")
    if any(ch in _BIDI_CONTROL for ch in name):
        issues.append("bidi_override")
    normalized = posixpath.normpath("/".join(p for p in parts if p != "..")) if parts else ""
    if normalized == ".":
        normalized = ""
    return MemberPathCheck(normalized=normalized[:max_length], issues=issues)


def mask_secret(value: str, keep: int = 4) -> str:
    """Mask a secret for display: ``AKIA************``."""
    value = value or ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(12, max(4, len(value) - keep))


def harden_file(path: Path) -> None:
    try:
        os.chmod(path, QUARANTINE_FILE_MODE)
    except OSError:
        pass


def harden_dir(path: Path) -> None:
    try:
        os.chmod(path, QUARANTINE_DIR_MODE)
    except OSError:
        pass
