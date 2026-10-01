"""Archive analyzer with defensive extraction.

Defences (each violation becomes evidence on the archive artifact):

* member names are data — every member is written to a fresh ``<uuid>.bin`` in
  ``storage/extracted/<analysis_id>/``; the original name is never a filesystem path;
* path traversal, absolute paths, drive letters, NUL bytes and over-deep names are flagged;
* symlinks, hardlinks, devices and FIFOs are never materialised;
* entry counts are read from the EOCD before the central directory is parsed;
* declared sizes are not trusted: the bytes actually produced are counted while
  streaming, per member and per analysis, with a compression-ratio guard;
* recursion depth and total artifact count are bounded by configuration.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from backend.core.security import check_member_path, harden_file, internal_name, sanitize_display_name

from .base import AnalysisContext, ArtifactContext
from .identify import zip_entry_count

try:  # optional: AES-encrypted ZIP support
    import pyzipper  # type: ignore
except Exception:  # pragma: no cover
    pyzipper = None

try:  # optional: 7z support
    import py7zr  # type: ignore
    import py7zr.io  # type: ignore
except Exception:  # pragma: no cover
    py7zr = None

COMMON_SAMPLE_PASSWORDS = ("infected", "malware", "virus")
CHUNK = 1024 * 1024
RATIO_MIN_BYTES = 2 * 1024 * 1024  # ratio guard kicks in after 2 MB of output

ARCHIVE_TYPES = {"zip", "jar", "apk", "ooxml", "odf", "tar", "gzip", "bzip2", "xz", "7z"}


class ExtractionLimit(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass
class MemberRecord:
    name: str
    normalized: str
    size: int | None
    compressed: int | None
    kind: str = "file"  # file | dir | symlink | hardlink | device | fifo | other
    encrypted: bool = False
    issues: list[str] = field(default_factory=list)
    link_target: str | None = None
    mtime: str | None = None
    extracted: bool = False
    skipped_reason: str | None = None
    child_id: str | None = None
    ratio: float | None = None


class _Budget:
    def __init__(self, ctx: AnalysisContext):
        self.ctx = ctx

    def check_artifacts(self) -> None:
        if len(self.ctx.artifacts) >= self.ctx.limits.max_total_artifacts:
            raise ExtractionLimit("too_many_artifacts", "max_total_artifacts reached")

    def add_bytes(self, n: int) -> None:
        self.ctx.extracted_bytes += n
        if self.ctx.extracted_bytes > self.ctx.limits.max_extracted_size:
            raise ExtractionLimit("extracted_size", "max_extracted_size reached for this analysis")


def _out_path(ctx: AnalysisContext) -> tuple[Path, str]:
    out_dir = ctx.storage_root / "extracted" / ctx.analysis_id
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, stat.S_IRWXU)
    name = internal_name()
    return out_dir / name, f"extracted/{ctx.analysis_id}/{name}"


def _stream_to_quarantine(ctx: AnalysisContext, src: BinaryIO, budget: _Budget, compressed_size: int | None) -> tuple[Path, str, int]:
    """Copy a decompressing stream into a new extracted file, enforcing all limits."""
    path, rel = _out_path(ctx)
    limits = ctx.limits
    written = 0
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                ctx.check()
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > limits.max_entry_size:
                    raise ExtractionLimit("entry_size", f"member exceeds max_entry_size ({limits.max_entry_size} bytes)")
                if compressed_size and written > RATIO_MIN_BYTES and written / max(1, compressed_size) > limits.max_compression_ratio:
                    raise ExtractionLimit("compression_ratio",
                                          f"compression ratio above {limits.max_compression_ratio}:1 (possible decompression bomb)")
                budget.add_bytes(len(chunk))
                out.write(chunk)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    harden_file(path)
    return path, rel, written


def _child(ctx: AnalysisContext, parent: ArtifactContext, member: MemberRecord, path: Path, rel: str, size: int) -> ArtifactContext:
    base = member.normalized.rsplit("/", 1)[-1] if member.normalized else (member.name or "member")
    san = sanitize_display_name(base, ctx.limits.max_filename_length)
    child = ArtifactContext(
        id=os.urandom(16).hex(), path=path, storage_rel=rel, display_name=san.display, size=size,
        parent_id=parent.id, depth=parent.depth + 1, path_in_archive=member.normalized or member.name,
        name_issues=list(dict.fromkeys(san.issues + member.issues)),
    )
    return ctx.add_artifact(child)


def analyze_archive(ctx: AnalysisContext, art: ArtifactContext) -> list[ArtifactContext]:
    det = art.detected_type
    if det not in ARCHIVE_TYPES:
        return []
    meta = art.metadata.setdefault("archive", {"format": det, "members": [], "stats": {}})
    if art.size > ctx.limits.max_archive_size:
        ctx.limitation(f"{art.display_name}: archive larger than max_archive_size; contents not extracted.")
        meta["stats"]["skipped"] = "max_archive_size"
        return []
    if art.depth >= ctx.limits.max_archive_depth:
        meta["stats"]["skipped"] = "max_archive_depth"
        ctx.add_evidence(
            type="archive_depth_limit", category="archive", source="archive_analyzer", artifact=art,
            title="Archive nesting exceeds configured depth",
            description=f"Nested archive at depth {art.depth} was not extracted (max_archive_depth={ctx.limits.max_archive_depth}). "
                        "Deeply nested archives are a known technique to exhaust scanners.",
            severity="low", confidence=0.7, reliability="high", value=str(art.depth),
        )
        return []
    budget = _Budget(ctx)
    children: list[ArtifactContext] = []
    try:
        if det in ("zip", "jar", "apk", "ooxml", "odf"):
            children = _zip(ctx, art, meta, budget)
        elif det == "tar":
            children = _tar(ctx, art, meta, budget)
        elif det in ("gzip", "bzip2", "xz"):
            children = _single_stream(ctx, art, meta, budget)
        elif det == "7z":
            children = _sevenzip(ctx, art, meta, budget)
    except ExtractionLimit as exc:
        _limit_evidence(ctx, art, exc)
        meta["stats"]["aborted"] = exc.kind
    _member_evidence(ctx, art, meta)
    return children


def _limit_evidence(ctx: AnalysisContext, art: ArtifactContext, exc: ExtractionLimit) -> None:
    bomb = exc.kind in ("compression_ratio", "entry_size", "extracted_size")
    ctx.add_evidence(
        type="decompression_bomb" if bomb else "archive_limit",
        category="archive", source="archive_analyzer", artifact=art,
        title="Possible decompression bomb" if bomb else "Archive extraction limit reached",
        description=f"Extraction stopped: {exc}. The archive expands far beyond what normal content does, "
                    "which is characteristic of decompression bombs designed to exhaust analysis systems."
        if bomb else f"Extraction stopped: {exc}.",
        severity="high" if exc.kind == "compression_ratio" else "medium", confidence=0.85 if bomb else 0.6,
        reliability="high", value=exc.kind, details={"limit": exc.kind},
    )
    ctx.limitation(f"{art.display_name}: extraction incomplete ({exc}).")


def _member_evidence(ctx: AnalysisContext, art: ArtifactContext, meta: dict) -> None:
    members: list[dict] = meta.get("members", [])
    traversal = [m for m in members if {"parent_reference", "absolute_path", "drive_letter"} & set(m["issues"])]
    if traversal:
        ctx.add_evidence(
            type="archive_path_traversal", category="archive", source="archive_analyzer", artifact=art,
            title="Archive contains path traversal entries",
            description="One or more member names try to escape the extraction directory (ZipSlip-style). "
                        "MALX never uses member names as paths, but legitimate archives do not contain such names.",
            severity="high", confidence=0.9, reliability="high",
            value=traversal[0]["name"][:300], details={"members": [m["name"][:300] for m in traversal[:20]], "count": len(traversal)},
        )
    links = [m for m in members if m["kind"] in ("symlink", "hardlink")]
    if links:
        ctx.add_evidence(
            type="archive_link_entries", category="archive", source="archive_analyzer", artifact=art,
            title="Archive contains symbolic/hard links",
            description="Links were recorded but not materialised. Links inside archives can redirect extraction to arbitrary locations.",
            severity="medium", confidence=0.75, reliability="high", value=f"{links[0]['name'][:200]} -> {links[0].get('link_target') or '?'}",
            details={"links": [{"name": m["name"][:200], "target": (m.get("link_target") or "")[:300]} for m in links[:20]]},
        )
    special = [m for m in members if m["kind"] in ("device", "fifo")]
    if special:
        ctx.add_evidence(
            type="archive_special_files", category="archive", source="archive_analyzer", artifact=art,
            title="Archive contains device/FIFO entries", description="Special file entries were ignored.",
            severity="medium", confidence=0.7, reliability="high", value=special[0]["name"][:200],
        )
    encrypted = [m for m in members if m["encrypted"]]
    if encrypted:
        not_extracted = [m for m in encrypted if not m["extracted"]]
        ctx.add_evidence(
            type="archive_encrypted", category="defense_evasion", source="archive_analyzer", artifact=art,
            title="Password-protected archive content",
            description="Encrypted members hide their content from gateways and scanners. "
                        + (f"{len(not_extracted)} member(s) could not be decrypted with the supplied password." if not_extracted
                           else "Members were decrypted for analysis with the supplied password (never stored)."),
            severity="low", confidence=0.6, reliability="high", value=str(len(encrypted)),
        )
        if not_extracted:
            ctx.limitation(f"{art.display_name}: {len(not_extracted)} encrypted member(s) not inspected (no/invalid password).")
    names = [m["normalized"].lower() for m in members if m["kind"] == "file"]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        ctx.add_evidence(
            type="archive_duplicate_names", category="archive", source="archive_analyzer", artifact=art,
            title="Duplicate member names", description="Several members share a name; extractors disagree on which one wins, a trick used to smuggle content.",
            severity="low", confidence=0.6, reliability="high", value=dupes[0][:200], details={"names": dupes[:20]},
        )
    weird = [m for m in members if {"null_byte", "bidi_override", "name_too_long", "too_deep"} & set(m["issues"])]
    if weird:
        ctx.add_evidence(
            type="archive_malformed_names", category="archive", source="archive_analyzer", artifact=art,
            title="Malformed member names", description="Member names contain NUL bytes, bidirectional overrides or excessive length/depth.",
            severity="medium", confidence=0.7, reliability="high", value=weird[0]["name"][:200],
            details={"issues": sorted({i for m in weird for i in m["issues"]})},
        )
    max_ratio = max((m.get("ratio") or 0 for m in members), default=0)
    meta["stats"]["max_ratio"] = round(max_ratio, 1)
    if max_ratio > 100 and not any(e.type == "decompression_bomb" for e in ctx.evidence_for(art.id)):
        ctx.add_evidence(
            type="high_compression_ratio", category="archive", source="archive_analyzer", artifact=art,
            title="Extremely high compression ratio", description=f"A member compresses at {max_ratio:.0f}:1. Highly repetitive content is unusual and can indicate padding or bomb-like construction.",
            severity="low", confidence=0.5, reliability="medium", value=f"{max_ratio:.0f}:1",
        )


def _record(meta: dict, rec: MemberRecord) -> None:
    if len(meta["members"]) < 5000:
        meta["members"].append(rec.__dict__.copy())


# ---------------------------------------------------------------------------------- ZIP
def _zip(ctx: AnalysisContext, art: ArtifactContext, meta: dict, budget: _Budget) -> list[ArtifactContext]:
    limits = ctx.limits
    declared = zip_entry_count(art.path)
    meta["stats"]["declared_entries"] = declared
    if declared is not None and declared > limits.max_files_per_archive:
        raise ExtractionLimit("too_many_files", f"archive declares {declared} entries (max_files_per_archive={limits.max_files_per_archive})")
    opener = pyzipper.AESZipFile if pyzipper is not None else zipfile.ZipFile
    children: list[ArtifactContext] = []
    try:
        zf = opener(art.path)
    except Exception as exc:
        meta["stats"]["error"] = f"corrupted archive: {str(exc)[:200]}"
        art.errors.append(f"zip: {exc}")
        ctx.add_evidence(type="corrupted_archive", category="archive", source="archive_analyzer", artifact=art,
                         title="Corrupted or malformed ZIP structure",
                         description="The archive could not be parsed. Malformed archives can target parser bugs or evade scanners.",
                         severity="low", confidence=0.5, reliability="medium", value=str(exc)[:200])
        return []
    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files_per_archive:
            raise ExtractionLimit("too_many_files", f"archive holds {len(infos)} entries")
        meta["stats"]["entries"] = len(infos)
        total_declared = sum(i.file_size for i in infos)
        meta["stats"]["declared_uncompressed"] = total_declared
        passwords = [ctx.password.encode()] if ctx.password else []
        passwords += [p.encode() for p in COMMON_SAMPLE_PASSWORDS]
        working_pwd: bytes | None = None
        for info in infos:
            ctx.check()
            check = check_member_path(info.filename, limits.max_filename_length * 4)
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = "dir" if info.is_dir() else ("symlink" if stat.S_ISLNK(mode) else "file")
            ratio = (info.file_size / info.compress_size) if info.compress_size else None
            rec = MemberRecord(
                name=info.filename[:1024], normalized=check.normalized, size=info.file_size, compressed=info.compress_size,
                kind=kind, encrypted=bool(info.flag_bits & 0x1), issues=check.issues, ratio=ratio,
                mtime=_zip_time(info.date_time),
            )
            if kind == "symlink":
                try:
                    if info.file_size < 4096 and not rec.encrypted:
                        rec.link_target = zf.read(info).decode("utf-8", "replace")
                except Exception:
                    pass
                rec.skipped_reason = "symlink not materialised"
            if kind != "file":
                _record(meta, rec)
                continue
            if rec.mtime:
                ctx.event(f"Archive member timestamp: {rec.normalized[:120]}", engine="archive_analyzer",
                          artifact_id=art.id, lane="artifact", ts=rec.mtime)
            budget.check_artifacts()
            try:
                candidates = [None] if not rec.encrypted else ([working_pwd] if working_pwd else []) + passwords
                done = False
                last_exc: Exception | None = None
                for pwd in candidates:
                    try:
                        if pwd is not None and hasattr(zf, "setpassword"):
                            zf.setpassword(pwd)
                        with zf.open(info, pwd=pwd) if pwd is not None else zf.open(info) as src:
                            path, rel, size = _stream_to_quarantine(ctx, src, budget, info.compress_size)
                        if rec.encrypted:
                            working_pwd = pwd
                            if ctx.password is None or pwd != ctx.password.encode():
                                ctx.event("Encrypted member opened with a common sample-sharing password",
                                          engine="archive_analyzer", artifact_id=art.id)
                        done = True
                        break
                    except ExtractionLimit:
                        raise
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, ValueError, OSError, EOFError) as exc:
                        last_exc = exc
                        continue
                    except Exception as exc:  # pyzipper-specific errors
                        last_exc = exc
                        continue
                if not done:
                    rec.skipped_reason = "encrypted (password unknown)" if rec.encrypted else f"read error: {str(last_exc)[:120]}"
                    _record(meta, rec)
                    continue
            except ExtractionLimit as exc:
                rec.skipped_reason = exc.kind
                _record(meta, rec)
                raise
            child = _child(ctx, art, rec, path, rel, size)
            rec.extracted, rec.child_id = True, child.id
            _record(meta, rec)
            children.append(child)
    return children


def _zip_time(dt: tuple) -> str | None:
    try:
        return datetime(*dt, tzinfo=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------------- TAR
def _tar(ctx: AnalysisContext, art: ArtifactContext, meta: dict, budget: _Budget) -> list[ArtifactContext]:
    limits = ctx.limits
    children: list[ArtifactContext] = []
    try:
        tf = tarfile.open(art.path, mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        meta["stats"]["error"] = str(exc)[:200]
        ctx.add_evidence(type="corrupted_archive", category="archive", source="archive_analyzer", artifact=art,
                         title="Corrupted or malformed TAR structure", description="The archive could not be parsed.",
                         severity="low", confidence=0.5, reliability="medium", value=str(exc)[:200])
        return []
    count = 0
    with tf:
        while True:
            ctx.check()
            try:
                member = tf.next()
            except (tarfile.TarError, OSError, EOFError) as exc:
                meta["stats"]["error"] = f"truncated/corrupted: {str(exc)[:200]}"
                break
            if member is None:
                break
            count += 1
            if count > limits.max_files_per_archive:
                raise ExtractionLimit("too_many_files", f"more than {limits.max_files_per_archive} entries")
            check = check_member_path(member.name, limits.max_filename_length * 4)
            if member.isreg():
                kind = "file"
            elif member.isdir():
                kind = "dir"
            elif member.issym():
                kind = "symlink"
            elif member.islnk():
                kind = "hardlink"
            elif member.ischr() or member.isblk():
                kind = "device"
            elif member.isfifo():
                kind = "fifo"
            else:
                kind = "other"
            rec = MemberRecord(
                name=member.name[:1024], normalized=check.normalized, size=member.size, compressed=None, kind=kind,
                issues=check.issues, link_target=(member.linkname[:1024] if kind in ("symlink", "hardlink") else None),
                mtime=datetime.fromtimestamp(member.mtime, tz=timezone.utc).isoformat() if member.mtime and member.mtime > 0 else None,
            )
            if kind in ("symlink", "hardlink"):
                lt = check_member_path(member.linkname)
                if lt.traversal:
                    rec.issues.append("link_escapes_root")
            if kind != "file":
                rec.skipped_reason = None if kind == "dir" else f"{kind} not materialised"
                _record(meta, rec)
                continue
            budget.check_artifacts()
            src = tf.extractfile(member)
            if src is None:
                _record(meta, rec)
                continue
            try:
                path, rel, size = _stream_to_quarantine(ctx, src, budget, None)
            except ExtractionLimit as exc:
                rec.skipped_reason = exc.kind
                _record(meta, rec)
                raise
            child = _child(ctx, art, rec, path, rel, size)
            rec.extracted, rec.child_id = True, child.id
            _record(meta, rec)
            children.append(child)
    meta["stats"]["entries"] = count
    return children


# ------------------------------------------------------------------------ gzip/bz2/xz
def _single_stream(ctx: AnalysisContext, art: ArtifactContext, meta: dict, budget: _Budget) -> list[ArtifactContext]:
    det = art.detected_type
    name = art.display_name
    for suffix in (".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".z"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)] + (".tar" if suffix.startswith(".t") else "")
            break
    else:
        name = name + ".out"
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[det]
    rec = MemberRecord(name=name, normalized=name, size=None, compressed=art.size)
    budget.check_artifacts()
    try:
        with opener(art.path, "rb") as src:
            path, rel, size = _stream_to_quarantine(ctx, src, budget, art.size)
    except ExtractionLimit as exc:
        rec.skipped_reason = exc.kind
        _record(meta, rec)
        raise
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        meta["stats"]["error"] = str(exc)[:200]
        ctx.add_evidence(type="corrupted_archive", category="archive", source="archive_analyzer", artifact=art,
                         title=f"Corrupted {det} stream", description="Decompression failed.", severity="low",
                         confidence=0.5, reliability="medium", value=str(exc)[:200])
        _record(meta, rec)
        return []
    rec.size = size
    rec.ratio = size / max(1, art.size)
    child = _child(ctx, art, rec, path, rel, size)
    rec.extracted, rec.child_id = True, child.id
    _record(meta, rec)
    meta["stats"]["entries"] = 1
    return [child]


# ----------------------------------------------------------------------------------- 7z
def _sevenzip(ctx: AnalysisContext, art: ArtifactContext, meta: dict, budget: _Budget) -> list[ArtifactContext]:
    if py7zr is None:
        ctx.limitation("7z support not installed (pip install py7zr); 7z contents not extracted.")
        meta["stats"]["skipped"] = "py7zr not installed"
        return []
    limits = ctx.limits
    produced: list[tuple[str, Path, str, int]] = []
    writers: list = []

    class _Writer(py7zr.io.Py7zIO):
        def __init__(self, fname: str):
            self.fname = fname
            self.path, self.rel = _out_path(ctx)
            self.fh = open(self.path, "wb")
            self.n = 0

        def write(self, s):
            ctx.check()
            self.n += len(s)
            if self.n > limits.max_entry_size:
                raise ExtractionLimit("entry_size", "member exceeds max_entry_size")
            budget.add_bytes(len(s))
            return self.fh.write(s)

        def read(self, size=None):
            return b""

        def seek(self, offset, whence=0):
            return self.fh.seek(offset, whence)

        def flush(self):
            self.fh.flush()

        def size(self):
            return self.n

        def close(self):
            if not self.fh.closed:
                self.fh.close()
                harden_file(self.path)
                produced.append((self.fname, self.path, self.rel, self.n))

    class _Factory(py7zr.io.WriterFactory):
        def create(self, filename):
            budget.check_artifacts()
            w = _Writer(filename)
            writers.append(w)
            return w

    pwd_candidates = [ctx.password] if ctx.password else [None, *COMMON_SAMPLE_PASSWORDS]
    last: Exception | None = None
    for pwd in pwd_candidates:
        try:
            with py7zr.SevenZipFile(art.path, mode="r", password=pwd) as z:
                entries = z.list()
                if len(entries) > limits.max_files_per_archive:
                    raise ExtractionLimit("too_many_files", f"archive holds {len(entries)} entries")
                declared = sum((e.uncompressed or 0) for e in entries)
                compressed = max(1, art.size)
                if declared > limits.max_extracted_size or declared / compressed > limits.max_compression_ratio * 4:
                    raise ExtractionLimit("compression_ratio", f"declared uncompressed size {declared} bytes for a {art.size}-byte archive")
                safe_targets = []
                recs: dict[str, MemberRecord] = {}
                for e in entries:
                    check = check_member_path(e.filename)
                    kind = "dir" if e.is_directory else ("symlink" if getattr(e, "is_symlink", False) else "file")
                    rec = MemberRecord(name=e.filename[:1024], normalized=check.normalized, size=e.uncompressed,
                                       compressed=getattr(e, "compressed", None), kind=kind, encrypted=bool(z.needs_password()),
                                       issues=check.issues,
                                       mtime=e.creationtime.astimezone(timezone.utc).isoformat() if getattr(e, "creationtime", None) else None)
                    recs[e.filename] = rec
                    if kind == "file" and not check.traversal:
                        safe_targets.append(e.filename)
                    elif check.traversal:
                        rec.skipped_reason = "path traversal name"
                if safe_targets:
                    try:
                        z.extract(targets=safe_targets, factory=_Factory())
                    finally:
                        for w in writers:
                            w.close()
                        writers.clear()
            names_done = {p[0].split("/")[-1]: p for p in produced}
            children = []
            for fname, rec in recs.items():
                hit = None
                for p in produced:
                    if p[0].endswith(rec.normalized) and rec.normalized:
                        hit = p
                        break
                if hit is None and rec.normalized.split("/")[-1] in names_done:
                    hit = names_done[rec.normalized.split("/")[-1]]
                if hit and rec.kind == "file":
                    _, path, rel, size = hit
                    produced.remove(hit)
                    child = _child(ctx, art, rec, path, rel, size)
                    rec.extracted, rec.child_id = True, child.id
                    children.append(child)
                _record(meta, rec)
            meta["stats"]["entries"] = len(recs)
            return children
        except ExtractionLimit:
            raise
        except Exception as exc:  # wrong password / corrupt
            for w in writers:
                w.close()
            writers.clear()
            for p in produced:
                try:
                    os.chmod(p[1], 0o600)
                    p[1].unlink()
                except OSError:
                    pass
            produced.clear()
            last = exc
            continue
    meta["stats"]["error"] = f"could not open 7z: {str(last)[:200]}"
    ctx.limitation(f"{art.display_name}: 7z archive could not be opened (encrypted or corrupted).")
    return []


def add_decoded_child(ctx: AnalysisContext, parent: ArtifactContext, data: bytes, label: str) -> ArtifactContext | None:
    """Materialise a payload decoded statically from a parent (e.g. base64 blob) as a child artifact."""
    if parent.depth + 1 > ctx.limits.max_archive_depth or len(ctx.artifacts) >= ctx.limits.max_total_artifacts:
        return None
    if len(data) > ctx.limits.max_entry_size:
        return None
    budget = _Budget(ctx)
    budget.add_bytes(len(data))
    path, rel = _out_path(ctx)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    harden_file(path)
    rec = MemberRecord(name=label, normalized=label, size=len(data), compressed=None)
    return _child(ctx, parent, rec, path, rel, len(data))
