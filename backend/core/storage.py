"""Isolated filesystem storage.

Layout::

    storage/
      quarantine/<analysis_id>/<uuid>.bin   uploaded samples (read-only, never served)
      extracted/<analysis_id>/<uuid>.bin    archive members (read-only, never served)
      evidence/<analysis_id>/               worker output (result.json, reverse/*.json)
      reports/<analysis_id>/                generated reports
      tmp/                                  worker scratch space, wiped after each job
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from .security import (
    QUARANTINE_DIR_MODE,
    ensure_within,
    harden_dir,
    harden_file,
    internal_name,
    is_valid_id,
)


class UploadTooLarge(Exception):
    pass


@dataclass
class StoredUpload:
    internal_name: str
    path: Path
    size: int
    sha256: str


class Storage:
    AREAS = ("quarantine", "extracted", "evidence", "reports", "tmp")

    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def init(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for area in self.AREAS:
            p = self.root / area
            p.mkdir(parents=True, exist_ok=True)
            harden_dir(p)

    def area_dir(self, area: str, analysis_id: str, create: bool = False) -> Path:
        if area not in self.AREAS:
            raise ValueError(area)
        if not is_valid_id(analysis_id):
            raise ValueError("invalid analysis id")
        path = ensure_within(self.root / area, self.root / area / analysis_id)
        if create:
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, QUARANTINE_DIR_MODE)
        return path

    def quarantine_dir(self, analysis_id: str, create: bool = False) -> Path:
        return self.area_dir("quarantine", analysis_id, create)

    def extracted_dir(self, analysis_id: str, create: bool = False) -> Path:
        return self.area_dir("extracted", analysis_id, create)

    def evidence_dir(self, analysis_id: str, create: bool = False) -> Path:
        return self.area_dir("evidence", analysis_id, create)

    def reports_dir(self, analysis_id: str, create: bool = False) -> Path:
        return self.area_dir("reports", analysis_id, create)

    def tmp_dir(self, analysis_id: str, create: bool = False) -> Path:
        return self.area_dir("tmp", analysis_id, create)

    def resolve_relative(self, relative: str) -> Path:
        """Turn a stored relative path back into an absolute one, refusing escapes."""
        return ensure_within(self.root, self.root / relative)

    def relative(self, path: Path) -> str:
        return str(ensure_within(self.root, path).relative_to(self.root))

    def store_upload(
        self,
        analysis_id: str,
        stream: BinaryIO,
        max_size: int,
        chunk_size: int = 1024 * 1024,
    ) -> StoredUpload:
        """Stream an upload into quarantine under a fresh internal name.

        The original filename is never used for the path. The size limit is
        enforced while streaming, so an oversized upload never fully lands on disk.
        """
        qdir = self.quarantine_dir(analysis_id, create=True)
        name = internal_name()
        target = ensure_within(qdir, qdir / name)
        digest = hashlib.sha256()
        size = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, stat.S_IRUSR | stat.S_IWUSR)
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_size:
                        raise UploadTooLarge(f"upload exceeds {max_size} bytes")
                    digest.update(chunk)
                    out.write(chunk)
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        harden_file(target)
        return StoredUpload(internal_name=name, path=target, size=size, sha256=digest.hexdigest())

    def purge_analysis(self, analysis_id: str) -> None:
        for area in self.AREAS:
            try:
                path = self.area_dir(area, analysis_id)
            except ValueError:
                continue
            if path.exists():
                _force_rmtree(path)

    def usage(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for area in self.AREAS:
            total = 0
            base = self.root / area
            for dirpath, _dirs, files in os.walk(base):
                for f in files:
                    try:
                        total += os.lstat(os.path.join(dirpath, f)).st_size
                    except OSError:
                        pass
            out[area] = total
        return out


def _force_rmtree(path: Path) -> None:
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IRWXU)
            func(p)
        except OSError:
            pass

    for dirpath, dirs, _files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(dirpath, d), stat.S_IRWXU)
            except OSError:
                pass
    shutil.rmtree(path, onerror=onerror)


def read_range(path: Path, offset: int, length: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(max(0, offset))
        return fh.read(max(0, length))


def iter_chunks(path: Path, chunk_size: int = 1024 * 1024, limit: int | None = None) -> Iterable[bytes]:
    remaining = limit
    with open(path, "rb") as fh:
        while True:
            size = chunk_size if remaining is None else min(chunk_size, remaining)
            if size <= 0:
                break
            chunk = fh.read(size)
            if not chunk:
                break
            if remaining is not None:
                remaining -= len(chunk)
            yield chunk
