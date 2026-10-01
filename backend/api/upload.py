"""Streaming multipart upload straight into quarantine.

The request body is parsed incrementally: file parts are written directly to
``storage/quarantine/<analysis_id>/<uuid>.bin`` (never to a shared temp dir), size
and count limits are enforced while streaming, and the archive password field is
kept in memory only.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request

from backend.core.config import Settings
from backend.core.security import harden_file, internal_name, sanitize_display_name
from backend.core.storage import Storage

try:
    from python_multipart.multipart import MultipartParser, parse_options_header
except ImportError:  # pragma: no cover - older python-multipart
    from multipart.multipart import MultipartParser, parse_options_header  # type: ignore

TEXT_FIELDS = {"password", "mode", "notes", "name"}
MAX_FIELD = 4096


@dataclass
class UploadResult:
    files: list[dict[str, Any]] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)


class _State:
    def __init__(self, storage: Storage, analysis_id: str, settings: Settings):
        self.storage = storage
        self.analysis_id = analysis_id
        self.limits = settings.limits
        self.result = UploadResult()
        self.header_field = b""
        self.header_value = b""
        self.headers: dict[bytes, bytes] = {}
        self.part_name: str | None = None
        self.part_filename: str | None = None
        self.fh = None
        self.current: dict[str, Any] | None = None
        self.buffer = bytearray()
        self.total = 0
        self.error: HTTPException | None = None

    # callbacks -------------------------------------------------------------------
    def on_part_begin(self) -> None:
        self.headers = {}
        self.part_name = None
        self.part_filename = None
        self.buffer = bytearray()

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self.header_field += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self.header_value += data[start:end]

    def on_header_end(self) -> None:
        self.headers[self.header_field.lower()] = self.header_value
        self.header_field = b""
        self.header_value = b""

    def on_headers_finished(self) -> None:
        disp, opts = parse_options_header(self.headers.get(b"content-disposition", b""))
        name = opts.get(b"name", b"").decode("utf-8", "replace")
        filename = opts.get(b"filename")
        self.part_name = name
        if filename is not None:
            if name != "files":
                raise HTTPException(400, "file parts must use the field name 'files'")
            if len(self.result.files) >= self.limits.max_files_per_upload:
                raise HTTPException(413, f"too many files (max_files_per_upload={self.limits.max_files_per_upload})")
            raw_name = filename.decode("utf-8", "surrogateescape")
            qdir = self.storage.quarantine_dir(self.analysis_id, create=True)
            iname = internal_name()
            path = qdir / iname
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), stat.S_IRUSR | stat.S_IWUSR)
            self.fh = os.fdopen(fd, "wb")
            raw_for_display = raw_name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
            san = sanitize_display_name(filename, self.limits.max_filename_length)
            self.current = {
                "artifact_id": iname.split(".")[0], "storage_rel": f"quarantine/{self.analysis_id}/{iname}",
                "original_name": raw_for_display[:2048], "display_name": san.display, "name_issues": san.issues,
                "size": 0, "path": path,
            }
        elif name not in TEXT_FIELDS:
            raise HTTPException(400, f"unexpected form field {name!r}")

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if self.fh is not None and self.current is not None:
            self.current["size"] += len(chunk)
            self.total += len(chunk)
            if self.current["size"] > self.limits.max_upload_size:
                raise HTTPException(413, f"file exceeds max_upload_size ({self.limits.max_upload_size} bytes)")
            self.fh.write(chunk)
        else:
            self.buffer += chunk
            if len(self.buffer) > MAX_FIELD:
                raise HTTPException(413, "form field too large")

    def on_part_end(self) -> None:
        if self.fh is not None and self.current is not None:
            self.fh.close()
            self.fh = None
            harden_file(self.current["path"])
            cur = self.current
            cur.pop("path")
            self.result.files.append(cur)
            self.current = None
        elif self.part_name in TEXT_FIELDS:
            self.result.fields[self.part_name] = self.buffer.decode("utf-8", "replace")
        self.buffer = bytearray()

    def cleanup(self) -> None:
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError:
                pass


async def receive_upload(request: Request, storage: Storage, analysis_id: str, settings: Settings) -> UploadResult:
    ctype, opts = parse_options_header(request.headers.get("content-type", ""))
    if ctype != b"multipart/form-data" or b"boundary" not in opts:
        raise HTTPException(415, "expected multipart/form-data")
    declared = request.headers.get("content-length")
    limit = settings.limits.max_upload_size * max(1, settings.limits.max_files_per_upload) + 1024 * 1024
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, "request body too large")
    state = _State(storage, analysis_id, settings)
    callbacks = {
        "on_part_begin": state.on_part_begin, "on_part_data": state.on_part_data, "on_part_end": state.on_part_end,
        "on_header_field": state.on_header_field, "on_header_value": state.on_header_value,
        "on_header_end": state.on_header_end, "on_headers_finished": state.on_headers_finished,
    }
    parser = MultipartParser(opts[b"boundary"], callbacks)
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > limit:
                raise HTTPException(413, "request body too large")
            parser.write(chunk)
        parser.finalize()
    except HTTPException:
        state.cleanup()
        storage.purge_analysis(analysis_id)
        raise
    except Exception as exc:
        state.cleanup()
        storage.purge_analysis(analysis_id)
        raise HTTPException(400, f"malformed multipart body: {type(exc).__name__}") from exc
    if not state.result.files:
        storage.purge_analysis(analysis_id)
        raise HTTPException(400, "no file uploaded (use the 'files' field)")
    return state.result
