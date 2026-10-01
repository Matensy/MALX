"""Worker process entry point.

The API process spawns one worker per analysis (``multiprocessing`` *spawn*
context: a fresh interpreter, no inherited state). The job — including the
optional archive password — travels through the process pipe, never through
argv/environment/disk. The worker has no database access: it writes a single
``result.json`` into the analysis evidence directory and reports progress through
a queue; the parent persists results.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import traceback
from pathlib import Path
from typing import Any

from backend.analyzers.base import AnalysisCancelled, AnalysisTimeout


def worker_main(job: dict[str, Any], progress_queue, cancel_event) -> None:
    from backend.workers import sandbox

    tmp_root = Path(job["storage_root"]) / "tmp" / job["analysis_id"]
    tmp_root.mkdir(parents=True, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="w-", dir=tmp_root)
    hardening: dict[str, Any] = {}
    try:
        sandbox.minimal_environment(tmp_dir)
        limits = job["limits"]
        hardening.update(sandbox.apply_limits(
            memory_bytes=int(limits["max_memory_per_worker"]),
            cpu_seconds=int(limits["max_analysis_time"]) + 30,
            max_file_bytes=max(int(limits["max_entry_size"]), 64 * 1024 * 1024) + 16 * 1024 * 1024,
        ))
        hardening.update(sandbox.drop_privileges_and_network())
        progress_queue.put(("hardening", hardening))

        from backend.workers.pipeline import run_pipeline

        def progress(stage: str, percent: int, detail: str | None) -> None:
            progress_queue.put(("progress", {"stage": stage, "percent": percent, "detail": detail}))

        result = run_pipeline(job, progress=progress, cancel_check=cancel_event.is_set)
        result["worker_hardening"] = hardening
        write_result(Path(job["result_path"]), result)
        progress_queue.put(("done", None))
    except AnalysisCancelled:
        progress_queue.put(("cancelled", None))
    except AnalysisTimeout as exc:
        progress_queue.put(("error", f"timeout: {exc}"))
    except MemoryError:
        progress_queue.put(("error", "worker exceeded max_memory_per_worker"))
    except Exception as exc:  # report but never leak file contents
        tb = traceback.extract_tb(exc.__traceback__)
        where = f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else "?"
        progress_queue.put(("error", f"{type(exc).__name__} at {where}: {str(exc)[:300]}"))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, default=str)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
