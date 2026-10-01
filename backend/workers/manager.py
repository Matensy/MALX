"""Job queue and worker supervision (runs in the API process).

API → Queue → Worker process → result.json → ingestion → reports.
Heavy analysis never runs inside an HTTP request.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import queue
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.config import Settings
from backend.core.database import session_scope
from backend.core.enums import AnalysisStatus
from backend.core.logging import get_logger, log_event
from backend.core.storage import Storage
from backend.models.entities import Analysis

log = get_logger("manager")
GRACE_SECONDS = 30
STAGE_ORDER = ["QUEUED", "VALIDATING", "EXTRACTING", "ANALYZING", "CORRELATING", "REPORTING", "COMPLETED"]


class JobManager:
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage
        self.q: queue.Queue[str] = queue.Queue()
        self._passwords: dict[str, str] = {}  # in memory only; removed as soon as the job starts
        self._cancel: dict[str, Any] = {}
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._ctx = mp.get_context("spawn")
        self.inline = settings.workers.mode == "inline"
        self.active: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._recover()
        for i in range(max(1, self.settings.workers.max_concurrent_analyses)):
            t = threading.Thread(target=self._loop, name=f"malx-dispatch-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for ev in list(self._cancel.values()):
            try:
                ev.set()
            except Exception:
                pass

    def _recover(self) -> None:
        """Re-queue analyses interrupted by a restart (the password is not recoverable)."""
        with session_scope() as s:
            rows = s.query(Analysis).filter(Analysis.status.notin_(["COMPLETED", "FAILED", "CANCELLED"])).all()
            for a in rows:
                a.status = AnalysisStatus.QUEUED.value
                a.progress = 0
                a.stage_detail = "re-queued after restart"
                opts = dict(a.options_json or {})
                if opts.get("has_password"):
                    opts["password_dropped"] = True
                a.options_json = opts
                self.q.put(a.id)

    # ------------------------------------------------------------------ API
    def submit(self, analysis_id: str, password: str | None) -> None:
        if password:
            self._passwords[analysis_id] = password
        self.q.put(analysis_id)

    def cancel(self, analysis_id: str) -> bool:
        ev = self._cancel.get(analysis_id)
        if ev is not None:
            ev.set()
            return True
        with session_scope() as s:
            a = s.get(Analysis, analysis_id)
            if a and a.status == AnalysisStatus.QUEUED.value:
                a.status = AnalysisStatus.CANCELLED.value
                a.completed_at = datetime.now(timezone.utc)
                a.stage_detail = "cancelled before start"
                self._passwords.pop(analysis_id, None)
                return True
        return False

    def run_now(self, analysis_id: str) -> None:
        """Synchronous execution (tests / CLI)."""
        self._process(analysis_id)

    # ------------------------------------------------------------------ internals
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                aid = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process(aid)
            except Exception as exc:  # never kill the dispatcher
                log_event(log, "dispatch_error", analysis_id=aid, status="failed", error=str(exc)[:300])
                self._finish(aid, AnalysisStatus.FAILED, f"internal error: {str(exc)[:300]}")

    def _update(self, aid: str, **fields) -> None:
        with session_scope() as s:
            a = s.get(Analysis, aid)
            if a is None:
                return
            for k, v in fields.items():
                setattr(a, k, v)

    def _finish(self, aid: str, status: AnalysisStatus, error: str | None = None) -> None:
        now = datetime.now(timezone.utc)
        with session_scope() as s:
            a = s.get(Analysis, aid)
            if a is None:
                return
            a.status = status.value
            a.completed_at = now
            if a.started_at:
                started = a.started_at if a.started_at.tzinfo else a.started_at.replace(tzinfo=timezone.utc)
                a.duration_ms = int((now - started).total_seconds() * 1000)
            if error:
                a.error = error
            if status == AnalysisStatus.COMPLETED:
                a.progress = 100
                a.stage_detail = "completed"
        log_event(log, "analysis_finished", analysis_id=aid, status=status.value, error=error)

    def build_job(self, a: Analysis, password: str | None) -> dict[str, Any]:
        opts = a.options_json or {}
        st = self.settings
        return {
            "analysis_id": a.id, "mode": a.mode, "files": opts.get("files", []), "password": password,
            "password_dropped": bool(opts.get("password_dropped")),
            "limits": st.limits.model_dump(), "storage_root": str(self.storage.root), "rules_dir": str(st.rules_dir),
            "advisories_dir": str(st.rules_dir / "advisories"),
            "result_path": str(self.storage.evidence_dir(a.id, create=True) / "result.json"),
            "tools": {"enabled": st.integrations.local_tools_enabled, "timeout": st.integrations.tool_timeout,
                      "ghidra_home": st.integrations.ghidra_home},
        }

    def _process(self, aid: str) -> None:
        with session_scope() as s:
            a = s.get(Analysis, aid)
            if a is None or a.status != AnalysisStatus.QUEUED.value:
                return
            password = self._passwords.pop(aid, None)
            job = self.build_job(a, password)
            a.status = AnalysisStatus.VALIDATING.value
            a.started_at = datetime.now(timezone.utc)
            a.progress = 2
        with self._lock:
            self.active.add(aid)
        log_event(log, "analysis_started", analysis_id=aid, status="VALIDATING")
        pipeline_events: list[dict[str, Any]] = []
        try:
            if self.inline:
                outcome, info = self._run_inline(job, pipeline_events)
            else:
                outcome, info = self._run_process(job, pipeline_events)
            job.pop("password", None)
            if outcome == "done":
                self._ingest(aid, Path(job["result_path"]), pipeline_events)
            elif outcome == "cancelled":
                self._finish(aid, AnalysisStatus.CANCELLED, "cancelled by user")
            else:
                self._finish(aid, AnalysisStatus.FAILED, info or "analysis failed")
        finally:
            with self._lock:
                self.active.discard(aid)
            self._cancel.pop(aid, None)
            shutil.rmtree(self.storage.root / "tmp" / aid, ignore_errors=True)

    def _on_progress(self, aid: str, payload: dict[str, Any], events: list[dict[str, Any]], last: dict[str, Any]) -> None:
        stage = payload["stage"]
        if last.get("stage") != stage:
            events.append({"ts": datetime.now(timezone.utc).isoformat(), "lane": "pipeline", "event": f"Stage {stage}", "engine": "worker"})
        if time.monotonic() - last.get("t", 0) > 0.4 or last.get("stage") != stage:
            self._update(aid, status=stage, progress=int(payload["percent"]), stage_detail=(payload.get("detail") or "")[:300])
            last["t"] = time.monotonic()
        last["stage"] = stage

    def _run_inline(self, job: dict[str, Any], events: list[dict[str, Any]]) -> tuple[str, str | None]:
        from backend.analyzers.base import AnalysisCancelled, AnalysisTimeout
        from backend.workers.pipeline import run_pipeline
        from backend.workers.worker import write_result

        aid = job["analysis_id"]
        cancel = threading.Event()
        self._cancel[aid] = cancel
        last: dict[str, Any] = {}
        try:
            result = run_pipeline(job, progress=lambda st, p, d: self._on_progress(aid, {"stage": st, "percent": p, "detail": d}, events, last),
                                  cancel_check=cancel.is_set)
        except AnalysisCancelled:
            return "cancelled", None
        except AnalysisTimeout as exc:
            return "error", f"timeout: {exc}"
        result["worker_hardening"] = {"mode": "inline (no process isolation)"}
        write_result(Path(job["result_path"]), result)
        return "done", None

    def _run_process(self, job: dict[str, Any], events: list[dict[str, Any]]) -> tuple[str, str | None]:
        from backend.workers.worker import worker_main

        aid = job["analysis_id"]
        pq = self._ctx.Queue()
        cancel = self._ctx.Event()
        self._cancel[aid] = cancel
        proc = self._ctx.Process(target=worker_main, args=(job, pq, cancel), name=f"malx-worker-{aid[:8]}", daemon=True)
        proc.start()
        deadline = time.monotonic() + self.settings.limits.max_analysis_time + GRACE_SECONDS
        last: dict[str, Any] = {}
        outcome, info = "error", None
        try:
            while True:
                if time.monotonic() > deadline:
                    outcome, info = "error", f"timeout: worker exceeded max_analysis_time ({self.settings.limits.max_analysis_time}s)"
                    break
                try:
                    kind, payload = pq.get(timeout=0.5)
                except queue.Empty:
                    if not proc.is_alive():
                        code = proc.exitcode
                        outcome = "error"
                        info = ("worker killed (resource limit reached?)" if code and code < 0 else f"worker exited unexpectedly (code {code})")
                        if cancel.is_set():
                            outcome, info = "cancelled", None
                        break
                    if cancel.is_set() and time.monotonic() > last.get("cancel_t", float("inf")):
                        outcome = "cancelled"
                        break
                    if cancel.is_set() and "cancel_t" not in last:
                        last["cancel_t"] = time.monotonic() + 5
                    continue
                if kind == "progress":
                    self._on_progress(aid, payload, events, last)
                elif kind == "hardening":
                    events.append({"ts": datetime.now(timezone.utc).isoformat(), "lane": "pipeline", "event": "Worker sandbox applied",
                                   "engine": "worker", "detail": json.dumps(payload)[:300]})
                elif kind in ("done", "cancelled", "error"):
                    outcome, info = kind, payload
                    break
        finally:
            proc.join(timeout=5)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=2)
            try:
                pq.close()
            except Exception:
                pass
        return outcome, info

    def _ingest(self, aid: str, result_path: Path, events: list[dict[str, Any]]) -> None:
        from backend.reports.generator import generate_reports
        from backend.services.persist import ingest

        self._update(aid, status=AnalysisStatus.REPORTING.value, progress=92, stage_detail="persisting evidence")
        with open(result_path, encoding="utf-8") as fh:
            result = json.load(fh)
        with session_scope() as s:
            a = s.get(Analysis, aid)
            ingest(s, a, result, extra_timeline=events)
        try:
            generate_reports(aid, self.storage)
        except Exception as exc:
            log_event(log, "report_error", analysis_id=aid, status="failed", error=str(exc)[:300])
        self._finish(aid, AnalysisStatus.COMPLETED)
