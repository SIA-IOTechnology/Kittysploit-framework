#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parallel command execution across multiple implant sessions."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


@dataclass
class SessionJobResult:
    session_id: str
    status: str = "pending"
    output: str = ""
    error: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None


@dataclass
class SessionJob:
    id: str
    name: str
    command: str = ""
    module_path: str = ""
    session_ids: List[str] = field(default_factory=list)
    status: str = "running"
    created_at: datetime = field(default_factory=datetime.utcnow)
    results: Dict[str, SessionJobResult] = field(default_factory=dict)
    cancel_event: threading.Event = field(default_factory=threading.Event)


class SessionJobManager:
    """Run shell commands or meterpreter commands across many sessions."""

    def __init__(self, framework):
        self.framework = framework
        self._jobs: Dict[str, SessionJob] = {}
        self._lock = threading.Lock()

    def list_jobs(self) -> List[SessionJob]:
        with self._lock:
            return list(self._jobs.values())

    def get_job(self, job_id: str) -> Optional[SessionJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def kill_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.cancel_event.set()
            job.status = "cancelled"
            return True

    def run_command_on_sessions(
        self,
        session_ids: List[str],
        command: str,
        *,
        wait: bool = False,
        on_result: Optional[Callable[[SessionJobResult], None]] = None,
    ) -> SessionJob:
        job = SessionJob(
            id=str(uuid.uuid4()),
            name=f"cmd:{command[:48]}",
            command=command,
            session_ids=list(session_ids),
        )
        for sid in session_ids:
            job.results[sid] = SessionJobResult(session_id=sid)

        with self._lock:
            self._jobs[job.id] = job

        worker = threading.Thread(
            target=self._execute_job,
            args=(job, on_result),
            daemon=True,
        )
        worker.start()
        if wait:
            worker.join()
        return job

    def _execute_job(self, job: SessionJob, on_result: Optional[Callable] = None) -> None:
        threads: List[threading.Thread] = []

        def _worker(session_id: str) -> None:
            result = job.results[session_id]
            if job.cancel_event.is_set():
                result.status = "cancelled"
                return
            result.started_at = time.time()
            try:
                payload = self._run_on_session(session_id, job.command)
                result.output = str(payload.get("output") or "")
                result.error = str(payload.get("error") or "")
                result.status = "completed" if int(payload.get("status", 1)) == 0 else "failed"
            except Exception as exc:
                result.status = "failed"
                result.error = str(exc)
            finally:
                result.finished_at = time.time()
                if on_result:
                    try:
                        on_result(result)
                    except Exception:
                        pass

        for sid in job.session_ids:
            if job.cancel_event.is_set():
                break
            t = threading.Thread(target=_worker, args=(sid,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if job.cancel_event.is_set():
            job.status = "cancelled"
        elif any(r.status == "failed" for r in job.results.values()):
            job.status = "completed_with_errors"
        else:
            job.status = "completed"

    def _run_on_session(self, session_id: str, command: str) -> Dict[str, Any]:
        shell_mgr = getattr(self.framework, "shell_manager", None)
        if not shell_mgr:
            return {"output": "", "status": 1, "error": "Shell manager unavailable"}

        session = self.framework.session_manager.get_session(session_id)
        if not session:
            return {"output": "", "status": 1, "error": "Session not found"}

        shell = shell_mgr.get_shell(session_id)
        if shell is None:
            shell_type = self._resolve_shell_type(session.session_type)
            shell = shell_mgr.create_shell(
                session_id,
                shell_type,
                session_type=session.session_type,
                framework=self.framework,
            )
        if shell is None:
            return {"output": "", "status": 1, "error": "Could not create shell for session"}

        if hasattr(shell, "execute_command"):
            return shell.execute_command(command)
        return {"output": "", "status": 1, "error": "Shell does not support execute_command"}

    @staticmethod
    def _resolve_shell_type(session_type: str) -> str:
        st = str(session_type or "").lower()
        mapping = {
            "meterpreter": "meterpreter",
            "shell": "classic",
            "classic": "classic",
            "polling": "polling",
            "reverse_http_polling": "polling",
        }
        return mapping.get(st, "meterpreter" if "meterpreter" in st else "classic")


_global_session_job_manager: Optional[SessionJobManager] = None


def get_session_job_manager(framework) -> SessionJobManager:
    global _global_session_job_manager
    if _global_session_job_manager is None:
        _global_session_job_manager = SessionJobManager(framework)
    return _global_session_job_manager
