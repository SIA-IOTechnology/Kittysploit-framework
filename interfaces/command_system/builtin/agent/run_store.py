#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Workspace-isolated storage, locking, run IDs, and checkpoints for the agent."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested


def _safe_component(value: str, fallback: str = "default") -> str:
    clean = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "")).strip("._")
    return clean[:120] or fallback


def new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"agent_{timestamp}_{uuid.uuid4().hex[:10]}"


class AgentPathService:
    def __init__(self, framework: Any = None, base_dir: Optional[str] = None) -> None:
        workspace = "default"
        if framework is not None:
            getter = getattr(framework, "get_current_workspace_name", None)
            if callable(getter):
                workspace = str(getter() or "default")
            else:
                workspace = str(getattr(framework, "current_workspace", "default") or "default")
        root = (
            Path(base_dir).expanduser()
            if base_dir
            else Path(os.environ.get("KITTYSPLOIT_AGENT_HOME", "~/.kittysploit/agent")).expanduser()
        )
        self.workspace = _safe_component(workspace)
        self.root = root / self.workspace

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def memory_dir(self) -> Path:
        return self.root / "memory"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / _safe_component(run_id, "run")

    def ensure(self) -> None:
        for directory in (self.reports_dir, self.memory_dir, self.runs_dir):
            directory.mkdir(parents=True, exist_ok=True)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        yield
    finally:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass
        handle.close()


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_agent_", suffix=".json", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class AgentRunStore:
    CHECKPOINT_VERSION = 1

    def __init__(self, paths: AgentPathService, run_id: str) -> None:
        self.paths = paths
        self.run_id = _safe_component(run_id, "run")
        self.paths.ensure()

    @property
    def checkpoint_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "checkpoint.json"

    @property
    def events_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "events.jsonl"

    def save_checkpoint(self, phase: str, state_payload: Dict[str, Any]) -> Path:
        payload = {
            "checkpoint_version": self.CHECKPOINT_VERSION,
            "run_id": self.run_id,
            "phase": str(phase),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "state": state_payload,
        }
        lock = self.checkpoint_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.checkpoint_path, payload)
        return self.checkpoint_path

    def load_checkpoint(self) -> Dict[str, Any]:
        if not self.checkpoint_path.is_file():
            return {}
        with file_lock(self.checkpoint_path.with_suffix(".lock")):
            with self.checkpoint_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Invalid agent checkpoint")
        version = int(payload.get("checkpoint_version", 0) or 0)
        if version != self.CHECKPOINT_VERSION:
            raise ValueError(f"Unsupported checkpoint version: {version}")
        return payload

    def append_event(self, event: Dict[str, Any]) -> None:
        record = sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            **event,
        })
        lock = self.events_path.with_suffix(".lock")
        with file_lock(lock):
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def list_runs(self) -> List[str]:
        if not self.paths.runs_dir.is_dir():
            return []
        return sorted(
            path.name
            for path in self.paths.runs_dir.iterdir()
            if path.is_dir()
        )
