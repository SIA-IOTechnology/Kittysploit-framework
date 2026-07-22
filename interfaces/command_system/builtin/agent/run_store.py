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

    @property
    def actions_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "actions.jsonl"

    @property
    def snapshot_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "snapshot.json"

    @property
    def shadow_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "shadow.jsonl"

    @property
    def shadow_report_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "shadow_report.json"

    @property
    def specialists_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "specialists.jsonl"

    @property
    def specialist_report_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "specialist_report.json"

    @property
    def adversarial_report_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "adversarial_report.json"

    @property
    def specialist_chaos_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "specialist_chaos.json"

    @property
    def specialist_resilience_path(self) -> Path:
        return self.paths.run_dir(self.run_id) / "specialist_resilience.jsonl"

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

    def append_action_trace(self, trace: Dict[str, Any]) -> None:
        record = sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            **trace,
        })
        lock = self.actions_path.with_suffix(".lock")
        with file_lock(lock):
            with self.actions_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def save_snapshot(self, snapshot: Dict[str, Any]) -> Path:
        lock = self.snapshot_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.snapshot_path, sanitize_nested(snapshot))
        return self.snapshot_path

    def load_snapshot(self) -> Dict[str, Any]:
        if not self.snapshot_path.is_file():
            return {}
        with file_lock(self.snapshot_path.with_suffix(".lock")):
            with self.snapshot_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}

    def append_shadow_comparison(self, comparison: Dict[str, Any]) -> None:
        record = sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            **comparison,
        })
        lock = self.shadow_path.with_suffix(".lock")
        with file_lock(lock):
            with self.shadow_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def save_shadow_report(self, payload: Dict[str, Any]) -> Path:
        lock = self.shadow_report_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.shadow_report_path, sanitize_nested(payload))
        return self.shadow_report_path

    def load_shadow_report(self) -> Dict[str, Any]:
        if not self.shadow_report_path.is_file():
            return {}
        with file_lock(self.shadow_report_path.with_suffix(".lock")):
            with self.shadow_report_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}

    def append_specialist_run(self, record: Dict[str, Any]) -> None:
        payload = sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            **record,
        })
        lock = self.specialists_path.with_suffix(".lock")
        with file_lock(lock):
            with self.specialists_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")

    def save_specialist_report(self, payload: Dict[str, Any]) -> Path:
        lock = self.specialist_report_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.specialist_report_path, sanitize_nested(payload))
        return self.specialist_report_path

    def load_specialist_report(self) -> Dict[str, Any]:
        if not self.specialist_report_path.is_file():
            return {}
        with file_lock(self.specialist_report_path.with_suffix(".lock")):
            with self.specialist_report_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}

    def append_specialist_resilience(self, record: Dict[str, Any]) -> None:
        payload = sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            **record,
        })
        lock = self.specialist_resilience_path.with_suffix(".lock")
        with file_lock(lock):
            with self.specialist_resilience_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")

    def save_specialist_chaos_report(self, payload: Dict[str, Any]) -> Path:
        lock = self.specialist_chaos_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.specialist_chaos_path, sanitize_nested(payload))
        return self.specialist_chaos_path

    def save_adversarial_report(self, payload: Dict[str, Any]) -> Path:
        lock = self.adversarial_report_path.with_suffix(".lock")
        with file_lock(lock):
            atomic_write_json(self.adversarial_report_path, sanitize_nested(payload))
        return self.adversarial_report_path

    def list_runs(self) -> List[str]:
        if not self.paths.runs_dir.is_dir():
            return []
        return sorted(
            path.name
            for path in self.paths.runs_dir.iterdir()
            if path.is_dir()
        )
