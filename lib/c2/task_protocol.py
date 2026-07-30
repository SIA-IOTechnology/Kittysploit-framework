#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed task protocol for KittySploit polling agents."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Supported task commands
TASK_SHELL = "shell"
TASK_LS = "ls"
TASK_PWD = "pwd"
TASK_WHOAMI = "whoami"
TASK_CAT = "cat"
TASK_DOWNLOAD = "download"
TASK_UPLOAD = "upload"
TASK_EXIT = "exit"

SUPPORTED_TASKS = frozenset(
    {
        TASK_SHELL,
        TASK_LS,
        TASK_PWD,
        TASK_WHOAMI,
        TASK_CAT,
        TASK_DOWNLOAD,
        TASK_UPLOAD,
        TASK_EXIT,
    }
)


@dataclass
class AgentTask:
    """Typed task delivered to a Kitty agent on /poll."""

    command: str
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    args: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "command": str(self.command),
            "args": dict(self.args or {}),
        }

    def to_wire(self) -> str:
        """JSON string placed in poll ``command`` when encoding=task."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["AgentTask"]:
        if not isinstance(data, dict):
            return None
        cmd = str(data.get("command") or "").strip().lower()
        if not cmd:
            return None
        return cls(
            command=cmd,
            task_id=str(data.get("task_id") or uuid.uuid4().hex[:16]),
            args=dict(data.get("args") or {}) if isinstance(data.get("args"), dict) else {},
        )

    @classmethod
    def from_wire(cls, text: str) -> Optional["AgentTask"]:
        text = str(text or "").strip()
        if not text:
            return None
        try:
            return cls.from_dict(json.loads(text))
        except Exception:
            # Legacy bare shell string
            return cls(command=TASK_SHELL, args={"cmd": text})


@dataclass
class AgentResult:
    task_id: str
    output: str = ""
    status: str = "completed"  # completed | failed
    files: List[Dict[str, Any]] = field(default_factory=list)
    # files entries: {path, encoding=base64, data}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "output": self.output,
            "status": self.status,
            "files": list(self.files or []),
        }


def make_shell_task(cmd: str, *, task_id: str = "") -> AgentTask:
    return AgentTask(
        command=TASK_SHELL,
        task_id=task_id or uuid.uuid4().hex[:16],
        args={"cmd": cmd},
    )


def make_ls_task(path: str = ".", *, task_id: str = "") -> AgentTask:
    return AgentTask(
        command=TASK_LS,
        task_id=task_id or uuid.uuid4().hex[:16],
        args={"path": path or "."},
    )


def make_download_task(path: str, *, task_id: str = "") -> AgentTask:
    return AgentTask(
        command=TASK_DOWNLOAD,
        task_id=task_id or uuid.uuid4().hex[:16],
        args={"path": path},
    )


def make_upload_task(path: str, data_b64: str, *, task_id: str = "") -> AgentTask:
    return AgentTask(
        command=TASK_UPLOAD,
        task_id=task_id or uuid.uuid4().hex[:16],
        args={"path": path, "data": data_b64, "encoding": "base64"},
    )


def poll_payload_for_task(task: Optional[AgentTask], *, next_sleep: float, die: bool = False) -> Dict[str, Any]:
    """Build /poll JSON body for typed or empty task."""
    payload: Dict[str, Any] = {
        "encoding": "task",
        "next_sleep": float(next_sleep),
        "die": bool(die),
        "command": "",
        "task": None,
    }
    if task is not None:
        payload["task"] = task.to_dict()
        payload["command"] = task.to_wire()
    return payload
