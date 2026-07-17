#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Session-scoped root elevation for Unix shell / SSH post execution.

Post modules run via fresh exec channels (SSH) or non-elevated reverse shells.
When ``session.data['root_elevate']`` is set, commands are wrapped with sudo so
subsequent post modules effectively run as root.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, Optional

ROOT_ELEVATE_FLAG = "root_elevate"
ROOT_ELEVATE_METHOD = "root_elevate_method"
ROOT_ELEVATE_PASSWORD = "root_elevate_password"

METHOD_NATIVE = "native"
METHOD_SUDO_NOPASSWD = "sudo_nopasswd"
METHOD_SUDO_PASSWORD = "sudo_password"

_WRAP_MARKERS = (
    "sudo -n -- ",
    "sudo -S -p '' -- ",
    'sudo -S -p "" -- ',
)


def get_session_data(framework, session_id: str) -> Dict[str, Any]:
    if not framework or not session_id:
        return {}
    sm = getattr(framework, "session_manager", None)
    if not sm:
        return {}
    session = sm.get_session(str(session_id))
    if not session:
        return {}
    data = getattr(session, "data", None)
    return data if isinstance(data, dict) else {}


def get_root_elevate_config(framework, session_id: str) -> Optional[Dict[str, Any]]:
    data = get_session_data(framework, session_id)
    if not data.get(ROOT_ELEVATE_FLAG):
        return None
    method = str(data.get(ROOT_ELEVATE_METHOD) or METHOD_SUDO_NOPASSWD).strip().lower()
    if method not in (METHOD_NATIVE, METHOD_SUDO_NOPASSWD, METHOD_SUDO_PASSWORD):
        method = METHOD_SUDO_NOPASSWD
    return {
        "enabled": True,
        "method": method,
        "password": str(data.get(ROOT_ELEVATE_PASSWORD) or ""),
    }


def parse_uid_output(output: str) -> str:
    """Extract a numeric uid from command output (id -u or full id)."""
    text = output or ""
    for line in text.splitlines():
        line = line.strip()
        if line.isdigit():
            return line
    match = re.search(r"\buid=(\d+)\b", text)
    if match:
        return match.group(1)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def is_root_uid_output(output: str) -> bool:
    return parse_uid_output(output) == "0"


def wrap_command_for_root(command: str, config: Optional[Dict[str, Any]]) -> str:
    """Wrap a Unix shell command so it runs as root when elevation is enabled."""
    cmd = (command or "").strip()
    if not cmd or not config or not config.get("enabled"):
        return command

    method = str(config.get("method") or METHOD_SUDO_NOPASSWD).lower()
    if method == METHOD_NATIVE:
        return command

    # Avoid double-wrapping
    if any(marker in cmd for marker in _WRAP_MARKERS):
        return command

    # shlex.quote avoids nested-quote breakage (e.g. cd '/path' inside sh -c '...')
    quoted = shlex.quote(cmd)
    if method == METHOD_SUDO_PASSWORD:
        password = str(config.get("password") or "")
        return (
            f"printf '%s\\n' {shlex.quote(password)} | "
            f"sudo -S -p '' -- sh -c {quoted}"
        )
    return f"sudo -n -- sh -c {quoted}"


def apply_root_elevate(framework, session_id: str, command: str) -> str:
    return wrap_command_for_root(command, get_root_elevate_config(framework, session_id))


def interactive_elevate_plan(config: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Plan for elevating a stateful interactive PTY to root.

    Returns None if no elevation is needed, otherwise:
      {"lines": [...], "method": str, "verify": "id -u"}
    """
    if not config or not config.get("enabled"):
        return None
    method = str(config.get("method") or METHOD_SUDO_NOPASSWD).lower()
    if method == METHOD_NATIVE:
        return None
    if method == METHOD_SUDO_PASSWORD:
        password = str(config.get("password") or "")
        if not password:
            return None
        # sudo -S reads password from stdin; -i gives a root login shell.
        return {
            "method": method,
            "lines": [
                "sudo -S -p '' -i",
                password,
            ],
            "verify": "id -u",
        }
    return {
        "method": method,
        "lines": ["sudo -n -i"],
        "verify": "id -u",
    }
