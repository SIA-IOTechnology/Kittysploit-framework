#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Stable Linux/Windows host primitives for identity, privilege, environment, and paths."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Literal, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.redaction import redact_text

SCHEMA_VERSION = "1.0"

Platform = Literal["linux", "windows", "unknown"]
PrimitiveCategory = Literal["identity", "privilege", "environment", "paths", "neutral"]

WINDOWS_SESSION_TYPES = frozenset({"winrm", "smb"})
COMMAND_SESSION_TYPES = frozenset({
    "standard",
    "shell",
    "meterpreter",
    "ssh",
    "php",
    "http",
    "https",
    "android",
    "winrm",
    "smb",
})

PRIVILEGE_ORDER: Tuple[str, ...] = ("user", "admin", "root", "system")


@dataclass(frozen=True)
class HostPrimitiveDef:
    id: str
    category: PrimitiveCategory
    linux: str
    windows: str
    fallback: str = ""
    description: str = ""


HOST_PRIMITIVES: Dict[str, HostPrimitiveDef] = {
    "neutral.verify": HostPrimitiveDef(
        id="neutral.verify",
        category="neutral",
        linux="id 2>/dev/null || whoami",
        windows="whoami",
        fallback="id 2>/dev/null || whoami",
        description="Neutral session liveness and identity proof.",
    ),
    "identity.current_user": HostPrimitiveDef(
        id="identity.current_user",
        category="identity",
        linux="id 2>/dev/null || whoami",
        windows="whoami",
        fallback="id 2>/dev/null || whoami",
        description="Effective user identity (id output or whoami).",
    ),
    "identity.username": HostPrimitiveDef(
        id="identity.username",
        category="identity",
        linux="whoami 2>/dev/null",
        windows="echo %USERNAME%",
        fallback="whoami 2>/dev/null || echo %USERNAME%",
        description="Short username without domain context.",
    ),
    "identity.hostname": HostPrimitiveDef(
        id="identity.hostname",
        category="identity",
        linux="hostname 2>/dev/null",
        windows="echo %COMPUTERNAME%",
        fallback="hostname 2>/dev/null || echo %COMPUTERNAME%",
        description="Local hostname.",
    ),
    "identity.domain": HostPrimitiveDef(
        id="identity.domain",
        category="identity",
        linux="dnsdomainname 2>/dev/null || domainname -A 2>/dev/null | head -1",
        windows="echo %USERDOMAIN%",
        fallback="echo %USERDOMAIN%",
        description="Domain or realm when available.",
    ),
    "privilege.id_output": HostPrimitiveDef(
        id="privilege.id_output",
        category="privilege",
        linux="id 2>/dev/null",
        windows="whoami /groups 2>nul & whoami /priv 2>nul & whoami",
        fallback="id 2>/dev/null || whoami",
        description="Raw privilege-bearing identity output.",
    ),
    "environment.os_info": HostPrimitiveDef(
        id="environment.os_info",
        category="environment",
        linux="uname -a 2>/dev/null",
        windows="ver",
        fallback="uname -a 2>/dev/null || ver",
        description="Operating system fingerprint.",
    ),
    "environment.architecture": HostPrimitiveDef(
        id="environment.architecture",
        category="environment",
        linux="uname -m 2>/dev/null",
        windows="echo %PROCESSOR_ARCHITECTURE%",
        fallback="uname -m 2>/dev/null || echo %PROCESSOR_ARCHITECTURE%",
        description="CPU architecture.",
    ),
    "environment.shell": HostPrimitiveDef(
        id="environment.shell",
        category="environment",
        linux="echo $SHELL",
        windows="echo %COMSPEC%",
        fallback="echo $SHELL 2>/dev/null || echo %COMSPEC%",
        description="Default shell or command interpreter.",
    ),
    "environment.home": HostPrimitiveDef(
        id="environment.home",
        category="environment",
        linux="echo $HOME",
        windows="echo %USERPROFILE%",
        fallback="echo $HOME 2>/dev/null || echo %USERPROFILE%",
        description="User home directory.",
    ),
    "environment.network_interfaces": HostPrimitiveDef(
        id="environment.network_interfaces",
        category="environment",
        linux="ip addr 2>/dev/null || ifconfig 2>/dev/null",
        windows="ipconfig",
        fallback="ip addr 2>/dev/null || ifconfig 2>/dev/null || ipconfig",
        description="Local network interface summary.",
    ),
    "paths.cwd": HostPrimitiveDef(
        id="paths.cwd",
        category="paths",
        linux="pwd 2>/dev/null",
        windows="cd",
        fallback="pwd 2>/dev/null || cd",
        description="Current working directory.",
    ),
    "paths.temp": HostPrimitiveDef(
        id="paths.temp",
        category="paths",
        linux="echo ${TMPDIR:-/tmp}",
        windows="echo %TEMP%",
        fallback="echo ${TMPDIR:-/tmp} 2>/dev/null || echo %TEMP%",
        description="Writable temp directory.",
    ),
    "paths.system_root": HostPrimitiveDef(
        id="paths.system_root",
        category="paths",
        linux="echo /",
        windows="echo %SystemRoot%",
        fallback="echo / 2>/dev/null || echo %SystemRoot%",
        description="System root path.",
    ),
}

INVENTORY_PRIMITIVE_IDS: Tuple[str, ...] = (
    "environment.os_info",
    "identity.current_user",
    "identity.hostname",
    "environment.network_interfaces",
    "paths.cwd",
)

LEGACY_INVENTORY_KEYS: Dict[str, str] = {
    "environment.os_info": "os_info",
    "identity.current_user": "current_user",
    "identity.hostname": "hostname",
    "environment.network_interfaces": "network_interfaces",
    "paths.cwd": "cwd",
}


def infer_platform(*, session_type: str = "", os_hint: str = "") -> Platform:
    token = str(session_type or "").strip().lower()
    if token in WINDOWS_SESSION_TYPES or "win" in token:
        return "windows"
    hint = str(os_hint or "").strip().lower()
    if any(marker in hint for marker in ("windows", "microsoft", "win32", "win64")):
        return "windows"
    if any(marker in hint for marker in ("linux", "darwin", "freebsd", "unix", "gnu")):
        return "linux"
    if token in {"ssh", "meterpreter", "shell", "standard", "php"}:
        return "linux"
    return "unknown"


def primitive_def(primitive_id: str) -> HostPrimitiveDef:
    key = str(primitive_id or "").strip()
    if key not in HOST_PRIMITIVES:
        raise KeyError(f"unknown host primitive: {key}")
    return HOST_PRIMITIVES[key]


def command_for(primitive_id: str, platform: Platform = "unknown") -> str:
    spec = primitive_def(primitive_id)
    if platform == "linux":
        return spec.linux
    if platform == "windows":
        return spec.windows
    return spec.fallback or spec.linux


def neutral_verify_command(session_type: str = "") -> str:
    platform = infer_platform(session_type=session_type)
    return command_for("neutral.verify", platform)


def parse_privilege_from_id_output(output: str) -> str:
    text = str(output or "").strip().lower()
    if not text:
        return "user"
    if "uid=0" in text or "root@" in text or "(root)" in text:
        return "root"
    if "nt authority\\system" in text or " mandatory label\\system mandatory level" in text:
        return "system"
    if "administrator" in text or " admin " in f" {text} " or "builtin\\administrators" in text:
        return "admin"
    return "user"


def privilege_meets(actual: str, expected: str) -> bool:
    actual_norm = str(actual or "user").strip().lower() or "user"
    expected_norm = str(expected or "user").strip().lower() or "user"
    try:
        actual_rank = PRIVILEGE_ORDER.index(actual_norm)
    except ValueError:
        actual_rank = 0
    try:
        expected_rank = PRIVILEGE_ORDER.index(expected_norm)
    except ValueError:
        expected_rank = 0
    return actual_rank >= expected_rank


def _normalize_path(raw: str, *, platform: Platform) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if platform == "windows":
        match = re.search(r"[A-Za-z]:\\[^\r\n>]*", text)
        if match:
            return match.group(0).rstrip("\\")
    first = text.splitlines()[0].strip()
    return first.strip(">")


def parse_primitive_output(
    primitive_id: str,
    output: str,
    *,
    platform: Platform = "unknown",
) -> Any:
    text = str(output or "").strip()
    if primitive_id in {"identity.current_user", "privilege.id_output", "neutral.verify"}:
        return {
            "raw": text,
            "privilege_level": parse_privilege_from_id_output(text),
        }
    if primitive_id == "identity.username":
        if "\\" in text:
            return text.split("\\", 1)[-1].strip()
        return text.splitlines()[0].strip() if text else ""
    if primitive_id == "identity.hostname":
        return text.splitlines()[0].strip() if text else ""
    if primitive_id == "paths.cwd":
        return _normalize_path(text, platform=platform)
    if primitive_id.startswith("environment.") or primitive_id.startswith("paths."):
        return text.splitlines()[0].strip() if text else text
    return text


@dataclass
class PrimitiveResult:
    primitive_id: str
    category: str
    command: str
    platform: Platform
    raw_output: str = ""
    parsed: Any = None
    ok: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primitive_id": self.primitive_id,
            "category": self.category,
            "command": self.command,
            "platform": self.platform,
            "raw_output": redact_text(self.raw_output, 4000),
            "parsed": self.parsed,
            "ok": self.ok,
            "error": self.error,
        }


def _extract_output(result: Any) -> str:
    if isinstance(result, dict):
        for key in ("output", "stdout", "message", "result"):
            value = result.get(key)
            if value is not None and str(value).strip():
                return str(value)
    return str(result or "")


class HostPrimitiveRunner:
    """Execute stable host primitives on an active session."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def supports_command_session(self, session_id: str) -> bool:
        manager = getattr(self.framework, "session_manager", None)
        if manager is None or str(session_id) in getattr(manager, "browser_sessions", {}):
            return False
        session = manager.get_session(str(session_id))
        if not session:
            return False
        session_type = str(getattr(session, "session_type", "") or "").lower()
        shell_manager = getattr(self.framework, "shell_manager", None)
        if shell_manager is not None and hasattr(shell_manager, "execute_command"):
            return not session_type or session_type in COMMAND_SESSION_TYPES
        executor = getattr(session, "execute_command", None) or getattr(session, "cmd_exec", None)
        return callable(executor) and (not session_type or session_type in COMMAND_SESSION_TYPES)

    def session_platform(self, session_id: str, *, os_hint: str = "") -> Platform:
        manager = getattr(self.framework, "session_manager", None)
        session = manager.get_session(str(session_id)) if manager is not None else None
        session_type = str(getattr(session, "session_type", "") or "").lower() if session else ""
        return infer_platform(session_type=session_type, os_hint=os_hint)

    def execute_command(self, session_id: str, command: str) -> str:
        shell_manager = getattr(self.framework, "shell_manager", None)
        if shell_manager is not None and hasattr(shell_manager, "execute_command"):
            result = shell_manager.execute_command(str(session_id), command, framework=self.framework)
            return _extract_output(result)
        manager = getattr(self.framework, "session_manager", None)
        session = manager.get_session(str(session_id)) if manager is not None else None
        if session is None:
            return ""
        executor = getattr(session, "execute_command", None) or getattr(session, "cmd_exec", None)
        if not callable(executor):
            return ""
        return _extract_output(executor(command))

    def run(
        self,
        session_id: str,
        primitive_id: str,
        *,
        platform: Optional[Platform] = None,
        os_hint: str = "",
    ) -> PrimitiveResult:
        spec = primitive_def(primitive_id)
        resolved_platform = platform or self.session_platform(session_id, os_hint=os_hint)
        command = command_for(primitive_id, resolved_platform)
        result = PrimitiveResult(
            primitive_id=primitive_id,
            category=spec.category,
            command=command,
            platform=resolved_platform,
        )
        if not self.supports_command_session(session_id):
            result.error = "session_unsupported"
            return result
        try:
            raw = self.execute_command(session_id, command)
            result.raw_output = raw
            result.parsed = parse_primitive_output(primitive_id, raw, platform=resolved_platform)
            result.ok = bool(str(raw).strip()) and str(raw).strip() != "error"
        except Exception as exc:
            result.error = str(exc)
        return result

    def run_many(
        self,
        session_id: str,
        primitive_ids: Sequence[str],
        *,
        platform: Optional[Platform] = None,
        os_hint: str = "",
    ) -> Dict[str, PrimitiveResult]:
        resolved_platform = platform or self.session_platform(session_id, os_hint=os_hint)
        return {
            pid: self.run(session_id, pid, platform=resolved_platform, os_hint=os_hint)
            for pid in primitive_ids
        }

    def collect_inventory(
        self,
        session_id: str,
        *,
        platform: Optional[Platform] = None,
        os_hint: str = "",
    ) -> Dict[str, Any]:
        results = self.run_many(session_id, INVENTORY_PRIMITIVE_IDS, platform=platform, os_hint=os_hint)
        legacy: Dict[str, Any] = {}
        for primitive_id, legacy_key in LEGACY_INVENTORY_KEYS.items():
            item = results.get(primitive_id)
            if item is None:
                continue
            legacy[legacy_key] = redact_text(str(item.raw_output).strip(), 4000) if item.ok else "error"
        return legacy

    def snapshot_to_kb(
        self,
        session_id: str,
        kb: MutableMapping[str, Any],
        *,
        platform: Optional[Platform] = None,
        os_hint: str = "",
    ) -> Dict[str, Any]:
        bundle = self.run_many(
            session_id,
            tuple(HOST_PRIMITIVES.keys()),
            platform=platform,
            os_hint=os_hint,
        )
        store = kb.setdefault("host_primitives", {})
        if not isinstance(store, dict):
            store = {}
            kb["host_primitives"] = store
        session_store = {
            pid: result.to_dict()
            for pid, result in bundle.items()
        }
        store[str(session_id)] = session_store
        if bundle.get("identity.current_user") and bundle["identity.current_user"].ok:
            parsed = bundle["identity.current_user"].parsed
            if isinstance(parsed, dict):
                kb["privilege_level"] = parsed.get("privilege_level", "user")
        return session_store
