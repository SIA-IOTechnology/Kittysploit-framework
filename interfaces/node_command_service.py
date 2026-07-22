#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared cluster node command API used by ApiServer and kittyCluster."""

from __future__ import annotations

from threading import RLock
from typing import Any, Dict, List, Optional
from urllib import error, request
from urllib.parse import urlparse, urlunparse
import contextlib
import http.client
import io
import json
import re
import socket
import ssl
import time
import uuid
import xmlrpc.client

from interfaces.command_system.command_parser import split_command_line


READ_ONLY_COMMANDS = {
    "compatible_payloads",
    "doctor",
    "help",
    "history",
    "host",
    "myip",
    "search",
    "show",
    "vuln",
}

STATEFUL_SAFE_COMMANDS = {
    "back",
    "reload",
    "set",
    "use",
    "workspace",
}

DANGEROUS_COMMANDS = {
    "agent",
    "browser_server",
    "campaign",
    "check",
    "collab_connect",
    "collab_disconnect",
    "collab_edit_module",
    "collab_server",
    "collab_share_module",
    "collab_sync_edit",
    "collab_sync_module",
    "debug",
    "detection_pack",
    "edit",
    "environments",
    "generate",
    "guardian",
    "http",
    "inventory",
    "irc",
    "jobs",
    "lab",
    "listen",
    "market",
    "msf",
    "network_discover",
    "pattern",
    "plugin",
    "portal",
    "proxy",
    "reset",
    "route",
    "run",
    "scanner",
    "scope",
    "sessions",
    "shell",
    "sound",
    "sync",
    "syscall",
    "tor",
    "workflows",
}

ALWAYS_BLOCKED_COMMANDS = {
    "clear",
    "collab_chat",
    "demo",
    "exit",
    "interpreter",
    "tuto",
}


def classify_command(command_line: str) -> Dict[str, Any]:
    parts = split_command_line(command_line)
    if not parts:
        return {
            "command": command_line,
            "allowed_without_dangerous": False,
            "safety": "invalid",
            "reason": "Empty command.",
        }

    command_name = parts[0].lower()
    args = [str(arg).lower() for arg in parts[1:]]

    if command_name in ALWAYS_BLOCKED_COMMANDS:
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": False,
            "safety": "blocked",
            "reason": "Interactive or session-breaking commands are blocked from cluster execution.",
        }

    if command_name == "sessions" and any(token in args for token in ("interact", "shell")):
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": False,
            "safety": "blocked",
            "reason": "Interactive session attachment is blocked from cluster execution.",
        }

    if command_name == "workspace":
        action = args[0] if args else ""
        if action in ("list", "current", "stats", "switch"):
            return {
                "command": command_line,
                "name": command_name,
                "allowed_without_dangerous": True,
                "safety": "safe",
                "reason": "Workspace inspection or switching is allowed.",
            }
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": False,
            "safety": "dangerous",
            "reason": "Workspace creation/deletion mutates framework data.",
        }

    if command_name in READ_ONLY_COMMANDS:
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": True,
            "safety": "safe",
            "reason": "Read-only command.",
        }

    if command_name in STATEFUL_SAFE_COMMANDS:
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": True,
            "safety": "stateful",
            "reason": "Stateful but non-executing command.",
        }

    if command_name in DANGEROUS_COMMANDS:
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": False,
            "safety": "dangerous",
            "reason": "This command can execute modules, open network services, or alter the environment.",
        }

    return {
        "command": command_line,
        "name": command_name,
        "allowed_without_dangerous": False,
        "safety": "unknown",
        "reason": "Unknown command; explicit confirmation is required.",
    }


def serialize_sessions(framework: Any) -> List[Dict[str, Any]]:
    """Return active KittySploit sessions for cluster topology views."""
    sessions: List[Dict[str, Any]] = []
    manager = getattr(framework, "session_manager", None)
    if not manager or not hasattr(manager, "get_sessions"):
        return sessions
    try:
        for index, item in enumerate(manager.get_sessions() or [], start=1):
            host = str(getattr(item, "host", "") or "")
            port = int(getattr(item, "port", 0) or 0)
            session_type = str(getattr(item, "session_type", "") or "unknown")
            session_id = str(getattr(item, "id", "") or "")
            display_host = format_session_target(host, port)
            sessions.append(
                {
                    "id": session_id,
                    "short_id": short_session_id(session_id),
                    "host": host,
                    "display_host": display_host,
                    "port": port,
                    "session_type": session_type,
                    "label": f"{session_type} #{index}",
                }
            )
    except Exception:
        return []
    return sessions


def short_session_id(session_id: str, *, max_len: int = 8) -> str:
    session_id = str(session_id or "").strip()
    if len(session_id) <= max_len:
        return session_id
    return session_id[:max_len]


def format_session_target(host: str, port: int) -> str:
    """Build a short, map-safe session target label."""
    host = str(host or "").strip()
    if not host:
        return f"port {port}" if port else "unknown"

    compact = host.replace(".", "").replace(":", "").replace("-", "").replace("_", "")
    looks_like_address = (
        len(host) <= 64
        and (
            host.count(".") >= 1
            or host.startswith("[")
            or (":" in host and len(host) <= 45)
            or (compact.isalnum() and len(host) <= 32)
        )
    )
    if looks_like_address:
        return f"{host}:{port}" if port else host
    if port:
        return f"port {port}"
    return "remote"


def infer_transport(base_url: str) -> str:
    """Infer a kittyCluster node transport from its URL."""
    path = urlparse(str(base_url or "").rstrip("/")).path.lower()
    if path.endswith("/rpc2"):
        return "rpc"
    return "api"


class RelayRemoteClientError(RuntimeError):
    """Raised when a relay target cannot be reached or parsed."""


class RelayRemoteClient:
    """Small shared client used by relay nodes to contact final targets."""

    def status(
        self,
        base_url: str,
        *,
        token: str = "",
        transport: Optional[str] = None,
        tls_no_verify: bool = False,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        mode = transport or infer_transport(base_url)
        if mode == "rpc":
            return self._rpc_status(base_url, token=token, tls_no_verify=tls_no_verify, timeout=timeout)
        return self._json_request(
            "GET",
            f"{base_url.rstrip('/')}/api/node/status",
            token=token,
            tls_no_verify=tls_no_verify,
            timeout=timeout,
        )

    def execute_command(
        self,
        base_url: str,
        *,
        token: str,
        transport: Optional[str] = None,
        command: str,
        tls_no_verify: bool = False,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        mode = transport or infer_transport(base_url)
        if mode == "rpc":
            return self._rpc_execute_command(
                base_url,
                token=token,
                command=command,
                tls_no_verify=tls_no_verify,
                timeout=timeout,
            )
        return self._json_request(
            "POST",
            f"{base_url.rstrip('/')}/api/node/command",
            token=token,
            payload={"command": command, "timeout_seconds": timeout},
            tls_no_verify=tls_no_verify,
            timeout=timeout,
        )

    def _json_request(
        self,
        method: str,
        url: str,
        *,
        token: str = "",
        payload: Optional[Dict[str, Any]] = None,
        tls_no_verify: bool = False,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-API-Key"] = token

        req = request.Request(url, data=body, headers=headers, method=method.upper())
        context = None
        if str(url).lower().startswith("https://") and tls_no_verify:
            context = ssl._create_unverified_context()
        try:
            with request.urlopen(req, timeout=max(1.0, float(timeout)), context=context) as response:
                raw = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
                if not raw:
                    return {}
                return json.loads(raw)
        except error.HTTPError as exc:
            detail = exc.read(8192).decode("utf-8", errors="replace")
            raise RelayRemoteClientError(f"HTTP {exc.code} from {url}: {detail or exc.reason}") from exc
        except error.URLError as exc:
            raise RelayRemoteClientError(f"Cannot reach {url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RelayRemoteClientError(f"Timeout while contacting {url}") from exc
        except json.JSONDecodeError as exc:
            raise RelayRemoteClientError(f"Invalid JSON response from {url}") from exc
        except Exception as exc:
            raise RelayRemoteClientError(f"Remote request failed for {url}: {exc}") from exc

    def _rpc_status(
        self,
        base_url: str,
        *,
        token: str = "",
        tls_no_verify: bool = False,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        proxy = self._rpc_proxy(base_url, token=token, tls_no_verify=tls_no_verify, timeout=timeout)
        try:
            health = proxy.health(True)
        except Exception as exc:
            raise RelayRemoteClientError(f"RPC health failed for {base_url}: {exc}") from exc
        status = str(health.get("status") or "").lower()
        sessions: List[Dict[str, Any]] = []
        try:
            raw_sessions = proxy.get_sessions()
            if isinstance(raw_sessions, list):
                sessions = [item for item in raw_sessions if isinstance(item, dict)]
        except Exception:
            sessions = []
        return {
            "status": "online" if status in {"healthy", "ok", "online"} else status or "unknown",
            "version": health.get("version"),
            "service": health.get("service", "kittysploit-rpc"),
            "runtime_kernel": health.get("runtime_kernel"),
            "interpreter": health.get("interpreter"),
            "sessions_count": len(sessions),
            "sessions": sessions,
            "raw": health,
        }

    def _rpc_execute_command(
        self,
        base_url: str,
        *,
        token: str,
        command: str,
        tls_no_verify: bool = False,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        safety = classify_command(command)
        if safety["safety"] == "blocked":
            return {"status": "blocked", "command": command, "success": False, "safety": safety}

        proxy = self._rpc_proxy(base_url, token=token, tls_no_verify=tls_no_verify, timeout=timeout)
        code = self._rpc_command_code(command)
        try:
            response = proxy.execute_interpreter(code, "kittycluster")
        except Exception as exc:
            raise RelayRemoteClientError(f"RPC command failed for {base_url}: {exc}") from exc
        if not isinstance(response, dict):
            raise RelayRemoteClientError(f"Unexpected RPC response from {base_url}")
        if response.get("error") and not response.get("output"):
            return {
                "status": "failed",
                "command": command,
                "success": False,
                "stderr": response.get("error"),
                "safety": safety,
            }
        return self._parse_rpc_command_response(command, response, safety)

    def _rpc_proxy(
        self,
        base_url: str,
        *,
        token: str = "",
        tls_no_verify: bool = False,
        timeout: float = 8.0,
    ) -> xmlrpc.client.ServerProxy:
        url = self._rpc_endpoint(base_url)
        parsed = urlparse(url)
        transport_cls = _RelayHttpsAuthTransport if parsed.scheme == "https" else _RelayHttpAuthTransport
        transport = transport_cls(
            token=token,
            timeout=max(1.0, float(timeout)),
            tls_no_verify=tls_no_verify,
        )
        return xmlrpc.client.ServerProxy(url, transport=transport, allow_none=True)

    @staticmethod
    def _rpc_endpoint(base_url: str) -> str:
        parsed = urlparse(str(base_url or "").rstrip("/"))
        path = parsed.path
        if not path or path == "/":
            path = "/RPC2"
        return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

    @staticmethod
    def _rpc_command_code(command: str) -> str:
        command_literal = repr(str(command or ""))
        return f"""
import contextlib
import io
import json
import time
from interfaces.command_system.command_parser import split_command_line

_command_line = {command_literal}
_stdout = io.StringIO()
_stderr = io.StringIO()
_started = time.monotonic()
try:
    _parts = split_command_line(_command_line)
    if not _parts:
        _payload = {{"status": "error", "success": False, "command": _command_line, "error": "Empty command."}}
    else:
        _registry = globals().get("_kittycluster_command_registry")
        if _registry is None:
            from core.output_handler import OutputHandler
            from core.session import Session
            from interfaces.command_system.command_registry import CommandRegistry
            _registry = CommandRegistry(framework, Session(), OutputHandler())
            globals()["_kittycluster_command_registry"] = _registry
        with contextlib.redirect_stdout(_stdout), contextlib.redirect_stderr(_stderr):
            _success = bool(_registry.execute_command(_parts[0], _parts[1:], framework=framework))
        _payload = {{
            "status": "ok" if _success else "failed",
            "success": _success,
            "command": _command_line,
            "stdout": _stdout.getvalue() or None,
            "stderr": _stderr.getvalue() or None,
            "elapsed_ms": round((time.monotonic() - _started) * 1000.0, 2),
        }}
except Exception as _exc:
    _payload = {{
        "status": "failed",
        "success": False,
        "command": _command_line,
        "stdout": _stdout.getvalue() or None,
        "stderr": (_stderr.getvalue() or "") + str(_exc),
        "elapsed_ms": round((time.monotonic() - _started) * 1000.0, 2),
    }}
print("__KITTYCLUSTER_RESULT__=" + json.dumps(_payload, sort_keys=True))
"""

    @staticmethod
    def _parse_rpc_command_response(command: str, response: Dict[str, Any], safety: Dict[str, Any]) -> Dict[str, Any]:
        output = str(response.get("output") or "")
        matches = re.findall(r"__KITTYCLUSTER_RESULT__=(\{.*\})", output)
        if not matches:
            return {
                "status": "failed",
                "command": command,
                "success": False,
                "stdout": output or None,
                "stderr": response.get("error"),
                "safety": safety,
            }
        try:
            payload = json.loads(matches[-1])
        except json.JSONDecodeError as exc:
            raise RelayRemoteClientError("Invalid RPC command payload") from exc
        payload["safety"] = safety
        return payload


class _RelayHttpAuthTransport(xmlrpc.client.Transport):
    def __init__(self, *, token: str = "", timeout: float = 8.0, tls_no_verify: bool = False):
        super().__init__()
        self.token = token
        self.timeout = timeout
        self.tls_no_verify = bool(tls_no_verify)

    def make_connection(self, host):
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        chost, self._extra_headers, _x509 = self.get_host_info(host)
        self._connection = host, http.client.HTTPConnection(chost, timeout=self.timeout)
        return self._connection[1]

    def send_headers(self, connection, headers):
        headers = list(headers)
        if self.token:
            headers.append(("Authorization", f"Bearer {self.token}"))
            headers.append(("X-API-Key", self.token))
        super().send_headers(connection, headers)


class _RelayHttpsAuthTransport(_RelayHttpAuthTransport, xmlrpc.client.SafeTransport):
    def make_connection(self, host):
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        chost, self._extra_headers, _x509 = self.get_host_info(host)
        context = None
        if self.tls_no_verify:
            context = ssl._create_unverified_context()
        self._connection = host, http.client.HTTPSConnection(chost, timeout=self.timeout, context=context)
        return self._connection[1]


class RelayService:
    """Forward cluster status/command calls from a relay node to an explicit target."""

    def __init__(self, remote_client: Optional[Any] = None):
        self.remote_client = remote_client or RelayRemoteClient()

    def relay_status(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = self._target_from_payload(payload, default_timeout=8.0)
        return self.remote_client.status(
            target["url"],
            token=target["token"],
            transport=infer_transport(target["url"]),
            tls_no_verify=target["tls_no_verify"],
            timeout=target["timeout"],
        )

    def relay_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = self._target_from_payload(payload, default_timeout=30.0)
        command = str((payload or {}).get("command") or "").strip()
        if not command:
            raise ValueError("command is required.")
        return self.remote_client.execute_command(
            target["url"],
            token=target["token"],
            transport=infer_transport(target["url"]),
            command=command,
            tls_no_verify=target["tls_no_verify"],
            timeout=target["timeout"],
        )

    def _target_from_payload(self, payload: Dict[str, Any], *, default_timeout: float) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("relay payload must be an object.")
        target_url = self._clean_target_url(str(payload.get("target_url") or ""))
        timeout = payload.get("timeout_seconds", default_timeout)
        try:
            timeout_value = max(1.0, float(timeout))
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout_seconds must be a number.") from exc
        return {
            "url": target_url,
            "token": str(payload.get("target_token") or ""),
            "tls_no_verify": bool(payload.get("target_tls_no_verify", False)),
            "timeout": timeout_value,
        }

    @staticmethod
    def _clean_target_url(value: str) -> str:
        value = str(value or "").strip().rstrip("/")
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target_url must be an absolute http(s) URL.")
        return value


class NodeCommandService:
    """Execute KittySploit CLI commands for remote cluster control."""

    def __init__(self, framework: Any, *, enabled: bool = True, node_name: Optional[str] = None, node_role: str = "slave"):
        self.framework = framework
        self.enabled = bool(enabled)
        self.node_name = node_name or socket.gethostname()
        self.node_role = node_role
        self.node_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"kittysploit-node:{self.node_name}").hex
        self._registry = None
        self._lock = RLock()

    def status(self) -> Dict[str, Any]:
        workspace_name = None
        try:
            workspace = self.framework.workspace_manager.get_current_workspace()
            workspace_name = getattr(workspace, "name", None) or str(workspace)
        except Exception:
            workspace_name = None

        active_sessions = serialize_sessions(self.framework)
        sessions_count = len(active_sessions)

        modules_count = 0
        try:
            modules_count = len(getattr(self.framework.module_loader, "modules", {}) or {})
        except Exception:
            modules_count = 0

        return {
            "id": self.node_id,
            "name": self.node_name,
            "role": self.node_role,
            "status": "online",
            "node_status": "online",
            "version": getattr(self.framework, "version", None),
            "framework_version": getattr(self.framework, "version", None),
            "workspace": workspace_name,
            "sessions_count": sessions_count,
            "sessions": active_sessions,
            "modules_count": modules_count,
            "command_execution": self.enabled,
        }

    def execute(self, command_line: str) -> Dict[str, Any]:
        command_line = str(command_line or "").strip()
        safety = classify_command(command_line)

        if not self.enabled:
            return {
                "status": "disabled",
                "command": command_line,
                "success": False,
                "safety": safety,
                "error": "Remote command execution is disabled on this node.",
            }

        if safety["safety"] == "blocked":
            return {
                "status": "blocked",
                "command": command_line,
                "success": False,
                "safety": safety,
            }

        parts = split_command_line(command_line)
        if not parts:
            return {
                "status": "error",
                "command": command_line,
                "success": False,
                "safety": safety,
                "error": "Empty command.",
            }

        stdout = io.StringIO()
        stderr = io.StringIO()
        started = time.monotonic()
        with self._lock:
            registry = self._ensure_registry()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                success = bool(registry.execute_command(parts[0], parts[1:], framework=self.framework))

        return {
            "status": "ok" if success else "failed",
            "command": command_line,
            "success": success,
            "stdout": stdout.getvalue() or None,
            "stderr": stderr.getvalue() or None,
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 2),
            "safety": safety,
        }

    def _ensure_registry(self):
        if self._registry is None:
            from core.output_handler import OutputHandler
            from core.session import Session
            from interfaces.command_system.command_registry import CommandRegistry

            self._registry = CommandRegistry(self.framework, Session(), OutputHandler())
        return self._registry
