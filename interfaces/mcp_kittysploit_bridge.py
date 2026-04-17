#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helpers for KittySploit's MCP bridge.

This module adds two layers on top of the low-level RPC tools:

1. A natural-language planner that extracts intent, targets, likely modules, and
   option hints from free-form requests.
2. A command bridge that exposes the framework's native command registry to MCP
   clients with basic safety guardrails.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shlex
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from urllib.parse import urlparse

from core.framework.option.base_option import Option as BaseOption
from core.utils.module_static_metadata import (
    extract_module_search_metadata,
    infer_module_type_from_path,
)


STOPWORDS = {
    "a",
    "an",
    "and",
    "against",
    "all",
    "au",
    "avec",
    "ce",
    "cet",
    "cette",
    "comment",
    "de",
    "des",
    "do",
    "does",
    "donc",
    "du",
    "find",
    "for",
    "from",
    "get",
    "give",
    "help",
    "how",
    "i",
    "il",
    "in",
    "into",
    "je",
    "la",
    "le",
    "les",
    "list",
    "manner",
    "maniere",
    "me",
    "module",
    "modules",
    "mon",
    "natural",
    "naturelle",
    "naturally",
    "need",
    "nous",
    "on",
    "or",
    "our",
    "pour",
    "please",
    "possible",
    "quiet",
    "discreet",
    "stealth",
    "stealthy",
    "aggressive",
    "run",
    "execute",
    "launch",
    "start",
    "show",
    "sur",
    "task",
    "that",
    "the",
    "this",
    "to",
    "tool",
    "tools",
    "un",
    "une",
    "use",
    "using",
    "veux",
    "want",
    "with",
}

GENERAL_INFO_TOKENS = (
    "explique",
    "explain",
    "overview",
    "what is",
    "what's",
    "c'est quoi",
    "présentation",
    "presentation",
    "presente",
    "présente",
    "framework",
    "kittysploit",
    "comment fonctionne",
    "how it works",
)

MODULE_TYPE_ALIASES = {
    "aux": "auxiliary",
    "auxiliary": "auxiliary",
    "backdoor": "backdoors",
    "backdoors": "backdoors",
    "browser": "browser_exploits",
    "docker": "docker_environment",
    "environment": "docker_environment",
    "environments": "docker_environment",
    "encoder": "encoders",
    "encoders": "encoders",
    "exploit": "exploits",
    "exploits": "exploits",
    "listener": "listeners",
    "listeners": "listeners",
    "nop": "nops",
    "nops": "nops",
    "obfuscator": "obfuscator",
    "obfuscators": "obfuscator",
    "payload": "payloads",
    "payloads": "payloads",
    "post": "post",
    "recon": "scanner",
    "scan": "scanner",
    "scanner": "scanner",
    "shortcut": "shortcut",
    "shortcuts": "shortcut",
    "workflow": "workflow",
    "workflows": "workflow",
}

FAMILY_HINTS = {
    "agent": "scanner",
    "auth bypass": "exploits",
    "bruteforce": "auxiliary",
    "cms": "scanner",
    "csrf": "browser_auxiliary",
    "dns": "scanner",
    "enum": "scanner",
    "enumerate": "scanner",
    "exploit": "exploits",
    "fingerprint": "scanner",
    "fuzz": "auxiliary",
    "generate payload": "payloads",
    "handler": "listeners",
    "http": "scanner",
    "inject": "exploits",
    "listener": "listeners",
    "lfi": "scanner",
    "payload": "payloads",
    "pivot": "post",
    "post": "post",
    "privesc": "post",
    "privilege escalation": "post",
    "rce": "exploits",
    "recon": "scanner",
    "reverse shell": "payloads",
    "scan": "scanner",
    "session": "post",
    "shell": "post",
    "sql injection": "scanner",
    "sqli": "scanner",
    "xss": "scanner",
}

KEYWORD_EXPANSIONS = {
    "wordpress": ["wordpress", "wp"],
    "woocommerce": ["woocommerce", "wordpress"],
    "sqli": ["sqli", "sql", "sql_injection"],
    "sql": ["sql", "sqli", "database"],
    "xss": ["xss", "cross_site_scripting"],
    "csrf": ["csrf", "cross_site_request_forgery"],
    "lfi": ["lfi", "file_inclusion"],
    "rce": ["rce", "command", "shell"],
    "ssh": ["ssh"],
    "smb": ["smb"],
    "ftp": ["ftp"],
    "http": ["http", "https", "web"],
    "https": ["https", "http", "web"],
    "cloud": ["cloud", "aws", "azure", "gcp", "kubernetes"],
    "aws": ["aws", "s3", "iam", "ec2", "cloud"],
    "azure": ["azure", "blob", "cloud"],
    "gcp": ["gcp", "google", "cloud"],
    "k8s": ["k8s", "kubernetes", "cluster"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "grafana": ["grafana"],
    "jenkins": ["jenkins"],
    "tomcat": ["tomcat"],
    "telecom": ["telecom", "diameter", "gtp", "pfcp"],
    "ldap": ["ldap", "active_directory", "ad"],
    "osint": ["osint", "whois", "dns"],
}

READ_ONLY_COMMANDS = {
    "banner",
    "compatible_payloads",
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
    "check",
    "collab_connect",
    "collab_disconnect",
    "collab_edit_module",
    "collab_server",
    "collab_share_module",
    "collab_sync_edit",
    "collab_sync_module",
    "debug",
    "edit",
    "environments",
    "generate",
    "guardian",
    "irc",
    "jobs",
    "market",
    "pattern",
    "plugin",
    "portal",
    "proxy",
    "reset",
    "run",
    "scanner",
    "sessions",
    "shell",
    "sound",
    "syscall",
    "tor",
}

ALWAYS_BLOCKED_COMMANDS = {
    "clear",
    "collab_chat",
    "demo",
    "exit",
    "interpreter",
    "tuto",
}

KNOWN_COMMANDS = READ_ONLY_COMMANDS | STATEFUL_SAFE_COMMANDS | DANGEROUS_COMMANDS | ALWAYS_BLOCKED_COMMANDS

NATURAL_FILLER_TOKENS = {
    "a",
    "an",
    "the",
    "please",
    "me",
    "my",
    "some",
    "une",
    "un",
    "le",
    "la",
    "les",
    "mon",
    "ma",
}

OPTION_ROLE_HINTS = (
    ("password", "password"),
    ("passwd", "password"),
    ("secret", "password"),
    ("token", "token"),
    ("username", "username"),
    ("user", "username"),
    ("login", "username"),
    ("cookie", "cookie"),
    ("session", "session"),
    ("lhost", "local_host"),
    ("lport", "local_port"),
    ("rhost", "target_host"),
    ("rhosts", "target_host"),
    ("rport", "target_port"),
    ("host", "target_host"),
    ("domain", "target_host"),
    ("hostname", "target_host"),
    ("target", "target"),
    ("url", "target_url"),
    ("uri", "target_url"),
    ("endpoint", "target_url"),
    ("base", "target_url"),
    ("port", "target_port"),
    ("ssl", "ssl_flag"),
    ("https", "ssl_flag"),
    ("payload", "payload"),
    ("wordlist", "wordlist"),
    ("file", "file"),
    ("path", "path"),
    ("threads", "threads"),
    ("timeout", "timeout"),
)

EXPLICIT_VALUE_PATTERNS = (
    ("username", re.compile(r"\b(?:username|user|login)\s*[:=]?\s*([^\s,;]+)", re.I)),
    ("password", re.compile(r"\b(?:password|pass|secret)\s*[:=]?\s*([^\s,;]+)", re.I)),
    ("rhost", re.compile(r"\b(?:rhost|target|host|ip)\s*[:=]?\s*([^\s,;]+)", re.I)),
    ("rport", re.compile(r"\b(?:rport|port)\s*[:=]?\s*(\d{1,5})\b", re.I)),
    ("lhost", re.compile(r"\b(?:lhost|callback|connect\s+back\s+to)\s*[:=]?\s*([^\s,;]+)", re.I)),
    ("lport", re.compile(r"\b(?:lport)\s*[:=]?\s*(\d{1,5})\b", re.I)),
)

TARGET_PATTERN = re.compile(
    r"(https?://[^\s]+)|"
    r"((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?)|"
    r"((?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?)",
    re.I,
)

MODULE_PATH_PATTERN = re.compile(
    r"\b(?:auxiliary|backdoors|browser_auxiliary|browser_exploits|docker_environments|"
    r"encoders|exploits|listeners|modules|obfuscators|payloads|post|scanner|shortcut|workflow)"
    r"/[a-z0-9_./-]+\b",
    re.I,
)


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _clean_whitespace(text: str) -> str:
    return " ".join(str(text or "").strip().split())


def _safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _safe_value(v) for k, v in value.items()}
    return str(value)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _normalize_module_type(raw_value: str) -> str:
    cleaned = str(raw_value or "").strip().lower()
    if not cleaned:
        return ""
    return MODULE_TYPE_ALIASES.get(cleaned, cleaned)


def _module_runtime_path(module: Any) -> Optional[str]:
    module_name = str(getattr(module, "__module__", "") or "")
    if module_name.startswith("modules."):
        return module_name[len("modules.") :].replace(".", "/")
    return None


def _looks_like_command(request: str) -> bool:
    parts = _split_command_line(request)
    if not parts:
        return False
    command_name = parts[0].lower()
    if command_name not in KNOWN_COMMANDS:
        return False
    if len(parts) == 1:
        return True

    second = parts[1].lower()
    if second in NATURAL_FILLER_TOKENS:
        return False

    if command_name in ("run", "agent", "scanner", "sessions", "shell"):
        if second.startswith("-"):
            return True
        if any(marker in second for marker in ("://", "/", ".", ":")):
            return True
        return len(parts) <= 3

    if command_name == "set":
        return len(parts) >= 3 and second not in NATURAL_FILLER_TOKENS

    if command_name == "workspace":
        return second in ("list", "current", "create", "delete", "switch", "stats")

    if command_name == "show":
        return second in (
            "advanced",
            "aux",
            "auxiliary",
            "docker",
            "encoders",
            "exploits",
            "info",
            "listeners",
            "modules",
            "nops",
            "obfuscators",
            "options",
            "payloads",
            "post",
            "workflows",
            "workspaces",
        )

    return len(parts) <= 6


def _split_command_line(command_line: str) -> List[str]:
    text = str(command_line or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _module_type_tokens(text: str) -> List[str]:
    lowered = str(text or "").lower()
    found: List[str] = []
    for token, module_type in FAMILY_HINTS.items():
        if token in lowered:
            found.append(module_type)
    for token in re.findall(r"[a-z0-9_+-]+", lowered):
        module_type = MODULE_TYPE_ALIASES.get(token)
        if module_type:
            found.append(module_type)
    return _dedupe(found)


def _expanded_keywords(tokens: Iterable[str], request: str) -> List[str]:
    expanded: List[str] = []
    lowered_request = str(request or "").lower()
    for token in tokens:
        lowered = str(token or "").strip().lower()
        if not lowered:
            continue
        expanded.append(lowered)
        if lowered in KEYWORD_EXPANSIONS:
            expanded.extend(KEYWORD_EXPANSIONS[lowered])
    for phrase, values in KEYWORD_EXPANSIONS.items():
        if " " in phrase and phrase in lowered_request:
            expanded.extend(values)
    return _dedupe(expanded)


def _extract_module_path(request: str) -> Optional[str]:
    match = MODULE_PATH_PATTERN.search(str(request or ""))
    if not match:
        return None
    return match.group(0).strip().lower()


def _extract_explicit_options(request: str) -> Dict[str, str]:
    options: Dict[str, str] = {}
    for name, pattern in EXPLICIT_VALUE_PATTERNS:
        match = pattern.search(str(request or ""))
        if match:
            options[name] = match.group(1).strip().strip(",;")
    return options


def _normalize_target(raw_target: Optional[str], request: str = "") -> Dict[str, Any]:
    raw_value = _clean_whitespace(raw_target or "")
    if not raw_value:
        return {
            "raw": None,
            "normalized": None,
            "kind": None,
            "scheme": None,
            "host": None,
            "port": None,
        }

    if "://" in raw_value:
        parsed = urlparse(raw_value)
        scheme = parsed.scheme.lower() or None
        host = parsed.hostname or None
        port = parsed.port
        if port is None and scheme == "https":
            port = 443
        elif port is None and scheme == "http":
            port = 80
        return {
            "raw": raw_value,
            "normalized": raw_value,
            "kind": "url",
            "scheme": scheme,
            "host": host,
            "port": port,
        }

    host = raw_value
    port = None
    if raw_value.count(":") == 1 and "/" not in raw_value:
        maybe_host, maybe_port = raw_value.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = int(maybe_port)

    request_lower = str(request or "").lower()
    scheme = None
    if "https" in request_lower or "ssl" in request_lower:
        scheme = "https"
    elif "http" in request_lower or "web" in request_lower:
        scheme = "http"

    kind = "ip" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or "") else "host"
    normalized = raw_value
    if scheme and host and kind == "host":
        normalized = f"{scheme}://{host}"
        if port:
            normalized = f"{normalized}:{port}"

    return {
        "raw": raw_value,
        "normalized": normalized,
        "kind": kind,
        "scheme": scheme,
        "host": host,
        "port": port,
    }


def _extract_target(request: str, explicit_options: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    options = explicit_options or {}
    for key in ("url", "target", "rhost", "host"):
        if key in options:
            return _normalize_target(options[key], request=request)

    match = TARGET_PATTERN.search(str(request or ""))
    if match:
        raw_target = next((group for group in match.groups() if group), None)
        return _normalize_target(raw_target, request=request)
    return _normalize_target(None, request=request)


def _extract_keywords(request: str, target: Dict[str, Any], explicit_module_path: Optional[str]) -> List[str]:
    text = str(request or "").lower()
    if explicit_module_path:
        text = text.replace(explicit_module_path.lower(), " ")
    raw_target = str((target or {}).get("raw") or "").lower()
    if raw_target:
        text = text.replace(raw_target, " ")

    tokens = re.findall(r"[a-z0-9_+-]+", text)
    filtered = [
        token
        for token in tokens
        if token not in STOPWORDS
        and len(token) > 1
        and not token.isdigit()
        and token not in KNOWN_COMMANDS
    ]

    if explicit_module_path:
        filtered.extend(
            part for part in explicit_module_path.split("/") if part and part not in STOPWORDS
        )

    if target.get("scheme"):
        filtered.append(target["scheme"])
        if target["scheme"] in ("http", "https"):
            filtered.append("web")

    if target.get("host"):
        host_bits = re.split(r"[^a-z0-9]+", str(target["host"]).lower())
        filtered.extend(bit for bit in host_bits if bit and bit not in STOPWORDS and len(bit) > 2)

    return _expanded_keywords(filtered, request)


def _detect_operation_profile(request: str) -> str:
    lowered = str(request or "").lower()
    discreet_tokens = ("quiet", "stealth", "stealthy", "discreet", "silent", "low noise")
    aggressive_tokens = ("aggressive", "fast", "full speed", "loud", "spray")
    if any(token in lowered for token in discreet_tokens):
        return "discreet"
    if any(token in lowered for token in aggressive_tokens):
        return "aggressive"
    return "normal"


def _detect_intent(request: str, explicit_module_path: Optional[str], target: Dict[str, Any]) -> Tuple[str, List[str]]:
    lowered = str(request or "").lower()
    secondary: List[str] = []

    if _looks_like_command(request):
        return "command", secondary

    if "workspace" in lowered:
        if "switch" in lowered:
            secondary.append("switch")
        elif "current" in lowered:
            secondary.append("current")
        elif "create" in lowered:
            secondary.append("create")
        elif "delete" in lowered:
            secondary.append("delete")
        return "workspace", secondary

    if any(token in lowered for token in ("agent", "autonomous", "campaign", "full recon")):
        return "autonomous", secondary

    if (
        not explicit_module_path
        and not target.get("normalized")
        and any(token in lowered for token in GENERAL_INFO_TOKENS)
    ):
        return "framework_info", secondary

    if any(token in lowered for token in ("options", "show info", "module info", "explain module", "describe module")):
        return "inspect_module", secondary

    if explicit_module_path and any(token in lowered for token in ("run", "execute", "launch", "start")):
        return "execute_module", secondary

    if any(token in lowered for token in ("run", "execute", "launch", "start")) and target.get("normalized"):
        return "execute_module", secondary

    if any(token in lowered for token in ("help", "commands", "what can you do")):
        return "help", secondary

    if any(token in lowered for token in ("show", "describe", "explain", "details", "info")) and explicit_module_path:
        return "inspect_module", secondary

    if any(token in lowered for token in ("scan", "enumerate", "detect", "fingerprint", "find", "search", "lookup")):
        return "search_module", secondary

    return "search_module", secondary


def _classify_command(command_line: str) -> Dict[str, Any]:
    parts = _split_command_line(command_line)
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
            "reason": "Interactive or session-breaking commands are blocked from MCP execution.",
        }

    if command_name == "sessions" and any(token in args for token in ("interact", "shell")):
        return {
            "command": command_line,
            "name": command_name,
            "allowed_without_dangerous": False,
            "safety": "blocked",
            "reason": "Interactive session attachment must stay outside MCP automation.",
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


def _option_role(name: str, description: str = "") -> str:
    lowered_name = str(name or "").strip().lower()
    lowered_desc = str(description or "").strip().lower()
    for token, role in OPTION_ROLE_HINTS:
        if token in lowered_name or token in lowered_desc:
            return role
    return "generic"


@dataclass
class ParsedNaturalRequest:
    request: str
    normalized_request: str
    intent: str
    secondary_intents: List[str]
    module_types: List[str]
    keywords: List[str]
    operation_profile: str
    explicit_module_path: Optional[str]
    explicit_options: Dict[str, str]
    target: Dict[str, Any]
    direct_command: Optional[str] = None


class MCPCommandBridge:
    """Expose KittySploit's command registry to MCP in a reusable way."""

    def __init__(self, framework) -> None:
        self.framework = framework
        self._registry = None
        self._session = None
        self._output_handler = None

    def _ensure_registry(self):
        if self._registry is not None:
            return self._registry

        from core.output_handler import OutputHandler
        from core.session import Session
        from interfaces.command_system.command_registry import CommandRegistry

        self._session = Session()
        self._output_handler = OutputHandler()
        self._registry = CommandRegistry(self.framework, self._session, self._output_handler)
        return self._registry

    def get_state(self) -> Dict[str, Any]:
        current_module = getattr(self.framework, "current_module", None)
        session_manager = getattr(self.framework, "session_manager", None)
        return {
            "workspace": (
                self.framework.get_current_workspace()
                if hasattr(self.framework, "get_current_workspace")
                else getattr(self.framework, "current_workspace", None)
            ),
            "current_module": {
                "path": _module_runtime_path(current_module),
                "name": getattr(current_module, "name", None),
                "description": getattr(current_module, "description", None),
            }
            if current_module
            else None,
            "sessions": {
                "standard": len(getattr(session_manager, "sessions", {}) or {}),
                "browser": len(getattr(session_manager, "browser_sessions", {}) or {}),
            },
        }

    def list_commands(self) -> Dict[str, Any]:
        registry = self._ensure_registry()
        items = []
        for name in sorted(registry.get_available_commands()):
            command = registry.get_command(name)
            safety = _classify_command(name)
            items.append(
                {
                    "name": name,
                    "description": getattr(command, "description", ""),
                    "usage": getattr(command, "usage", name),
                    "help_text": getattr(command, "help_text", ""),
                    "safety": safety.get("safety"),
                    "reason": safety.get("reason"),
                }
            )
        return {"count": len(items), "commands": items}

    def get_command_help(self, command_name: str) -> Dict[str, Any]:
        registry = self._ensure_registry()
        command = registry.get_command(command_name)
        safety = _classify_command(command_name)
        return {
            "name": command_name,
            "description": getattr(command, "description", ""),
            "usage": getattr(command, "usage", command_name),
            "help_text": getattr(command, "help_text", ""),
            "safety": safety.get("safety"),
            "reason": safety.get("reason"),
        }

    def classify_command(self, command_line: str) -> Dict[str, Any]:
        return _classify_command(command_line)

    def execute_command(self, command_line: str, allow_dangerous: bool = False) -> Dict[str, Any]:
        registry = self._ensure_registry()
        safety = self.classify_command(command_line)

        if safety["safety"] == "blocked":
            return {
                "status": "blocked",
                "command": command_line,
                "safety": safety,
                "state": self.get_state(),
            }

        if not allow_dangerous and not safety.get("allowed_without_dangerous", False):
            return {
                "status": "requires_allow_dangerous",
                "command": command_line,
                "safety": safety,
                "state": self.get_state(),
            }

        parts = _split_command_line(command_line)
        if not parts:
            return {
                "status": "error",
                "command": command_line,
                "error": "Empty command.",
                "state": self.get_state(),
            }

        stdout = io.StringIO()
        stderr = io.StringIO()
        started_at = time.monotonic()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            success = bool(registry.execute_command(parts[0], parts[1:], framework=self.framework))

        return {
            "status": "ok" if success else "failed",
            "command": command_line,
            "success": success,
            "stdout": stdout.getvalue() or None,
            "stderr": stderr.getvalue() or None,
            "elapsed_ms": round((time.monotonic() - started_at) * 1000.0, 2),
            "safety": safety,
            "state": self.get_state(),
        }


class NaturalLanguagePlanner:
    """Plan module usage and command sequences from free-form user requests."""

    def __init__(
        self,
        framework,
        command_bridge: Optional[MCPCommandBridge] = None,
        llm_service: Optional[Any] = None,
        ollama_enabled: Optional[bool] = None,
        ollama_endpoint: Optional[str] = None,
        ollama_model: Optional[str] = None,
        ollama_timeout: Optional[int] = None,
    ) -> None:
        self.framework = framework
        self.command_bridge = command_bridge
        self.cache_ttl = 20.0
        self._module_index_cache: Dict[str, Any] = {"expires_at": 0.0, "rows": []}
        self._module_details_cache: Dict[str, Dict[str, Any]] = {}
        self.ollama_enabled = (
            bool(ollama_enabled)
            if ollama_enabled is not None
            else os.environ.get("KITTYMCP_OLLAMA_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
        )
        self.ollama_endpoint = (
            ollama_endpoint
            or os.environ.get("KITTYMCP_OLLAMA_ENDPOINT")
            or "http://127.0.0.1:11434/api/chat"
        )
        self.ollama_model = (
            ollama_model
            or os.environ.get("KITTYMCP_OLLAMA_MODEL")
            or "llama3.1:8b"
        )
        try:
            self.ollama_timeout = int(
                ollama_timeout
                if ollama_timeout is not None
                else (os.environ.get("KITTYMCP_OLLAMA_TIMEOUT") or 20)
            )
        except (TypeError, ValueError):
            self.ollama_timeout = 20
        if llm_service is not None:
            self._llm = llm_service
        elif self.ollama_enabled:
            from interfaces.command_system.builtin.agent.local_llm import LocalLLMService

            self._llm = LocalLLMService()
        else:
            self._llm = type("NullLLMService", (), {"last_error": None})()

    def invalidate_caches(self) -> None:
        self._module_index_cache = {"expires_at": 0.0, "rows": []}
        self._module_details_cache.clear()

    def ollama_status(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.ollama_enabled),
            "endpoint": self.ollama_endpoint,
            "model": self.ollama_model,
            "timeout": self.ollama_timeout,
            "last_error": self._llm.last_error,
        }

    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def get_framework_overview(self) -> Dict[str, Any]:
        readme_path = self._repo_root() / "README.md"
        summary = {
            "title": "KittySploit Framework",
            "summary": (
                "KittySploit is a modular penetration testing framework with CLI, web interfaces, "
                "session handling, scanners, payloads, listeners, post-exploitation modules, "
                "automation workflows, and optional AI-assisted planning."
            ),
            "highlights": [
                "Interactive CLI with native commands such as search, use, show, set, run, scanner, sessions, and workspace.",
                "Large module catalog covering scanners, exploits, payloads, listeners, post-exploitation, workflows, and more.",
                "Companion interfaces like KittyProxy, KittyOSINT, collaboration tooling, API/RPC access, and marketplace support.",
                "Natural-language planning through kittymcp_client and optional Ollama assistance.",
            ],
            "sources": [str(readme_path)],
        }
        try:
            text = readme_path.read_text(encoding="utf-8", errors="ignore")
            lines = [line.strip() for line in text.splitlines()]
            first_paragraph: List[str] = []
            capture = False
            for line in lines:
                if line.startswith("KittySploit is a **next-generation"):
                    capture = True
                if capture:
                    if not line:
                        break
                    first_paragraph.append(line)
            if first_paragraph:
                summary["summary"] = " ".join(first_paragraph)
            wiki_links = []
            for line in lines:
                if "Getting Started" in line or "CLI Reference" in line or "Architecture" in line:
                    wiki_links.append(line)
            if wiki_links:
                summary["documentation_hints"] = wiki_links[:6]
        except Exception:
            pass
        return summary

    def _candidate_module_families(self) -> List[str]:
        families = set()
        for row in self._get_module_index():
            normalized = _normalize_module_type(row.get("type") or "")
            if normalized:
                families.add(normalized)
        return sorted(families)

    def parse_request(self, request: str) -> ParsedNaturalRequest:
        normalized = _clean_whitespace(request)
        explicit_module_path = _extract_module_path(normalized)
        explicit_options = _extract_explicit_options(normalized)
        target = _extract_target(normalized, explicit_options=explicit_options)
        keywords = _extract_keywords(normalized, target=target, explicit_module_path=explicit_module_path)
        intent, secondary = _detect_intent(normalized, explicit_module_path, target)
        direct_command = normalized if _looks_like_command(normalized) else None
        return ParsedNaturalRequest(
            request=request,
            normalized_request=normalized,
            intent=intent,
            secondary_intents=secondary,
            module_types=_module_type_tokens(normalized),
            keywords=keywords,
            operation_profile=_detect_operation_profile(normalized),
            explicit_module_path=explicit_module_path,
            explicit_options=explicit_options,
            target=target,
            direct_command=direct_command,
        )

    def _get_module_index(self) -> List[Dict[str, Any]]:
        now = time.monotonic()
        if now < float(self._module_index_cache["expires_at"]) and self._module_index_cache["rows"]:
            return list(self._module_index_cache["rows"])

        discovered = self.framework.module_loader.discover_modules()
        rows: List[Dict[str, Any]] = []
        for module_path, file_path in discovered.items():
            meta = extract_module_search_metadata(file_path)
            rows.append(
                {
                    "path": module_path,
                    "file_path": file_path,
                    "name": meta.get("name") or module_path,
                    "description": meta.get("description") or "",
                    "author": meta.get("author") or "",
                    "tags": [str(tag) for tag in meta.get("tags") or []],
                    "cve": meta.get("cve") or "",
                    "type": infer_module_type_from_path(module_path),
                }
            )

        rows.sort(key=lambda row: (row["path"], row["name"]))
        self._module_index_cache = {
            "expires_at": now + self.cache_ttl,
            "rows": rows,
        }
        return list(rows)

    def list_modules(self, limit: int = 50, module_types: Optional[List[str]] = None) -> Dict[str, Any]:
        normalized_types = {_normalize_module_type(item) for item in (module_types or []) if item}
        items = []
        for row in self._get_module_index():
            if normalized_types and _normalize_module_type(row.get("type")) not in normalized_types:
                continue
            items.append({k: row[k] for k in ("path", "name", "description", "author", "tags", "cve", "type")})
            if len(items) >= max(1, min(limit, 500)):
                break
        return {"count": len(items), "modules": items}

    def _score_module(self, row: Dict[str, Any], parsed: ParsedNaturalRequest) -> Tuple[float, List[str]]:
        score = 0.0
        reasons: List[str] = []
        path_low = str(row.get("path") or "").lower()
        name_low = str(row.get("name") or "").lower()
        desc_low = str(row.get("description") or "").lower()
        tags_low = " ".join([str(tag).lower() for tag in row.get("tags") or []])
        row_type = _normalize_module_type(row.get("type") or "")
        preferred_types = {_normalize_module_type(item) for item in parsed.module_types if item}

        if parsed.explicit_module_path and parsed.explicit_module_path == path_low:
            score += 250.0
            reasons.append("Exact module path requested.")

        if preferred_types:
            if row_type in preferred_types:
                score += 26.0
                reasons.append(f"Matches requested module family '{row_type}'.")
            else:
                score -= 12.0

        if parsed.intent == "execute_module" and row_type in ("exploits", "scanner", "listeners", "payloads"):
            score += 6.0
        elif parsed.intent == "inspect_module":
            score += 2.0

        for token in parsed.keywords:
            if token in path_low:
                score += 18.0
                reasons.append(f"Keyword '{token}' appears in module path.")
                continue
            if token in name_low:
                score += 13.0
                reasons.append(f"Keyword '{token}' appears in module name.")
                continue
            if token in tags_low:
                score += 11.0
                reasons.append(f"Keyword '{token}' appears in module tags.")
                continue
            if token in desc_low:
                score += 7.0
                reasons.append(f"Keyword '{token}' appears in module description.")

        target = parsed.target or {}
        scheme = str(target.get("scheme") or "").lower()
        if scheme in ("http", "https") and (
            path_low.startswith("scanner/http/")
            or path_low.startswith("auxiliary/scanner/http/")
            or path_low.startswith("exploits/http/")
            or path_low.startswith("exploits/multi/http/")
        ):
            score += 10.0
            reasons.append("HTTP/HTTPS target detected.")

        if target.get("kind") in ("host", "ip") and any(
            path_low.startswith(prefix)
            for prefix in ("scanner/smb/", "scanner/ldap/", "scanner/cloud/", "scanner/telecom/")
        ):
            score += 4.0

        if parsed.operation_profile == "discreet":
            score += 1.5
        elif parsed.operation_profile == "aggressive" and row_type in ("scanner", "exploits"):
            score += 1.5

        if not parsed.keywords and not preferred_types and not parsed.explicit_module_path:
            score += 1.0

        return score, _dedupe(reasons)

    def _ollama_search_assist(self, parsed: ParsedNaturalRequest) -> Optional[Dict[str, Any]]:
        if not self.ollama_enabled:
            return None

        payload = {
            "request": parsed.normalized_request,
            "parsed_request": asdict(parsed),
            "module_families": self._candidate_module_families(),
            "current_state": self.command_bridge.get_state() if self.command_bridge else {},
        }
        instruction = (
            "You are KittySploit's search-query assistant. "
            "Reply ONLY a valid JSON object. "
            "Required keys: search_terms (array), module_types (array), rationale (string). "
            "Optional keys: rewritten_request (string), boost_terms (array), intent_override (string), "
            "target_hint (string), reasoning_confidence (0..1). "
            "Use only module_types from the provided module_families list. "
            "search_terms must be short tokens or short phrases useful for matching module paths, names, tags, or descriptions."
        )
        response = self._llm.query_json(
            endpoint=self.ollama_endpoint,
            model=self.ollama_model,
            instruction=instruction,
            payload=payload,
            timeout=self.ollama_timeout,
        )
        if not isinstance(response, dict):
            return None

        search_terms = response.get("search_terms", [])
        module_types = response.get("module_types", [])
        boost_terms = response.get("boost_terms", [])
        if not isinstance(search_terms, list):
            search_terms = []
        if not isinstance(module_types, list):
            module_types = []
        if not isinstance(boost_terms, list):
            boost_terms = []

        allowed_families = set(self._candidate_module_families())
        normalized_types = []
        for item in module_types:
            if not isinstance(item, str):
                continue
            normalized = _normalize_module_type(item)
            if normalized and normalized in allowed_families and normalized not in normalized_types:
                normalized_types.append(normalized)

        return {
            "provider": "ollama",
            "rewritten_request": _clean_whitespace(response.get("rewritten_request", "")),
            "search_terms": _dedupe(
                [str(item).strip().lower() for item in search_terms if isinstance(item, str)]
            ),
            "boost_terms": _dedupe(
                [str(item).strip().lower() for item in boost_terms if isinstance(item, str)]
            ),
            "module_types": normalized_types,
            "intent_override": _clean_whitespace(response.get("intent_override", "")),
            "target_hint": _clean_whitespace(response.get("target_hint", "")),
            "rationale": str(response.get("rationale", "") or ""),
            "reasoning_confidence": response.get("reasoning_confidence"),
            "error": self._llm.last_error,
        }

    def search_modules(
        self,
        request: Union[str, ParsedNaturalRequest],
        max_candidates: int = 8,
        module_types: Optional[List[str]] = None,
        search_assist: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        parsed = request if isinstance(request, ParsedNaturalRequest) else self.parse_request(request)
        assisted = search_assist or {}
        assisted_types = [
            _normalize_module_type(item)
            for item in (assisted.get("module_types") or [])
            if item
        ]
        preferred_types = {
            _normalize_module_type(item)
            for item in ((module_types or parsed.module_types) + assisted_types)
            if item
        }
        parsed_keywords = list(parsed.keywords or [])
        assisted_terms = [
            str(item).strip().lower()
            for item in ((assisted.get("search_terms") or []) + (assisted.get("boost_terms") or []))
            if str(item).strip()
        ]
        scoring_keywords = _dedupe(parsed_keywords + assisted_terms)

        scored_rows = []
        for row in self._get_module_index():
            row_type = _normalize_module_type(row.get("type") or "")
            if preferred_types and row_type not in preferred_types:
                continue
            score, reasons = self._score_module(row, parsed)
            if assisted_terms:
                path_low = str(row.get("path") or "").lower()
                name_low = str(row.get("name") or "").lower()
                desc_low = str(row.get("description") or "").lower()
                tags_low = " ".join([str(tag).lower() for tag in row.get("tags") or []])
                for token in assisted_terms:
                    if token in path_low:
                        score += 22.0
                        reasons.append(f"Ollama boosted path match on '{token}'.")
                    elif token in name_low:
                        score += 16.0
                        reasons.append(f"Ollama boosted name match on '{token}'.")
                    elif token in tags_low:
                        score += 13.0
                        reasons.append(f"Ollama boosted tag match on '{token}'.")
                    elif token in desc_low:
                        score += 8.0
                        reasons.append(f"Ollama boosted description match on '{token}'.")
            if scoring_keywords or parsed.explicit_module_path or preferred_types:
                if score <= 0:
                    continue
            scored_rows.append(
                {
                    **row,
                    "score": round(score, 2),
                    "why": reasons[:4],
                }
            )

        scored_rows.sort(
            key=lambda row: (
                -float(row.get("score") or 0.0),
                row.get("path") or "",
            )
        )

        if not scored_rows and parsed.explicit_module_path:
            scored_rows = [
                row for row in self._get_module_index() if row.get("path") == parsed.explicit_module_path
            ]

        items = []
        for row in scored_rows[: max(1, min(max_candidates, 50))]:
            items.append(
                {
                    "path": row["path"],
                    "name": row["name"],
                    "description": row["description"],
                    "author": row["author"],
                    "tags": row["tags"],
                    "cve": row["cve"],
                    "type": row["type"],
                    "score": row.get("score"),
                    "why": row.get("why") or [],
                }
            )

        return {
            "query": parsed.normalized_request,
            "count": len(items),
            "parsed_request": asdict(parsed),
            "search_assist": assisted,
            "modules": items,
        }

    def _guess_option_values(
        self,
        option_entries: List[Dict[str, Any]],
        parsed: ParsedNaturalRequest,
    ) -> Dict[str, str]:
        hints: Dict[str, str] = {}
        explicit = {str(k).lower(): str(v) for k, v in (parsed.explicit_options or {}).items()}
        target = parsed.target or {}
        target_url = str(target.get("normalized") or "")
        target_host = str(target.get("host") or "")
        target_port = target.get("port")

        for entry in option_entries:
            option_name = str(entry.get("name") or "")
            lowered_name = option_name.lower()
            role = str(entry.get("semantic_role") or "")

            if lowered_name in explicit:
                hints[option_name] = explicit[lowered_name]
                continue

            if role == "target_url" and target_url:
                hints[option_name] = target_url
                continue
            if role in ("target", "target_host") and target_host:
                if role == "target" and target_url:
                    hints[option_name] = target_url
                else:
                    hints[option_name] = target_host
                continue
            if role == "target_port" and target_port:
                hints[option_name] = str(target_port)
                continue
            if role == "ssl_flag" and target.get("scheme") == "https":
                hints[option_name] = "true"
                continue
            if role == "username" and "username" in explicit:
                hints[option_name] = explicit["username"]
                continue
            if role == "password" and "password" in explicit:
                hints[option_name] = explicit["password"]
                continue

        return hints

    def get_module_details(
        self,
        module_path: str,
        request: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        cache_key = f"{module_path}|{request or ''}|{target or ''}"
        if cache_key in self._module_details_cache:
            return self._module_details_cache[cache_key]

        module = self.framework.module_loader.load_module(module_path, framework=self.framework)
        if not module:
            return {"error": "Module not found", "module_path": module_path}

        info = module.get_info() if hasattr(module, "get_info") else {}
        raw_options = module.get_options() if hasattr(module, "get_options") else {}
        missing = []
        if hasattr(module, "get_missing_options"):
            try:
                missing = [str(item) for item in module.get_missing_options()]
            except Exception:
                missing = []

        option_entries: List[Dict[str, Any]] = []
        for option_name, option_data in (raw_options or {}).items():
            default = option_data[0] if len(option_data) > 0 else None
            required = bool(option_data[1]) if len(option_data) > 1 else False
            description = str(option_data[2]) if len(option_data) > 2 else ""
            advanced = bool(option_data[3]) if len(option_data) > 3 else False
            descriptor = getattr(type(module), option_name, None)

            current_value = default
            type_hint = None
            if descriptor is not None and isinstance(descriptor, BaseOption):
                descriptor_state = descriptor.to_dict(module)
                current_value = descriptor_state.get("display_value", descriptor_state.get("value", default))
                type_hint = descriptor.__class__.__name__
            else:
                attr = getattr(module, option_name, default)
                if hasattr(attr, "display_value"):
                    current_value = getattr(attr, "display_value")
                elif hasattr(attr, "value"):
                    current_value = getattr(attr, "value")
                else:
                    current_value = attr
                type_hint = type(current_value).__name__ if current_value is not None else None

            option_entries.append(
                {
                    "name": option_name,
                    "default": _safe_value(default),
                    "current_value": _safe_value(current_value),
                    "required": required,
                    "description": description,
                    "advanced": advanced,
                    "type_hint": type_hint,
                    "semantic_role": _option_role(option_name, description),
                }
            )

        option_entries.sort(
            key=lambda entry: (
                0 if entry["required"] else 1,
                1 if entry["advanced"] else 0,
                entry["name"].lower(),
            )
        )

        parsed_request = self.parse_request(" ".join([part for part in [request or "", target or ""] if part]))
        option_hints = self._guess_option_values(option_entries, parsed_request)

        details = {
            "module_path": module_path,
            "module_runtime_path": _module_runtime_path(module),
            "name": info.get("name", getattr(module, "name", module_path)),
            "description": info.get("description", getattr(module, "description", "")),
            "author": info.get("author", getattr(module, "author", "")),
            "references": _safe_value(info.get("references", getattr(module, "references", []))),
            "tags": _safe_value(info.get("tags", getattr(module, "tags", []))),
            "requires_root": bool(info.get("requires_root", getattr(module, "requires_root", False))),
            "type": infer_module_type_from_path(module_path),
            "options": option_entries,
            "required_options": [entry["name"] for entry in option_entries if entry["required"]],
            "missing_options": missing,
            "option_hints": option_hints,
        }

        self._module_details_cache[cache_key] = details
        return details

    def _ollama_plan(
        self,
        parsed: ParsedNaturalRequest,
        module_candidates: List[Dict[str, Any]],
        heuristic_commands: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not self.ollama_enabled:
            return None

        command_catalog = []
        if self.command_bridge:
            try:
                command_catalog = list((self.command_bridge.list_commands().get("commands") or []))[:40]
            except Exception:
                command_catalog = []

        payload = {
            "request": parsed.normalized_request,
            "parsed_request": asdict(parsed),
            "state": self.command_bridge.get_state() if self.command_bridge else {},
            "candidate_modules": [
                {
                    "path": item.get("path"),
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "type": item.get("type"),
                    "required_options": item.get("required_options"),
                    "option_hints": item.get("option_hints"),
                }
                for item in module_candidates[:6]
            ],
            "heuristic_commands": heuristic_commands[:8],
            "command_catalog": [
                {
                    "name": item.get("name"),
                    "usage": item.get("usage"),
                    "description": item.get("description"),
                    "safety": item.get("safety"),
                }
                for item in command_catalog
            ],
        }
        instruction = (
            "You are KittySploit MCP's natural-language planner. "
            "Reply ONLY a valid JSON object. "
            "Required keys: rationale (string), command_sequence (array), selected_paths (array). "
            "Optional keys: should_execute_now (boolean), execution_mode (string), reasoning_confidence (0..1), notes (array). "
            "Each item of command_sequence must be an object with keys: command (string), reason (string). "
            "Use only realistic KittySploit commands. Prefer safe stateful preparation commands first. "
            "Do not invent modules outside candidate_modules unless they are already in selected_paths."
        )
        response = self._llm.query_json(
            endpoint=self.ollama_endpoint,
            model=self.ollama_model,
            instruction=instruction,
            payload=payload,
            timeout=self.ollama_timeout,
        )
        if not isinstance(response, dict):
            return None

        command_sequence = response.get("command_sequence", [])
        normalized_commands: List[Dict[str, Any]] = []
        if isinstance(command_sequence, list):
            for item in command_sequence[:8]:
                if not isinstance(item, dict):
                    continue
                command = _clean_whitespace(item.get("command", ""))
                reason = _clean_whitespace(item.get("reason", ""))
                if not command:
                    continue
                safety = (
                    self.command_bridge.classify_command(command)
                    if self.command_bridge
                    else _classify_command(command)
                )
                normalized_commands.append(
                    {
                        "command": command,
                        "reason": reason or "Recommended by Ollama.",
                        "safety": safety.get("safety"),
                        "allowed_without_dangerous": safety.get("allowed_without_dangerous", False),
                    }
                )

        selected_paths = response.get("selected_paths", [])
        if not isinstance(selected_paths, list):
            selected_paths = []

        return {
            "provider": "ollama",
            "rationale": str(response.get("rationale", "") or ""),
            "reasoning_confidence": response.get("reasoning_confidence"),
            "should_execute_now": bool(response.get("should_execute_now", False)),
            "execution_mode": str(response.get("execution_mode", "") or ""),
            "notes": response.get("notes", []),
            "selected_paths": [path for path in selected_paths if isinstance(path, str) and path.strip()],
            "command_sequence": normalized_commands,
            "error": self._llm.last_error,
        }

    def _recommend_commands(
        self,
        parsed: ParsedNaturalRequest,
        module_candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        commands: List[Dict[str, Any]] = []

        def add(command: str, reason: str) -> None:
            safety = (
                self.command_bridge.classify_command(command)
                if self.command_bridge
                else _classify_command(command)
            )
            commands.append(
                {
                    "command": command,
                    "reason": reason,
                    "safety": safety.get("safety"),
                    "allowed_without_dangerous": safety.get("allowed_without_dangerous", False),
                }
            )

        if parsed.direct_command:
            add(parsed.direct_command, "Direct framework command detected in the request.")
            return commands

        top = module_candidates[0] if module_candidates else None
        top_path = str(top.get("path") or "") if top else ""
        target = parsed.target or {}

        if parsed.intent == "help":
            add("help", "Show the framework command catalog.")
            return commands

        if parsed.intent == "workspace":
            lowered = parsed.normalized_request.lower()
            if "list" in lowered:
                add("workspace list", "List available workspaces.")
            elif "current" in lowered:
                add("workspace current", "Show the active workspace.")
            elif "switch" in lowered and target.get("raw"):
                add(f"workspace switch {target['raw']}", "Switch to the requested workspace.")
            else:
                add("workspace current", "Show the active workspace first.")
                add("workspace list", "List available workspaces.")
            return commands

        if parsed.intent == "autonomous" and target.get("normalized"):
            add(f"agent {target['normalized']}", "Launch the autonomous agent against the target.")

        search_terms = " ".join(parsed.keywords[:4]).strip()
        if search_terms:
            add(f"search {search_terms}", "Search for matching modules in the framework.")

        if parsed.intent in ("inspect_module", "execute_module") and top_path:
            add(f"use {top_path}", "Select the most relevant module.")
            add("show info", "Inspect the selected module.")
            add("show options", "Review configurable options.")

        if parsed.intent == "execute_module" and top_path:
            details = self.get_module_details(top_path, request=parsed.request)
            for option_name, option_value in list((details.get("option_hints") or {}).items())[:4]:
                add(f"set {option_name} {option_value}", f"Pre-fill inferred option '{option_name}'.")
            add("run", "Execute the selected module once options are ready.")

        if parsed.intent == "search_module" and not commands and search_terms:
            add(f"search {search_terms}", "Search the module catalog using extracted keywords.")

        return commands[:8]

    def _recommend_mcp_calls(
        self,
        parsed: ParsedNaturalRequest,
        module_candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        calls: List[Dict[str, Any]] = []
        top = module_candidates[0] if module_candidates else None
        top_path = str(top.get("path") or "") if top else ""

        if parsed.intent == "workspace":
            lowered = parsed.normalized_request.lower()
            if "switch" in lowered and parsed.target.get("raw"):
                calls.append(
                    {
                        "tool": "ks_switch_workspace",
                        "arguments": {"name": parsed.target["raw"]},
                        "reason": "Switch workspace from natural request.",
                    }
                )
            else:
                calls.append(
                    {
                        "tool": "ks_list_workspaces",
                        "arguments": {},
                        "reason": "Inspect available workspaces.",
                    }
                )
            return calls

        if parsed.direct_command:
            calls.append(
                {
                    "tool": "ks_execute_command",
                    "arguments": {"command_line": parsed.direct_command},
                    "reason": "Execute the detected native framework command.",
                }
            )
            return calls

        calls.append(
            {
                "tool": "ks_list_modules",
                "arguments": {"query": parsed.normalized_request, "limit": 12},
                "reason": "Search matching modules from the natural-language request.",
            }
        )

        if top_path:
            calls.append(
                {
                    "tool": "ks_get_module_options",
                    "arguments": {"module_path": top_path},
                    "reason": "Inspect the best candidate's options.",
                }
            )
            details = self.get_module_details(top_path, request=parsed.request)
            option_hints = details.get("option_hints") or {}
            if parsed.intent == "execute_module":
                calls.append(
                    {
                        "tool": "ks_run_module",
                        "arguments": {
                            "module_path": top_path,
                            "options": option_hints,
                            "operation_profile": parsed.operation_profile,
                        },
                        "reason": "Execute the top candidate with inferred option hints.",
                    }
                )

        return calls[:4]

    def plan_request(
        self,
        request: str,
        max_candidates: int = 6,
        execute_safe_command: bool = False,
        prefer_ollama: bool = True,
        execute_recommended: bool = False,
        allow_dangerous: bool = False,
    ) -> Dict[str, Any]:
        parsed = self.parse_request(request)
        if parsed.intent == "framework_info":
            framework_overview = self.get_framework_overview()
            ollama_plan = None
            if prefer_ollama and self.ollama_enabled:
                payload = {
                    "request": parsed.normalized_request,
                    "framework_overview": framework_overview,
                    "state": self.command_bridge.get_state() if self.command_bridge else {},
                }
                instruction = (
                    "You are explaining KittySploit to a user. "
                    "Reply ONLY a valid JSON object with required keys: rationale (string), answer (string). "
                    "Optional keys: next_steps (array), reasoning_confidence (0..1). "
                    "Stay high-level, concise, and grounded in the provided framework_overview."
                )
                response = self._llm.query_json(
                    endpoint=self.ollama_endpoint,
                    model=self.ollama_model,
                    instruction=instruction,
                    payload=payload,
                    timeout=self.ollama_timeout,
                )
                if isinstance(response, dict):
                    ollama_plan = {
                        "provider": "ollama",
                        "rationale": str(response.get("rationale", "") or ""),
                        "answer": str(response.get("answer", "") or ""),
                        "next_steps": response.get("next_steps", []),
                        "reasoning_confidence": response.get("reasoning_confidence"),
                    }

            return {
                "request": request,
                "parsed_request": asdict(parsed),
                "framework_overview": framework_overview,
                "recommended_modules": [],
                "recommended_commands": [],
                "heuristic_commands": [],
                "recommended_mcp_calls": [],
                "ollama": self.ollama_status(),
                "ollama_search_assist": None,
                "ollama_plan": ollama_plan,
                "executed_command": None,
                "state": self.command_bridge.get_state() if self.command_bridge else None,
            }
        search_assist = self._ollama_search_assist(parsed) if prefer_ollama else None
        search_result = self.search_modules(
            parsed,
            max_candidates=max_candidates,
            search_assist=search_assist,
        )
        module_candidates = list(search_result.get("modules") or [])

        enriched_candidates = []
        for candidate in module_candidates[: max(1, min(max_candidates, 8))]:
            details = self.get_module_details(candidate["path"], request=request)
            enriched_candidates.append(
                {
                    **candidate,
                    "required_options": details.get("required_options") or [],
                    "missing_options": details.get("missing_options") or [],
                    "option_hints": details.get("option_hints") or {},
                }
            )

        heuristic_commands = self._recommend_commands(parsed, enriched_candidates)
        ollama_plan = self._ollama_plan(parsed, enriched_candidates, heuristic_commands) if prefer_ollama else None
        recommended_commands = list(
            (ollama_plan or {}).get("command_sequence") or heuristic_commands
        )
        mcp_calls = self._recommend_mcp_calls(parsed, enriched_candidates)

        executed_command = None
        if execute_recommended and recommended_commands and self.command_bridge:
            first_command = recommended_commands[0]["command"]
            executed_command = self.command_bridge.execute_command(
                first_command,
                allow_dangerous=allow_dangerous,
            )
        elif execute_safe_command and recommended_commands and self.command_bridge:
            first_command = recommended_commands[0]["command"]
            safety = self.command_bridge.classify_command(first_command)
            if safety.get("allowed_without_dangerous", False):
                executed_command = self.command_bridge.execute_command(first_command, allow_dangerous=False)

        return {
            "request": request,
            "parsed_request": asdict(parsed),
            "recommended_modules": enriched_candidates,
            "recommended_commands": recommended_commands,
            "heuristic_commands": heuristic_commands,
            "recommended_mcp_calls": mcp_calls,
            "ollama": self.ollama_status(),
            "ollama_search_assist": search_assist,
            "ollama_plan": ollama_plan,
            "executed_command": executed_command,
            "state": self.command_bridge.get_state() if self.command_bridge else None,
        }
