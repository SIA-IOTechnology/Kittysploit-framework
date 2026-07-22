#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Campaign helpers for browser C2 (`browser_server`) integration."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


BROWSER_AUX_PREFERRED: tuple[str, ...] = (
    "browser_auxiliary/misc/detect_properties",
    "browser_auxiliary/misc/generate_fingerprint",
    "browser_auxiliary/misc/keylogger",
    "browser_auxiliary/misc/find_similar_sessions",
)

BROWSER_C2_TECHNIQUES = ("T1189", "T1566", "T1071.001")
BROWSER_POST_TECHNIQUES = ("T1056.001", "T1189", "T1071.001")


def _url_host(host: str) -> str:
    text = str(host or "127.0.0.1").strip()
    if text in {"0.0.0.0", "::", "::0"}:
        return "127.0.0.1"
    if text.startswith("::ffff:"):
        return text.split(":", 2)[-1]
    return text or "127.0.0.1"


def browser_server_running(framework: Any) -> bool:
    server = getattr(framework, "browser_server", None)
    return bool(server and getattr(server, "is_running", lambda: False)())


def browser_server_endpoints(framework: Any) -> Dict[str, str]:
    server = getattr(framework, "browser_server", None)
    if not server:
        return {}
    host = _url_host(getattr(server, "host", "127.0.0.1"))
    port = int(getattr(server, "port", 8080) or 8080)
    base = f"http://{host}:{port}"
    return {
        "base": base,
        "inject_js": f"{base}/inject.js",
        "xss_js": f"{base}/xss.js",
        "admin": f"{base}/admin",
        "test": f"{base}/test",
    }


def browser_c2_framework_commands(framework: Any, *, host_address: str = "") -> List[str]:
    """Operator commands to stand up and operate browser C2 in a campaign."""
    _ = host_address
    commands = ["browser_server start"]
    if browser_server_running(framework):
        commands.extend(
            [
                "browser_server status",
                "browser_server urls",
                "browser_server inject",
                "browser_server sessions",
            ]
        )
    else:
        commands.extend(
            [
                "browser_server urls",
                "browser_server inject",
                "browser_server sessions",
            ]
        )
    return commands


def is_browser_session(session: Dict[str, Any]) -> bool:
    session_type = str(session.get("session_type") or session.get("type") or "").lower()
    if session_type == "browser":
        return True
    category = str(session.get("category") or "").lower()
    return category == "browser"


def browser_session_host(session: Dict[str, Any]) -> str:
    for key in ("target_host", "host", "ip_address", "ip"):
        value = session.get(key)
        if value:
            return str(value)
    info = session.get("info") or {}
    if isinstance(info, dict):
        for key in ("ip", "ip_address", "host"):
            value = info.get(key)
            if value:
                return str(value)
    return "browser-client"


def browser_session_id(session: Dict[str, Any]) -> str:
    for key in ("id", "session_id"):
        value = session.get(key)
        if value:
            return str(value)
    return ""


def normalize_browser_session(
    *,
    session_id: str,
    ip_address: str = "",
    user_agent: str = "",
    active: bool = True,
    source: str = "browser_server",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "id": session_id,
        "session_id": session_id,
        "session_type": "browser",
        "type": "browser",
        "category": "browser",
        "target_host": ip_address or "browser-client",
        "host": ip_address or "browser-client",
        "ip_address": ip_address,
        "user_agent": user_agent,
        "active": active,
        "source": source,
    }
    if extra:
        payload.update(extra)
    return payload


def collect_browser_sessions(framework: Any) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    server = getattr(framework, "browser_server", None)
    if server and getattr(server, "is_running", lambda: False)():
        for session_id, session in (getattr(server, "get_sessions", lambda: {})() or {}).items():
            merged[str(session_id)] = normalize_browser_session(
                session_id=str(session_id),
                ip_address=str(getattr(session, "ip_address", "") or ""),
                user_agent=str(getattr(session, "user_agent", "") or ""),
                active=bool(getattr(session, "is_connected", True)),
                source="browser_server",
                extra={
                    "commands_executed": int(getattr(session, "commands_executed", 0) or 0),
                    "browser_info": getattr(session, "browser_info", {}) or {},
                    "polling_active": bool(getattr(session, "is_polling_active", lambda: False)()),
                },
            )

    session_manager = getattr(framework, "session_manager", None)
    if session_manager and hasattr(session_manager, "get_browser_sessions"):
        for row in session_manager.get_browser_sessions() or []:
            if not isinstance(row, dict):
                continue
            session_id = browser_session_id(row)
            if not session_id:
                continue
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            merged[session_id] = normalize_browser_session(
                session_id=session_id,
                ip_address=str(info.get("ip") or info.get("ip_address") or row.get("ip") or ""),
                user_agent=str(info.get("user_agent") or row.get("user_agent") or ""),
                active=bool(row.get("active", True)),
                source="session_manager",
                extra={
                    "commands_executed": int(row.get("commands_executed", 0) or 0),
                    "commands_sent": int(row.get("commands_sent", 0) or 0),
                    "browser_info": info.get("browser_info") or info,
                },
            )

    return list(merged.values())
