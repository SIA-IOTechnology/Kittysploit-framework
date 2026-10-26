#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deterministic ad hoc tool steps when the LLM is unavailable or returns nothing."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def heuristic_adhoc_step(state: Any) -> Optional[Dict[str, Any]]:
    """
    Return a single tool step ``{tool, arguments, rationale}`` without LLM.
    Used as fallback to keep long campaigns moving off-catalog.
    """
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return None
    history = kb.get("adhoc_tool_history") or []
    used_tools = {str(row.get("tool") or "") for row in history if isinstance(row, dict)}

    endpoints = [str(u).strip() for u in (kb.get("discovered_endpoints") or []) if str(u).strip()]
    if endpoints and "http_request" not in used_tools:
        path = endpoints[0]
        return {
            "tool": "http_request",
            "arguments": {"url": path, "method": "GET"},
            "rationale": "heuristic: probe first discovered endpoint",
        }

    signals = " ".join(str(s) for s in (kb.get("risk_signals") or [])).lower()
    terms: List[str] = []
    for token in ("sql", "xss", "rce", "upload", "lfi", "ssrf", "auth", "login", "wordpress", "joomla"):
        if token in signals and token not in terms:
            terms.append(token)
    hints = [str(h).lower() for h in (kb.get("tech_hints") or [])[:6]]
    for hint in hints:
        for part in hint.replace("/", " ").split():
            if len(part) >= 3 and part not in terms:
                terms.append(part[:32])
    if terms and "discover_modules" not in used_tools:
        return {
            "tool": "discover_modules",
            "arguments": {"terms": terms[:6], "limit": 12},
            "rationale": "heuristic: search catalog from tech/risk signals",
        }

    observed = {str(p).strip() for p in (kb.get("observed_modules") or []) if str(p).strip()}
    discovered = kb.get("adhoc_discovered_modules") or []
    for path in reversed(discovered):
        p = str(path).strip()
        if not p or p in observed:
            continue
        if getattr(state, "no_exploit", False) and p.startswith("exploits/"):
            continue
        return {
            "tool": "run_module",
            "arguments": {"path": p},
            "rationale": f"heuristic: run discovered module {p}",
        }

    fw = getattr(state, "framework", None)
    server = getattr(fw, "browser_server", None) if fw else None
    sm = getattr(fw, "session_manager", None) if fw else None
    browser_ids = list(getattr(sm, "browser_sessions", {}).keys()) if sm else []
    if browser_ids and "browser_eval" not in used_tools:
        return {
            "tool": "browser_eval",
            "arguments": {
                "session_id": browser_ids[-1],
                "code": "JSON.stringify({href: location.href, cookies: document.cookie.length})",
                "wait_seconds": 8,
            },
            "rationale": "heuristic: fingerprint hooked browser session",
        }

    if server is not None and getattr(server, "running", False) is False and "framework_command" not in used_tools:
        return {
            "tool": "framework_command",
            "arguments": {"command": "browser_server status"},
            "rationale": "heuristic: check browser_server before XSS chain",
        }

    target = str(getattr(state, "raw_target", "") or "").strip()
    if target and "shell_exec" not in used_tools:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        if host:
            return {
                "tool": "shell_exec",
                "arguments": {"command": f"curl -skI --max-time 15 https://{host}/ || curl -skI --max-time 15 http://{host}/"},
                "rationale": "heuristic: local curl headers when modules stalled",
            }
    return None
