#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Execute ad hoc runtime tools (HTTP, modules, shell, browser, framework CLI)."""

from __future__ import annotations

import shlex
import subprocess
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.adhoc_autonomy import shell_exec_allowed
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.typed_models import AgentAction

_SHELL_SAFE_PREFIXES = (
    "curl",
    "wget",
    "openssl",
    "nmap",
    "ping",
    "tracert",
    "traceroute",
    "nslookup",
    "dig",
    "whoami",
    "echo",
    "python",
    "python3",
    "host",
    "nc",
    "ncat",
)


class AgentRuntimeToolExecutor:
    def __init__(self, state: Any, services: Any) -> None:
        self.state = state
        self.services = services

    @property
    def framework(self) -> Any:
        fw = getattr(self.state, "framework", None)
        if fw is not None:
            return fw
        core = getattr(self.services, "core", None)
        return getattr(core, "framework", None) if core is not None else None

    def handle(self, tool: str, arguments: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        name = str(tool or "").strip().lower().replace("-", "_")
        args = dict(arguments or {})
        handlers = {
            "http_request": self._http_request,
            "run_module": self._run_module,
            "discover_modules": self._discover_modules,
            "search_modules": self._discover_modules,
            "shell_exec": self._shell_exec,
            "framework_command": self._framework_command,
            "browser_eval": self._browser_eval,
            "done": self._done,
        }
        fn = handlers.get(name)
        if fn is None:
            return {"ok": False, "tool": name, "error": f"unknown tool: {tool}"}
        try:
            result = fn(args)
            return sanitize_nested(result if isinstance(result, dict) else {"ok": False, "error": "bad result"})
        except Exception as exc:
            return {"ok": False, "tool": name, "error": str(exc)[:500]}

    def _done(self, _args: Mapping[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "tool": "done", "finished": True}

    def _http_request(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            execute_agent_http_request,
            ingest_http_probe_result,
            record_llm_http_requests,
        )

        method = str(args.get("method") or "GET").upper()
        url = str(args.get("url") or args.get("path") or "").strip()
        if not url:
            return {"ok": False, "tool": "http_request", "error": "url required"}
        raw = execute_agent_http_request(
            self.state,
            {
                "type": "http_request",
                "path": url,
                "options": {"method": method, **dict(args.get("options") or {})},
            },
        )
        kb = getattr(self.state, "knowledge_base", None)
        if isinstance(kb, dict):
            record_llm_http_requests(kb, [raw])
            if self.framework is not None:
                self.state.framework = self.framework
            ingest_http_probe_result(self.state, raw)
        return {"ok": str(raw.get("status", "")).lower() not in {"error", "skipped"}, "tool": "http_request", "result": raw}

    def _run_module(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        path = str(args.get("path") or args.get("module_path") or "").strip()
        if not path:
            return {"ok": False, "tool": "run_module", "error": "path required"}
        if getattr(self.state, "no_exploit", False) and path.startswith("exploits/"):
            return {"ok": False, "tool": "run_module", "error": "no_exploit blocks exploits"}
        fw = self.framework
        if fw is None:
            return {"ok": False, "tool": "run_module", "error": "framework unavailable"}
        module = fw.module_loader.load_module(path, framework=fw, load_only=False)
        if module is None:
            return {"ok": False, "tool": "run_module", "error": f"module not found: {path}"}
        from interfaces.command_system.builtin.agent.execution_service import AgentModuleExecutionService

        action_type = "run_exploit" if path.startswith("exploits/") else "run_followup"
        action = AgentAction(
            type=action_type,
            path=path,
            priority=80,
            risk="intrusive" if path.startswith("exploits/") else "active",
            reason="adhoc_tool:run_module",
            status="planned",
            options={"option_patch": args.get("options")} if args.get("options") else {},
        )
        executor = AgentModuleExecutionService(fw)
        raw = executor.execute(
            module,
            path,
            self.state,
            phase=str(getattr(self.state, "current_phase", "") or "act"),
            candidates=[],
            score=80.0,
            decision_source="adhoc_tool_loop",
            option_patch=args.get("options") if isinstance(args.get("options"), dict) else None,
        )
        blocked = bool(raw.get("blocked"))
        self._touch_sessions()
        return {
            "ok": not blocked,
            "tool": "run_module",
            "path": path,
            "action_type": action_type,
            "execution": getattr(raw.get("execution"), "module_path", None) or path,
            "blocked": blocked,
            "error": str(raw.get("error") or ""),
        }

    def _discover_modules(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        fw = self.framework
        if fw is None:
            return {"ok": False, "tool": "discover_modules", "error": "framework unavailable"}
        terms = args.get("terms") or args.get("query") or []
        if isinstance(terms, str):
            query = terms.strip()
        else:
            query = " ".join(str(t).strip() for t in terms if str(t).strip())
        families = args.get("families") or args.get("family") or []
        if isinstance(families, str) and families.strip():
            query = f"{query} {families}".strip()
        from core.module_search import ModuleSearchFilters

        limit = max(1, min(int(args.get("limit") or 15), 30))
        filters = ModuleSearchFilters(query=query[:200], limit=limit)
        rows: List[Dict[str, Any]] = []
        try:
            hits = fw.search_modules_db(filters=filters) or []
        except Exception:
            hits = []
        for row in hits[:limit]:
            if not isinstance(row, dict):
                continue
            rows.append({
                "path": row.get("path") or row.get("module_path"),
                "name": row.get("name"),
                "type": row.get("type"),
            })
        kb = getattr(self.state, "knowledge_base", None)
        if isinstance(kb, dict):
            stash = kb.setdefault("adhoc_discovered_modules", [])
            for item in rows:
                p = str(item.get("path") or "").strip()
                if p and p not in stash:
                    stash.append(p)
            kb["adhoc_discovered_modules"] = stash[-80:]
        return {"ok": True, "tool": "discover_modules", "query": query, "modules": rows}

    def _shell_exec(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        command = str(args.get("command") or args.get("cmd") or "").strip()
        if not command:
            return {"ok": False, "tool": "shell_exec", "error": "command required"}
        if not shell_exec_allowed(self.state):
            return {
                "ok": False,
                "tool": "shell_exec",
                "error": "shell_exec requires --approve-shell-exec or safety-profile aggressive",
            }
        try:
            parts = shlex.split(command, posix=False)
        except ValueError as exc:
            return {"ok": False, "tool": "shell_exec", "error": str(exc)}
        if not parts:
            return {"ok": False, "tool": "shell_exec", "error": "empty command"}
        head = parts[0].lower().replace(".exe", "")
        if head not in _SHELL_SAFE_PREFIXES and not getattr(self.state, "approve_shell_exec", False):
            return {"ok": False, "tool": "shell_exec", "error": f"command prefix not allowlisted: {head}"}
        timeout = max(5, min(int(args.get("timeout") or 45), 120))
        started = time.monotonic()
        proc = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        stdout = (proc.stdout or "")[:8000]
        stderr = (proc.stderr or "")[:4000]
        kb = getattr(self.state, "knowledge_base", None)
        if isinstance(kb, dict):
            log = kb.setdefault("adhoc_shell_log", [])
            log.append({"command": command[:500], "code": proc.returncode, "stdout_head": stdout[:500]})
            kb["adhoc_shell_log"] = log[-20:]
        return {
            "ok": proc.returncode == 0,
            "tool": "shell_exec",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    def _framework_command(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        command_line = str(args.get("command") or args.get("command_line") or "").strip()
        if not command_line:
            return {"ok": False, "tool": "framework_command", "error": "command required"}
        fw = self.framework
        if fw is None:
            return {"ok": False, "tool": "framework_command", "error": "framework unavailable"}
        from interfaces.mcp_kittysploit_bridge import MCPCommandBridge

        allow = bool(args.get("allow_dangerous")) or shell_exec_allowed(self.state)
        bridge = MCPCommandBridge(fw)
        result = bridge.execute_command(command_line, allow_dangerous=allow)
        status = str(result.get("status") or "")
        ok = status == "ok" and bool(result.get("success", True))
        self._touch_sessions()
        return {
            "ok": ok,
            "tool": "framework_command",
            "status": status,
            "stdout": (result.get("stdout") or "")[:8000] or None,
            "stderr": (result.get("stderr") or "")[:4000] or None,
            "safety": result.get("safety"),
        }

    def _browser_eval(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        code = str(args.get("code") or args.get("javascript") or "").strip()
        if not code:
            return {"ok": False, "tool": "browser_eval", "error": "code required"}
        fw = self.framework
        server = getattr(fw, "browser_server", None) if fw else None
        if server is None or not getattr(server, "running", False):
            return {
                "ok": False,
                "tool": "browser_eval",
                "error": "browser_server not running (framework_command: browser_server start)",
            }
        session_id = str(args.get("session_id") or "").strip()
        if not session_id and fw is not None:
            sm = getattr(fw, "session_manager", None)
            browser = getattr(sm, "browser_sessions", {}) if sm else {}
            if browser:
                session_id = sorted(browser.keys())[-1]
        if not session_id:
            return {"ok": False, "tool": "browser_eval", "error": "no browser session_id"}
        command = {"type": "execute_js", "code": code[:12000]}
        queued = server.send_command_to_session(session_id, command)
        wait_s = max(0, min(int(args.get("wait_seconds") or 0), 30))
        response_snippet = None
        if queued and wait_s > 0:
            cmd_id = str(command.get("id") or "")
            session = server.get_session(session_id)
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline and session is not None:
                time.sleep(0.35)
                session = server.get_session(session_id)
                if session is None:
                    break
                for row in reversed(session.responses or []):
                    if not isinstance(row, dict):
                        continue
                    if cmd_id and str(row.get("command_id") or "") != cmd_id:
                        continue
                    response_snippet = str(row.get("result") or "")[:2000]
                    break
                if response_snippet is not None:
                    break
        kb = getattr(self.state, "knowledge_base", None)
        if isinstance(kb, dict) and response_snippet:
            kb.setdefault("browser_eval_results", []).append(
                {"session_id": session_id, "result": response_snippet[:500]}
            )
        return {
            "ok": bool(queued),
            "tool": "browser_eval",
            "session_id": session_id,
            "queued": queued,
            "response": response_snippet,
            "note": "Response arrives on browser poll; use wait_seconds to capture",
        }

    def _touch_sessions(self) -> None:
        fw = self.framework
        if fw is None:
            return
        sm = getattr(fw, "session_manager", None)
        if sm is None:
            return
        before_std = getattr(self.state, "sessions_before", {}).get("standard") or set()
        before_br = getattr(self.state, "sessions_before", {}).get("browser") or set()
        current_std = set(sm.sessions.keys())
        current_br = set(sm.browser_sessions.keys())
        new_std = sorted(current_std - set(before_std))
        new_br = sorted(current_br - set(before_br))
        merged = list(getattr(self.state, "new_sessions", []) or [])
        for sid in new_std + new_br:
            if sid not in merged:
                merged.append(sid)
        self.state.new_sessions = merged
        verified = list(getattr(self.state, "verified_sessions", []) or [])
        for sid in merged:
            if sid not in verified:
                verified.append(sid)
        self.state.verified_sessions = verified


def runtime_tools_for_llm() -> Sequence[Dict[str, Any]]:
    return [
        {
            "name": "http_request",
            "description": "Single in-scope HTTP GET/HEAD/OPTIONS probe.",
            "parameters": {"url": "string", "method": "GET|HEAD|OPTIONS"},
        },
        {
            "name": "run_module",
            "description": "Run a KittySploit module path (scanner/auxiliary/exploit).",
            "parameters": {"path": "string module path", "options": "object optional"},
        },
        {
            "name": "discover_modules",
            "description": "Search module catalog by keywords/CVE when no catalog row fits.",
            "parameters": {"terms": "array of strings", "limit": "int optional"},
        },
        {
            "name": "shell_exec",
            "description": "Run a local allowlisted shell command (curl, nmap, openssl, …).",
            "parameters": {"command": "string", "timeout": "seconds optional"},
        },
        {
            "name": "framework_command",
            "description": "Run native KittySploit CLI (sessions, browser_server, use, set, run).",
            "parameters": {"command": "string command line"},
        },
        {
            "name": "browser_eval",
            "description": "Queue JavaScript on a hooked browser_server session.",
            "parameters": {"session_id": "string optional", "code": "javascript string"},
        },
        {
            "name": "done",
            "description": "Stop ad hoc tool loop when goal reached or no further steps.",
            "parameters": {"reason": "string"},
        },
    ]
