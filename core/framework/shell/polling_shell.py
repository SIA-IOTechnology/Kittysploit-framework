#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic shell for listener-backed polling transports."""

from typing import Any, Dict, List

from .base_shell import BaseShell


class PollingShell(BaseShell):
    """Queue commands through a listener and read buffered output."""

    def __init__(self, session_id: str, session_type: str = "polling", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.listener = None
        self.transport = session_type or "polling"
        self.client_id = ""
        self.client_ip = ""
        self._initialize_listener()

    def _initialize_listener(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        self.transport = session.data.get("protocol", session.session_type) if session.data else session.session_type
        self.client_id = session.data.get("client_id", "") if session.data else ""
        self.client_ip = session.data.get("client_ip", session.host) if session.data else session.host
        listener_id = session.data.get("listener_id") if session.data else None
        if listener_id and hasattr(self.framework, "active_listeners"):
            self.listener = self.framework.active_listeners.get(listener_id)
            if self.listener:
                return
        for module in getattr(self.framework, "modules", {}).values():
            if hasattr(module, "set_pending_command") and hasattr(module, "get_output_lines"):
                session_map = getattr(module, "_session_to_client_id", {})
                if self.session_id in session_map:
                    self.listener = module
                    return

    @property
    def shell_name(self) -> str:
        return "polling"

    @property
    def prompt_template(self) -> str:
        label = self.client_id or self.session_id[:8]
        return f"{self.transport} [{label}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {"output": "", "status": 0, "error": ""}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if cmd == "help":
            return {"output": self._help(), "status": 0, "error": ""}
        if cmd == "info":
            return {"output": self._info(), "status": 0, "error": ""}
        if cmd in ("run", "cmd"):
            return self._run(args)
        if cmd in ("output", "out"):
            return self._output(args)
        if cmd in ("clear_output", "output_clear"):
            return self._clear_output()
        if cmd in ("exit", "quit", "disconnect"):
            self.is_active = False
            return {"output": "Bye!", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"Unknown command: {cmd}. Use 'help'."}

    def _help(self) -> str:
        return """Polling Shell Commands:
  run <command>      Queue command for the remote agent
  output [N]         Show last N output chunks (default 50)
  clear_output       Clear buffered output
  info               Show transport/session info
  help               This help
  exit, quit         Exit shell"""

    def _info(self) -> str:
        return "\n".join(
            [
                f"Transport: {self.transport or '(unknown)'}",
                f"Client:    {self.client_id or '(unknown)'}",
                f"IP/Host:   {self.client_ip or '(unknown)'}",
                f"Session:   {self.session_id}",
            ]
        )

    def _run(self, args: str) -> Dict[str, Any]:
        if not self.listener:
            self._initialize_listener()
        if not self.listener or not hasattr(self.listener, "set_pending_command"):
            return {"output": "", "status": 1, "error": "Polling listener not available"}
        if not args.strip():
            return {"output": "", "status": 1, "error": "Usage: run <command>"}
        self.listener.set_pending_command(self.session_id, args.strip())
        return {"output": "Command queued. Agent will receive it on next poll.", "status": 0, "error": ""}

    def _output(self, args: str) -> Dict[str, Any]:
        if not self.listener:
            self._initialize_listener()
        if not self.listener or not hasattr(self.listener, "get_output_lines"):
            return {"output": "(no output)", "status": 0, "error": ""}
        n = 50
        if args.strip().isdigit():
            n = min(int(args.strip()), 500)
        lines = self.listener.get_output_lines(self.session_id, last_n=n)
        return {"output": "\n".join(lines) if lines else "(no output from agent yet)", "status": 0, "error": ""}

    def _clear_output(self) -> Dict[str, Any]:
        if self.listener and hasattr(self.listener, "get_output"):
            self.listener.get_output(self.session_id, clear=True)
        return {"output": "Output buffer cleared.", "status": 0, "error": ""}

    def get_available_commands(self) -> List[str]:
        return ["help", "info", "run", "cmd", "output", "out", "clear_output", "exit", "quit"]

