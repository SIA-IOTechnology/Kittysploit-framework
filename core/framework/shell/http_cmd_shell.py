#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shell wrapper for HTTP command-execution webshell sessions."""

from typing import Any, Dict, List

from .base_shell import BaseShell


class HttpCmdShell(BaseShell):
    def __init__(self, session_id: str, session_type: str = "http_cmd", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.hostname = "target"
        self.current_directory = "/"
        self._initialize_connection()

    @property
    def shell_name(self) -> str:
        return "http_cmd"

    @property
    def prompt_template(self) -> str:
        return f"http-cmd [{self.hostname}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def _initialize_connection(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        self.hostname = session.host or self.hostname
        listener_id = session.data.get("listener_id") if session.data else None
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                self.connection = listener._session_connections.get(self.session_id)
                if self.connection:
                    return
        for module in getattr(self.framework, "modules", {}).values():
            if hasattr(module, "_session_connections") and self.session_id in module._session_connections:
                self.connection = module._session_connections[self.session_id]
                return

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {"output": "", "status": 0, "error": ""}
        self.add_to_history(command)
        if not self.connection:
            self._initialize_connection()
        if not self.connection or not hasattr(self.connection, "run_command"):
            return {"output": "", "status": 1, "error": "HTTP command channel not available"}
        try:
            output = self.connection.run_command(command)
            return {"output": output or "", "status": 0, "error": ""}
        except Exception as exc:
            return {"output": "", "status": 1, "error": str(exc)}

    def get_available_commands(self) -> List[str]:
        return ["<any shell command supported by the remote webshell>"]
