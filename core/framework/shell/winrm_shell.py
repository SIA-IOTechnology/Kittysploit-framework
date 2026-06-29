#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List

from .base_shell import BaseShell


class WinRMShell(BaseShell):
    """Shell wrapper for pypsrp WinRM Client sessions."""

    def __init__(self, session_id: str, session_type: str = "winrm", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.hostname = "winrm"
        self.current_directory = "C:\\"
        self._initialize_connection()

    @property
    def shell_name(self) -> str:
        return "winrm"

    @property
    def prompt_template(self) -> str:
        return "PS {hostname}:{directory}> "

    def get_prompt(self) -> str:
        return self.prompt_template.format(hostname=self.hostname, directory=self.current_directory)

    def get_available_commands(self) -> List[str]:
        return ["whoami", "hostname", "dir", "type", "powershell", "cmd", "cd", "pwd"]

    def _initialize_connection(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        self.hostname = session.host
        if session.data and session.data.get("username"):
            self.username = session.data.get("username")

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
        if not self.connection:
            return {"output": "", "status": 1, "error": "WinRM connection not available"}
        try:
            stdout, stderr, rc = self.connection.execute_cmd(command)
            return {"output": stdout or "", "status": int(rc or 0), "error": stderr or ""}
        except Exception as e:
            return {"output": "", "status": 1, "error": str(e)}

