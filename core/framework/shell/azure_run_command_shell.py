#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shell wrapper for Azure VM Run Command sessions."""

from typing import Any, Dict, List

from .base_shell import BaseShell


class AzureRunCommandShell(BaseShell):
    def __init__(self, session_id: str, session_type: str = "azure_run_command", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.hostname = "azure-vm"
        self.current_directory = "Azure"
        self._initialize_connection()

    @property
    def shell_name(self) -> str:
        return "azure_run_command"

    @property
    def prompt_template(self) -> str:
        return f"azure-run-command [{self.hostname}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def _initialize_connection(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        self.hostname = session.data.get("vm_name", session.host) if session.data else session.host
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
            return {"output": "", "status": 1, "error": "Azure Run Command connection not available"}
        try:
            output = self.connection.run_command(command)
            return {"output": output or "", "status": 0, "error": ""}
        except Exception as e:
            return {"output": "", "status": 1, "error": str(e)}

    def get_available_commands(self) -> List[str]:
        return ["<any OS command supported by Azure Run Command>"]

