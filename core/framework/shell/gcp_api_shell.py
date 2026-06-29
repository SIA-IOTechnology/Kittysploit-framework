#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive shell wrapper for Google Cloud API console sessions."""

from typing import Any, Dict, List

from .base_shell import BaseShell


class GcpApiShell(BaseShell):
    def __init__(self, session_id: str, session_type: str = "gcp_api", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.project_id = "project"
        self.current_directory = "GCP"
        self._initialize_connection()

    @property
    def shell_name(self) -> str:
        return "gcp_api"

    @property
    def prompt_template(self) -> str:
        return f"gcp-api [{self.project_id}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def _initialize_connection(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        data = session.data if isinstance(getattr(session, "data", None), dict) else {}
        self.project_id = data.get("project_id", session.host)
        listener_id = data.get("listener_id")
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
            return {"output": "", "status": 1, "error": "GCP API console connection not available"}
        try:
            output = self.connection.run_command(command)
            return {"output": output or "", "status": 0, "error": ""}
        except Exception as e:
            return {"output": "", "status": 1, "error": str(e)}

    def get_available_commands(self) -> List[str]:
        if self.connection and hasattr(self.connection, "help_text"):
            return self.connection.help_text().splitlines()[1:]
        return [
            "whoami",
            "project",
            "iam_policy",
            "enabled_services",
            "service_accounts",
            "storage_buckets",
            "compute_instances",
            "secrets",
            "firestore_collections",
            "firebase_apps",
            "get <url>",
            "post <url> [json_payload]",
        ]
