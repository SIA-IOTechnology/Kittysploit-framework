#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive OPC UA shell for read-only server browsing."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.opcua_client import OpcUaClient, opcua_available

from .base_shell import BaseShell


class OpcUaShell(BaseShell):
    """OPC UA shell — show session info and browse nodes."""

    def __init__(self, session_id: str, session_type: str = "opcua", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: OpcUaClient | None = None
        self.host = "localhost"
        self.port = 4840
        self.endpoint = ""
        self.username = ""

        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "browse": self._cmd_browse,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _resolve_session(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return None
        return self.framework.session_manager.get_session(self.session_id)

    def _session_data(self) -> Dict[str, Any]:
        session = self._resolve_session()
        return (session.data or {}) if session else {}

    def _initialize_connection(self):
        try:
            data = self._session_data()
            self.host = str(data.get("host") or data.get("address", ["localhost", 4840])[0] or "localhost")
            self.port = int(data.get("port") or 4840)
            self.endpoint = str(data.get("endpoint") or "")
            self.username = str(data.get("username") or "")
            self.client = OpcUaClient(
                self.host,
                self.port,
                endpoint=self.endpoint,
                username=self.username,
                password=str(data.get("password") or ""),
                ssl=bool(data.get("ssl", False)),
            )
        except Exception as exc:
            print_warning(f"Could not initialize OPC UA connection: {exc}")

    def _require_client(self) -> OpcUaClient:
        if not opcua_available():
            raise RuntimeError("asyncua not installed — pip install asyncua")
        if not self.client:
            self._initialize_connection()
        if not self.client:
            raise RuntimeError("OPC UA connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "opcua"

    @property
    def prompt_template(self) -> str:
        return f"opcua [{self.host}:{self.port}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {"output": "", "status": 0, "error": ""}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as exc:
                return {"output": "", "status": 1, "error": str(exc)}
        return {"output": "", "status": 1, "error": f"Unknown command: {cmd}. Type help."}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        text = """
OPC UA Shell Commands:
======================
  info                 Show endpoint and initial browse details
  browse [node] [max]  Browse root/objects/a NodeId (default: root, max 30)
  exit / quit          Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        data = self._session_data()
        lines = [
            f"Endpoint: {data.get('endpoint') or self.endpoint or f'opc.tcp://{self.host}:{self.port}'}",
            f"Auth mode: {data.get('auth_mode') or ('username' if self.username else 'anonymous')}",
            f"Anonymous: {data.get('anonymous')}",
            f"Cached top-level nodes: {data.get('node_count', len(data.get('nodes') or []))}",
        ]
        for node in (data.get("nodes") or [])[:10]:
            lines.append(f"  {node}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_browse(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        node_id = parts[0] if len(parts) >= 1 else "root"
        max_nodes = int(parts[1]) if len(parts) >= 2 else 30
        client = self._require_client()
        result = client.browse(node_id=node_id, max_nodes=max_nodes)
        if not result.connected:
            return {"output": "", "status": 1, "error": result.error or "Browse failed"}
        if not result.nodes:
            return {"output": "No child nodes returned.\n", "status": 0, "error": ""}
        return {"output": "\n".join(result.nodes) + "\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Disconnecting from OPC UA shell.\n", "status": 0, "error": "", "exit": True}
