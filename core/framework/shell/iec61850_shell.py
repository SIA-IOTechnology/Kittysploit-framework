#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive IEC 61850 MMS shell for identify / directory probes."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.iec61850_client import Iec61850Client
from lib.protocols.ics.ics_session_mixin import Iec61850SessionMixin

from .base_shell import BaseShell


class Iec61850Shell(BaseShell, Iec61850SessionMixin):
    def __init__(self, session_id: str, session_type: str = "iec61850", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: Iec61850Client | None = None
        self.host = "localhost"
        self.port = 102
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "identify": self._cmd_identify,
            "domains": self._cmd_domains,
            "variables": self._cmd_variables,
            "directory": self._cmd_directory,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_iec61850_client()
            info = self.get_iec61850_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 102)
        except Exception as exc:
            print_warning(f"Could not initialize IEC 61850 connection: {exc}")

    def _require_client(self) -> Iec61850Client:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("IEC 61850 MMS connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "iec61850"

    @property
    def prompt_template(self) -> str:
        return f"iec61850 [{self.host}:{self.port}]> "

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
IEC 61850 MMS Shell Commands:
========================
  info              Show connection details
  identify          MMS Identify (vendor/model/revision strings)
  domains           GetNameList domains (VMD scope)
  variables         GetNameList named variables
  directory         Identify + domains + variables
  exit / quit       Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        info = self.get_iec61850_connection_info()
        client = self.client
        lines = [
            f"Host: {info.get('host')}:{info.get('port')}",
            f"Connected: {bool(client and client.connected)}",
            f"COTP: {bool(client and client.cotp_accepted)}",
            f"Initiate: {bool(client and client.initiate_ok)}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_identify(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        result = client.identify(keep_open=True)
        if result.error and not result.strings:
            return {"output": "", "status": 1, "error": result.error}
        lines = [
            f"vendor={result.vendor or '-'} model={result.model or '-'} rev={result.revision or '-'}"
        ]
        lines.extend(f"  {s}" for s in result.strings[:20])
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_domains(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        names = client.get_name_list("domain")
        if not names:
            return {"output": "No domain names parsed\n", "status": 0, "error": ""}
        return {"output": "\n".join(f"  {n}" for n in names) + "\n", "status": 0, "error": ""}

    def _cmd_variables(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        names = client.get_name_list("variable")
        if not names:
            return {"output": "No variable names parsed\n", "status": 0, "error": ""}
        return {"output": "\n".join(f"  {n}" for n in names) + "\n", "status": 0, "error": ""}

    def _cmd_directory(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        result = client.directory(keep_open=True)
        if result.error and not (result.strings or result.domains or result.variables):
            return {"output": "", "status": 1, "error": result.error}
        lines = [
            f"strings={len(result.strings)} domains={len(result.domains)} "
            f"variables={len(result.variables)}",
        ]
        if result.strings:
            lines.append("Identify:")
            lines.extend(f"  {s}" for s in result.strings[:12])
        if result.domains:
            lines.append("Domains:")
            lines.extend(f"  {d}" for d in result.domains[:20])
        if result.variables:
            lines.append("Variables:")
            lines.extend(f"  {v}" for v in result.variables[:20])
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting IEC 61850 shell\n", "status": 0, "error": "", "exit": True}
