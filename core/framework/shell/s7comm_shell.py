#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive S7comm shell for Siemens PLC diagnostics and DB access."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.ics_session_mixin import S7SessionMixin
from lib.protocols.ics.s7_client import S7Client, snap7_available

from .base_shell import BaseShell


class S7CommShell(BaseShell, S7SessionMixin):
    """S7comm shell — identify PLC, read protection level, optional DB access via snap7."""

    def __init__(self, session_id: str, session_type: str = "s7comm", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: S7Client | None = None
        self.host = "localhost"
        self.port = 102

        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "protection": self._cmd_protection,
            "read-db": self._cmd_read_db,
            "write-db": self._cmd_write_db,
            "cpu-stop": self._cmd_cpu_stop,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_s7_client()
            info = self.get_s7_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 102)
        except Exception as exc:
            print_warning(f"Could not initialize S7comm connection: {exc}")

    def _require_client(self) -> S7Client:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("S7comm connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "s7comm"

    @property
    def prompt_template(self) -> str:
        return f"s7 [{self.host}]> "

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

    def _snap7_hint(self) -> str:
        if snap7_available():
            return ""
        return "Install python-snap7 for read-db / write-db / cpu-stop support.\n"

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        text = """
S7comm Shell Commands:
========================
  info                 Show CPU / module identification
  protection           Show protection level
  read-db <db> <start> <size>
                       Read DB bytes (requires python-snap7)
  write-db <db> <start> <hex>
                       Write raw bytes to DB (intrusive — requires snap7)
  cpu-stop             Stop PLC CPU (intrusive — requires snap7)
  exit / quit          Leave the shell
"""
        hint = self._snap7_hint()
        return {"output": (text.strip() + ("\n\n" + hint if hint else "") + "\n"), "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        identity = client.identify()
        lines = [
            f"Host: {identity.host}:{identity.port}",
            f"Backend: {identity.backend}",
            f"Module: {identity.module_type_name or 'unknown'}",
            f"Serial: {identity.serial_number or 'n/a'}",
            f"Firmware: {identity.firmware or 'n/a'}",
            f"Protection: {identity.protection_label}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_protection(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        info = client.get_protection_level()
        return {
            "output": (
                f"Protection level: {info.get('protection_level')} "
                f"({info.get('protection_label')})\n"
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_read_db(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        if len(parts) != 3:
            return {"output": "", "status": 1, "error": "Usage: read-db <db> <start> <size>"}
        db_number, start, size = int(parts[0]), int(parts[1]), int(parts[2])
        client = self._require_client()
        data = client.read_db(db_number, start, size)
        hex_dump = " ".join(f"{byte:02x}" for byte in data)
        return {"output": f"DB{db_number}@{start} ({len(data)} bytes): {hex_dump}\n", "status": 0, "error": ""}

    def _cmd_write_db(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        if len(parts) < 3:
            return {"output": "", "status": 1, "error": "Usage: write-db <db> <start> <hex_bytes>"}
        db_number, start = int(parts[0]), int(parts[1])
        hex_data = "".join(parts[2:]).replace(" ", "")
        try:
            payload = bytes.fromhex(hex_data)
        except ValueError:
            return {"output": "", "status": 1, "error": "Invalid hex payload"}
        client = self._require_client()
        client.write_db(db_number, start, payload)
        return {"output": f"Wrote {len(payload)} byte(s) to DB{db_number}@{start}\n", "status": 0, "error": ""}

    def _cmd_cpu_stop(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        if client.cpu_stop():
            return {"output": "CPU stop command sent.\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": "CPU stop failed"}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Disconnecting from S7comm shell.\n", "status": 0, "error": "", "exit": True}
