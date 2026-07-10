#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive Modbus TCP shell for register reads and controlled writes."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.ics_session_mixin import ModbusSessionMixin
from lib.protocols.ics.modbus_client import ModbusTCPClient

from .base_shell import BaseShell


class ModbusShell(BaseShell, ModbusSessionMixin):
    """Modbus shell — scan units, read registers, write single register."""

    def __init__(self, session_id: str, session_type: str = "modbus", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: ModbusTCPClient | None = None
        self.host = "localhost"
        self.port = 502
        self.unit_id = 1

        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "unit": self._cmd_unit,
            "scan-units": self._cmd_scan_units,
            "read-holding": self._cmd_read_holding,
            "read-input": self._cmd_read_input,
            "write-register": self._cmd_write_register,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_modbus_client()
            info = self.get_modbus_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 502)
            self.unit_id = int(info.get("unit_id") or 1)
        except Exception as exc:
            print_warning(f"Could not initialize Modbus connection: {exc}")

    def _require_client(self) -> ModbusTCPClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("Modbus connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "modbus"

    @property
    def prompt_template(self) -> str:
        return f"modbus [{self.host}:unit{self.unit_id}]> "

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
Modbus Shell Commands:
========================
  info                 Show connection details
  unit <id>            Set default unit ID
  scan-units [start] [end]
                       Scan responsive unit IDs
  read-holding <addr> [count]
                       Read holding registers (FC3)
  read-input <addr> [count]
                       Read input registers (FC4)
  write-register <addr> <value>
                       Write single holding register (FC6)
  exit / quit          Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        info = self.get_modbus_connection_info()
        lines = [
            f"Host: {info.get('host')}:{info.get('port')}",
            f"Default unit ID: {self.unit_id}",
        ]
        session = self._resolve_session()
        if session:
            units = self._session_data(session).get("units") or []
            if units:
                ids = ", ".join(str(item.get("unit_id")) for item in units[:16])
                lines.append(f"Known units: {ids}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_unit(self, args: str) -> Dict[str, Any]:
        value = (args or "").strip()
        if not value:
            return {"output": "", "status": 1, "error": "Usage: unit <id>"}
        self.unit_id = int(value)
        return {"output": f"Default unit ID set to {self.unit_id}\n", "status": 0, "error": ""}

    def _cmd_scan_units(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        start = int(parts[0]) if len(parts) > 0 else 1
        end = int(parts[1]) if len(parts) > 1 else 32
        client = self._require_client()
        results = client.scan_unit_ids(start, end)
        if not results:
            return {"output": "No responsive unit IDs found.\n", "status": 0, "error": ""}
        lines = [f"  unit_id={item.unit_id} values={item.values[:4]}" for item in results]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_read_holding(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: read-holding <addr> [count]"}
        address = int(parts[0])
        count = int(parts[1]) if len(parts) > 1 else 1
        client = self._require_client()
        result = client.read_holding_registers(self.unit_id, address, count)
        if not result.success:
            return {"output": "", "status": 1, "error": result.raw_error or f"exception {result.error_code}"}
        return {"output": f"values={result.values}\n", "status": 0, "error": ""}

    def _cmd_read_input(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: read-input <addr> [count]"}
        address = int(parts[0])
        count = int(parts[1]) if len(parts) > 1 else 1
        client = self._require_client()
        result = client.read_input_registers(self.unit_id, address, count)
        if not result.success:
            return {"output": "", "status": 1, "error": result.raw_error or f"exception {result.error_code}"}
        return {"output": f"values={result.values}\n", "status": 0, "error": ""}

    def _cmd_write_register(self, args: str) -> Dict[str, Any]:
        parts = (args or "").split()
        if len(parts) != 2:
            return {"output": "", "status": 1, "error": "Usage: write-register <addr> <value>"}
        address, value = int(parts[0]), int(parts[1])
        client = self._require_client()
        result = client.write_single_register(self.unit_id, address, value)
        if not result.success:
            return {"output": "", "status": 1, "error": result.raw_error or f"exception {result.error_code}"}
        return {"output": f"Wrote register {address} = {value}\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Disconnecting from Modbus shell.\n", "status": 0, "error": "", "exit": True}
