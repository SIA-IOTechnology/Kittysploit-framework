#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive IEC 60870-5-104 shell for STARTDT, interrogation, and gated commands."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.iec104_client import Iec104Client
from lib.protocols.ics.ics_session_mixin import Iec104SessionMixin

from .base_shell import BaseShell


class Iec104Shell(BaseShell, Iec104SessionMixin):
    def __init__(self, session_id: str, session_type: str = "iec104", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: Iec104Client | None = None
        self.host = "localhost"
        self.port = 2404
        self.common_address = 1
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "ca": self._cmd_ca,
            "startdt": self._cmd_startdt,
            "interrogate": self._cmd_interrogate,
            "dump": self._cmd_dump,
            "sc": self._cmd_single_command,
            "dc": self._cmd_double_command,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_iec104_client()
            info = self.get_iec104_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 2404)
            self.common_address = int(info.get("common_address") or 1)
        except Exception as exc:
            print_warning(f"Could not initialize IEC 104 connection: {exc}")

    def _require_client(self) -> Iec104Client:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("IEC 104 connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "iec104"

    @property
    def prompt_template(self) -> str:
        return f"iec104 [{self.host}:ca{self.common_address}]> "

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
IEC 104 Shell Commands:
========================
  info              Show connection details
  ca <addr>         Set ASDU common address
  startdt           Send STARTDT activation
  interrogate       General interrogation (C_IC_NA_1)
  dump [max]        Interrogation + collect response frames
  sc <ioa> <0|1> confirm [select]
                    Single command C_SC_NA_1 (intrusive)
  dc <ioa> <1|2> confirm [select]
                    Double command C_DC_NA_1 (1=OFF 2=ON)
  exit / quit       Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        info = self.get_iec104_connection_info()
        lines = [
            f"Host: {info.get('host')}:{info.get('port')}",
            f"Common address: {self.common_address}",
            f"Connected: {bool(self.client and self.client.connected)}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_ca(self, args: str) -> Dict[str, Any]:
        if not args.strip():
            return {"output": f"ca={self.common_address}\n", "status": 0, "error": ""}
        self.common_address = int(args.strip().split()[0])
        client = self._require_client()
        client.common_address = self.common_address
        return {"output": f"Common address set to {self.common_address}\n", "status": 0, "error": ""}

    def _cmd_startdt(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        ok = client.startdt()
        if not ok:
            return {"output": "", "status": 1, "error": "STARTDT not confirmed"}
        return {"output": "STARTDT confirmed\n", "status": 0, "error": ""}

    def _cmd_interrogate(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        if not client.startdt():
            return {"output": "", "status": 1, "error": "STARTDT failed before interrogation"}
        ok = client.general_interrogation()
        if not ok:
            return {"output": "", "status": 1, "error": "Interrogation send failed"}
        return {"output": "General interrogation sent\n", "status": 0, "error": ""}

    def _cmd_dump(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        max_frames = int(args.strip().split()[0]) if args.strip() else 16
        if not client.startdt():
            return {"output": "", "status": 1, "error": "STARTDT not confirmed"}
        if not client.general_interrogation():
            return {"output": "", "status": 1, "error": "Interrogation send failed"}
        frames = client.collect_frames(max_frames)
        lines = [f"frames={len(frames)}"]
        for frame in frames[:max_frames]:
            lines.append(f"  {frame[:80]}{'...' if len(frame) > 80 else ''}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_single_command(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if len(parts) < 3 or "confirm" not in [p.lower() for p in parts]:
            return {
                "output": "",
                "status": 1,
                "error": "Usage: sc <ioa> <0|1> confirm [select]",
            }
        ioa = int(parts[0])
        value = bool(int(parts[1]))
        select = any(p.lower() == "select" for p in parts)
        client = self._require_client()
        if not client.startdt():
            return {"output": "", "status": 1, "error": "STARTDT not confirmed"}
        if not client.single_command(ioa, value, select=select):
            return {"output": "", "status": 1, "error": "Single command failed"}
        return {
            "output": f"C_SC_NA_1 sent IOA={ioa} value={int(value)} select={select}\n",
            "status": 0,
            "error": "",
        }

    def _cmd_double_command(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if len(parts) < 3 or "confirm" not in [p.lower() for p in parts]:
            return {
                "output": "",
                "status": 1,
                "error": "Usage: dc <ioa> <1|2> confirm [select]",
            }
        ioa = int(parts[0])
        value = int(parts[1])
        select = any(p.lower() == "select" for p in parts)
        client = self._require_client()
        if not client.startdt():
            return {"output": "", "status": 1, "error": "STARTDT not confirmed"}
        if not client.double_command(ioa, value, select=select):
            return {"output": "", "status": 1, "error": "Double command failed"}
        return {
            "output": f"C_DC_NA_1 sent IOA={ioa} dco={value} select={select}\n",
            "status": 0,
            "error": "",
        }

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting IEC 104 shell\n", "status": 0, "error": "", "exit": True}
