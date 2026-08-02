#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive DNP3 shell for identify / integrity / read / gated operate."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.dnp3_client import (
    GRP_ANALOG_INPUT,
    GRP_BINARY_INPUT,
    Dnp3Client,
)
from lib.protocols.ics.ics_session_mixin import Dnp3SessionMixin

from .base_shell import BaseShell


class Dnp3Shell(BaseShell, Dnp3SessionMixin):
    def __init__(self, session_id: str, session_type: str = "dnp3", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: Dnp3Client | None = None
        self.host = "localhost"
        self.port = 20000
        self.dest = 1
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "dest": self._cmd_dest,
            "identify": self._cmd_identify,
            "integrity": self._cmd_integrity,
            "read": self._cmd_read,
            "probe_operate": self._cmd_probe_operate,
            "operate": self._cmd_operate,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_dnp3_client()
            info = self.get_dnp3_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 20000)
            self.dest = int(info.get("dest") or 1)
        except Exception as exc:
            print_warning(f"Could not initialize DNP3 connection: {exc}")

    def _require_client(self) -> Dnp3Client:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("DNP3 connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "dnp3"

    @property
    def prompt_template(self) -> str:
        return f"dnp3 [{self.host}:dest{self.dest}]> "

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
DNP3 Shell Commands:
========================
  info                         Show connection details
  dest <addr>                  Set outstation destination address
  identify                     Device attribute / identify probe
  integrity                    Integrity poll (class 0/1/2/3)
  read [binary|analog] [start] [count]
                               Read input points
  probe_operate [index]        Non-destructive SELECT/DirectOperate probe
  operate <index> [control] confirm
                               CROB Select/Operate (intrusive — requires confirm)
  exit / quit                  Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        info = self.get_dnp3_connection_info()
        lines = [
            f"Host: {info.get('host')}:{info.get('port')}",
            f"Source: {info.get('src')}  Dest: {self.dest}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_dest(self, args: str) -> Dict[str, Any]:
        if not args.strip():
            return {"output": f"dest={self.dest}\n", "status": 0, "error": ""}
        self.dest = int(args.strip().split()[0])
        client = self._require_client()
        client.dest = self.dest
        return {"output": f"Destination set to {self.dest}\n", "status": 0, "error": ""}

    def _cmd_identify(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        result = client.identify()
        if result.error:
            return {"output": "", "status": 1, "error": result.error}
        strings = getattr(result, "strings", None) or []
        lines = [f"identify ok — {len(strings)} string(s)"] + [f"  {s}" for s in strings[:20]]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_integrity(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        result = client.integrity_poll()
        err = getattr(result, "error", "") or ""
        if err and not result.connected:
            return {"output": "", "status": 1, "error": err}
        points = getattr(result, "points", None) or {}
        if isinstance(points, dict):
            detail = ", ".join(f"{k}={v}" for k, v in list(points.items())[:12])
        else:
            detail = str(points)
        classes = getattr(result, "class_results", None) or {}
        return {
            "output": f"integrity poll ok — classes={classes} points={{ {detail} }}\n",
            "status": 0,
            "error": "",
        }

    def _cmd_read(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        kind = parts[0].lower() if parts else "binary"
        start = int(parts[1]) if len(parts) > 1 else 0
        count = int(parts[2]) if len(parts) > 2 else 10
        if kind.startswith("a"):
            group = GRP_ANALOG_INPUT
        else:
            group = GRP_BINARY_INPUT
        stop = start + max(0, count - 1)
        client = self._require_client()
        result = client.read_points(group, 0x01, start, stop)
        if not result.success:
            return {"output": "", "status": 1, "error": result.error or "read failed"}
        lines = [f"read ok — {result.response_len} bytes"] + [
            f"  {s}" for s in (result.strings or [])[:12]
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_probe_operate(self, args: str) -> Dict[str, Any]:
        index = int(args.strip().split()[0]) if args.strip() else 0
        client = self._require_client()
        result = client.probe_operate_accepted(index)
        if result.error and not result.connected:
            return {"output": "", "status": 1, "error": result.error}
        return {
            "output": (
                f"probe_operate index={index} select={result.select_accepted} "
                f"direct={result.direct_operate_accepted}\n"
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_operate(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if len(parts) < 2 or parts[-1].lower() != "confirm":
            return {
                "output": "",
                "status": 1,
                "error": "Usage: operate <index> [control_hex_or_int] confirm",
            }
        index = int(parts[0], 0)
        control = int(parts[1], 0) if len(parts) > 2 else 0x41
        client = self._require_client()
        result = client.operate_crob(index, control, select_before=True)
        if result.error and not result.operate_accepted:
            return {"output": "", "status": 1, "error": result.error}
        return {
            "output": (
                f"operate accepted index={index} control=0x{control & 0xFF:02x} "
                f"select={result.select_accepted} operate={result.operate_accepted}\n"
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting DNP3 shell\n", "status": 0, "error": "", "exit": True}
