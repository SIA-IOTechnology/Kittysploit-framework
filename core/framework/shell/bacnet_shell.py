#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive BACnet/IP shell for Who-Is, property reads, and gated writes."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.ics.bacnet_client import BacnetClient
from lib.protocols.ics.ics_session_mixin import BacnetSessionMixin

from .base_shell import BaseShell


class BacnetShell(BaseShell, BacnetSessionMixin):
    def __init__(self, session_id: str, session_type: str = "bacnet", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: BacnetClient | None = None
        self.host = "localhost"
        self.port = 47808
        self.device_id = 0
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "device": self._cmd_device,
            "whois": self._cmd_whois,
            "inventory": self._cmd_inventory,
            "read": self._cmd_read,
            "write": self._cmd_write,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_bacnet_client()
            info = self.get_bacnet_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 47808)
            self.device_id = int(info.get("device_id") or getattr(self.client, "device_id", 0) or 0)
        except Exception as exc:
            print_warning(f"Could not initialize BACnet connection: {exc}")

    def _require_client(self) -> BacnetClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("BACnet connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "bacnet"

    @property
    def prompt_template(self) -> str:
        return f"bacnet [{self.host}:dev{self.device_id}]> "

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
BACnet Shell Commands:
========================
  info                         Show connection details
  device <id>                  Set default device instance
  whois [broadcast]            Send Who-Is / list I-Am devices
  inventory [device_id]        Read object-list property
  read <objType> <objInst> <propId>
                               ReadProperty request
  write <objType> <objInst> <propId> <intValue> confirm
                               WriteProperty (intrusive — requires trailing confirm)
  exit / quit                  Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        info = self.get_bacnet_connection_info()
        lines = [
            f"Host: {info.get('host')}:{info.get('port')}",
            f"Device ID: {self.device_id}",
            f"Discovered devices: {len(getattr(self.client, 'devices', []) or [])}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_device(self, args: str) -> Dict[str, Any]:
        if not args.strip():
            return {"output": f"device_id={self.device_id}\n", "status": 0, "error": ""}
        self.device_id = int(args.strip().split()[0])
        client = self._require_client()
        client.device_id = self.device_id
        return {"output": f"Default device_id set to {self.device_id}\n", "status": 0, "error": ""}

    def _cmd_whois(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        broadcast = "broadcast" in args.lower()
        devices = client.who_is(broadcast=broadcast)
        if self.device_id <= 0 and client.device_id:
            self.device_id = client.device_id
        if not devices:
            return {"output": "No I-Am responses\n", "status": 0, "error": ""}
        lines = [
            f"device_id={d.device_id} vendor={d.vendor_id} {d.host}:{d.port}"
            for d in devices
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_inventory(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        did = int(args.strip().split()[0]) if args.strip() else self.device_id
        items = client.inventory(did)
        if not items:
            return {"output": "No inventory data\n", "status": 0, "error": ""}
        lines = [
            f"device={it.get('device_id')} bytes={len(it.get('raw_hex', '')) // 2} "
            f"hint={it.get('object_count_hint')}"
            for it in items
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_read(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if len(parts) < 3:
            return {
                "output": "",
                "status": 1,
                "error": "Usage: read <objType> <objInst> <propId>",
            }
        client = self._require_client()
        raw = client.read_prop(int(parts[0]), int(parts[1]), int(parts[2]))
        return {"output": f"{len(raw)} bytes: {raw.hex()}\n", "status": 0, "error": ""}

    def _cmd_write(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if len(parts) < 5 or parts[-1].lower() != "confirm":
            return {
                "output": "",
                "status": 1,
                "error": "Usage: write <objType> <objInst> <propId> <intValue> confirm",
            }
        client = self._require_client()
        value = int(parts[3])
        payload = bytes([0x21, value & 0xFF])
        raw = client.write_prop(int(parts[0]), int(parts[1]), int(parts[2]), payload)
        if not raw:
            return {"output": "", "status": 1, "error": "No WriteProperty response"}
        return {"output": f"WriteProperty ok — {len(raw)} bytes: {raw.hex()}\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting BACnet shell\n", "status": 0, "error": "", "exit": True}
