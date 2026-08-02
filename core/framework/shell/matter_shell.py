#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive Matter shell — discovery / TXT inventory / UDP probe."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.matter.client import MatterClient, probe_matter_udp
from lib.protocols.matter.session import MatterSessionMixin

from .base_shell import BaseShell


class MatterShell(BaseShell, MatterSessionMixin):
    def __init__(self, session_id: str, session_type: str = "matter", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: MatterClient | None = None
        self.host = ""
        self.port = 5540
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "discover": self._cmd_discover,
            "devices": self._cmd_devices,
            "inventory": self._cmd_inventory,
            "txt": self._cmd_txt,
            "probe": self._cmd_probe,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.open_matter(connect=True)
            info = self.get_matter_connection_info()
            self.host = str(info.get("host") or getattr(self.client, "host", "") or "multicast")
            self.port = int(info.get("port") or getattr(self.client, "port", 5540))
        except Exception as exc:
            print_warning(f"Could not initialize Matter discovery: {exc}")

    def _require(self) -> MatterClient:
        if not self.client:
            self._initialize_connection()
        if not self.client:
            raise RuntimeError("Matter client not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "matter"

    @property
    def prompt_template(self) -> str:
        return f"matter [{self.host}:{self.port}]> "

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
Matter Shell Commands:
========================
  info                 Show session / discovery details
  discover [udp]       Re-run mDNS Matter discovery (add 'udp' to probe 5540)
  devices              List discovered nodes (short)
  inventory            Full inventory summary
  txt [index]          Dump raw TXT for device index (default 0)
  probe [host]         UDP/5540 reachability probe
  exit / quit          Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self._require()
        info = self.get_matter_connection_info()
        lines = [
            f"Host: {info.get('host') or '*'}",
            f"Port: {info.get('port')}",
            f"Multicast: {info.get('multicast')}",
            f"Devices: {len(client.devices)}",
            f"Connected: {bool(client.connected)}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_discover(self, args: str) -> Dict[str, Any]:
        client = self._require()
        probe = "udp" in args.lower()
        result = client.discover(probe_udp=probe)
        client.connected = bool(result.devices)
        if not result.devices:
            return {
                "output": "",
                "status": 1,
                "error": result.error or "No Matter nodes found",
            }
        lines = [f"Found {len(result.devices)} device(s) mode={result.mode}"]
        for i, d in enumerate(result.devices):
            kind = "C" if d.commissionable else "O"
            lines.append(
                f"  [{i}] [{kind}] {d.device_name or d.instance or d.host} "
                f"vid={d.vendor_id or '-'} pid={d.product_id or '-'} "
                f"type={d.device_type_name or d.device_type or '-'}"
            )
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_devices(self, args: str) -> Dict[str, Any]:
        client = self._require()
        if not client.devices:
            client.discover(probe_udp=False)
        if not client.devices:
            return {"output": "No devices cached — run discover\n", "status": 0, "error": ""}
        lines = []
        for i, d in enumerate(client.devices):
            kind = "commissionable" if d.commissionable else "operational"
            addr = (d.addresses[0] if d.addresses else d.host) or "-"
            lines.append(
                f"[{i}] {kind} {d.device_name or d.instance or '-'} @ {addr}:{d.port or '-'} "
                f"{d.vendor_name or d.vendor_id or ''} "
                f"{d.device_type_name or ''}".rstrip()
            )
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_inventory(self, args: str) -> Dict[str, Any]:
        client = self._require()
        data = client.inventory()
        lines = [
            f"count={data.get('count')} commissionable={data.get('commissionable')} "
            f"operational={data.get('operational')}"
        ]
        for i, d in enumerate(data.get("devices") or []):
            lines.append(
                f"  [{i}] {d.get('device_name') or d.get('instance')} "
                f"vid={d.get('vendor_id')} type={d.get('device_type_name') or d.get('device_type')} "
                f"cm={d.get('commissioning_mode_name') or d.get('commissioning_mode')} "
                f"disc={d.get('discriminator')} udp={d.get('udp_reachable')}"
            )
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_txt(self, args: str) -> Dict[str, Any]:
        client = self._require()
        if not client.devices:
            client.discover(probe_udp=False)
        if not client.devices:
            return {"output": "", "status": 1, "error": "No devices"}
        idx = 0
        if args.strip().isdigit():
            idx = int(args.strip())
        if idx < 0 or idx >= len(client.devices):
            return {"output": "", "status": 1, "error": f"index out of range 0..{len(client.devices)-1}"}
        device = client.devices[idx]
        if not device.raw_txt:
            return {"output": "(empty TXT)\n", "status": 0, "error": ""}
        lines = [f"{k}={v}" for k, v in sorted(device.raw_txt.items())]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_probe(self, args: str) -> Dict[str, Any]:
        client = self._require()
        host = args.strip() or self.host
        if not host or host == "multicast":
            if client.devices:
                host = (client.devices[0].addresses or [client.devices[0].host] or [""])[0]
        if not host:
            return {"output": "", "status": 1, "error": "host required"}
        result = probe_matter_udp(host, self.port, timeout=2.0)
        if result.get("reachable"):
            return {
                "output": f"UDP reachable {host}:{self.port} bytes={result.get('bytes')} "
                f"peer={result.get('peer')}\n",
                "status": 0,
                "error": "",
            }
        return {
            "output": "",
            "status": 1,
            "error": f"no reply from {host}:{self.port} ({result.get('error')})",
        }

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting Matter shell\n", "status": 0, "error": "", "exit": True}
