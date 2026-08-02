#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive UPnP / IGD shell."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.upnp.client import UpnpClient
from lib.protocols.upnp.session import UpnpSessionMixin

from .base_shell import BaseShell


class UpnpShell(BaseShell, UpnpSessionMixin):
    def __init__(self, session_id: str, session_type: str = "upnp", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: UpnpClient | None = None
        self.host = "localhost"
        self.port = 1900
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "device": self._cmd_device,
            "services": self._cmd_services,
            "extip": self._cmd_extip,
            "status": self._cmd_status,
            "portmaps": self._cmd_portmaps,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.open_upnp()
            info = self.get_upnp_connection_info()
            self.host = str(info.get("host") or getattr(self.client, "host", "localhost"))
            self.port = int(info.get("port") or 1900)
        except Exception as exc:
            print_warning(f"Could not initialize UPnP connection: {exc}")

    def _require(self) -> UpnpClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("UPnP connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "upnp"

    @property
    def prompt_template(self) -> str:
        return f"upnp [{self.host}]> "

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
UPnP Shell Commands:
========================
  info              Show LOCATION / SSDP headers
  device            Device identity (friendlyName, model, …)
  services          List services (controlURL)
  extip             IGD GetExternalIPAddress
  status            IGD GetStatusInfo
  portmaps [N]      Enumerate port mappings (default max 32)
  exit / quit       Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self._require()
        lines = [
            f"Host: {client.host}:{client.port}",
            f"LOCATION: {client.location}",
            f"SERVER: {client.server or '-'}",
            f"ST: {client.st or '-'}",
            f"USN: {client.usn or '-'}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_device(self, args: str) -> Dict[str, Any]:
        device = self._require().root_device
        if not device:
            return {"output": "(no device)\n", "status": 1, "error": "no device"}
        lines = [
            f"friendlyName: {device.friendly_name or '?'}",
            f"manufacturer: {device.manufacturer or '?'}",
            f"model: {device.model_name or '?'} {device.model_number or ''}".rstrip(),
            f"deviceType: {device.device_type or '?'}",
            f"UDN: {device.udn or '?'}",
            f"serial: {device.serial_number or '?'}",
            f"presentationURL: {device.presentation_url or '-'}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_services(self, args: str) -> Dict[str, Any]:
        services = self._require().list_services()
        if not services:
            return {"output": "(no services)\n", "status": 1, "error": "no services"}
        lines = []
        for i, svc in enumerate(services, 1):
            wan = " [WAN]" if svc.is_wan else ""
            lines.append(f"{i}. {svc.service_type}{wan}")
            lines.append(f"   control: {svc.control_url}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_extip(self, args: str) -> Dict[str, Any]:
        client = self._require()
        ip = client.get_external_ip()
        if not ip:
            return {"output": "", "status": 1, "error": client.last_error or "GetExternalIPAddress failed"}
        return {"output": f"External IP: {ip}\n", "status": 0, "error": ""}

    def _cmd_status(self, args: str) -> Dict[str, Any]:
        client = self._require()
        info = client.get_status_info()
        if not info:
            return {"output": "", "status": 1, "error": client.last_error or "GetStatusInfo failed"}
        lines = [f"{k}: {v}" for k, v in info.items()]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_portmaps(self, args: str) -> Dict[str, Any]:
        max_entries = 32
        if args.strip():
            try:
                max_entries = int(args.strip())
            except ValueError:
                return {"output": "", "status": 1, "error": "Usage: portmaps [max]"}
        client = self._require()
        mappings = client.get_port_mappings(max_entries=max_entries)
        if not mappings:
            err = client.last_error or "no mappings (or WAN service missing)"
            return {"output": f"(empty) {err}\n", "status": 0, "error": ""}
        lines = [f"Port mappings ({len(mappings)}):"]
        for i, m in enumerate(mappings, 1):
            proto = m.get("NewProtocol") or m.get("Protocol") or "?"
            eport = m.get("NewExternalPort") or m.get("ExternalPort") or "?"
            ihost = m.get("NewInternalClient") or m.get("InternalClient") or "?"
            iport = m.get("NewInternalPort") or m.get("InternalPort") or "?"
            desc = m.get("NewPortMappingDescription") or m.get("Description") or ""
            lines.append(f"  [{i}] {proto} {eport} -> {ihost}:{iport} {desc}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting UPnP shell\n", "status": 0, "error": "", "exit": True}
