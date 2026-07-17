#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive BLE GATT shell for service discovery, read/write, and notify capture."""

from typing import Any, Dict, List, Optional

from core.output_handler import print_warning
from lib.protocols.ble.ble_client import BleGattClient, normalize_uuid
from lib.protocols.ble.ble_session_mixin import BleSessionMixin

from .base_shell import BaseShell


class BleShell(BaseShell, BleSessionMixin):
    """BLE GATT shell — services, characteristics, read, write, notify."""

    def __init__(self, session_id: str, session_type: str = "ble", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: Optional[BleGattClient] = None
        self.address = "unknown"
        self.name = ""

        self.builtin_commands = {
            "help": self._cmd_help,
            "?": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "services": self._cmd_services,
            "chars": self._cmd_chars,
            "characteristics": self._cmd_chars,
            "read": self._cmd_read,
            "write": self._cmd_write,
            "notify": self._cmd_notify,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
            "back": self._cmd_exit,
            "background": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.get_ble_client()
            info = self.get_ble_connection_info()
            self.address = str(info.get("address") or self.address)
            self.name = str(info.get("name") or "")
            if self.client:
                summary = self.client.connection_summary()
                self.address = str(summary.get("address") or self.address)
                self.name = str(summary.get("name") or self.name)
        except Exception as exc:
            print_warning(f"Could not initialize BLE connection: {exc}")

    def _require_client(self) -> BleGattClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("BLE GATT connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "ble"

    @property
    def prompt_template(self) -> str:
        label = self.name or self.address
        return f"ble [{label}]> "

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
BLE GATT Shell Commands:
========================
  info                         Show connection details
  services                     List GATT services
  chars [service_uuid]         List characteristics (optional service filter)
  read <uuid>                  Read characteristic value
  write <uuid> <hex|ascii:...> Write characteristic
                               Examples:
                                 write 2A00 48656c6c6f
                                 write 2A00 ascii:Hello
  notify <uuid> [seconds]      Capture notifications (default 5s)
  help                         Show this help
  exit / back / background     Return to main shell
"""
        return {"output": text.strip(), "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        lines = [f"  {i + 1}: {cmd}" for i, cmd in enumerate(self.command_history[-50:])]
        return {"output": "\n".join(lines) if lines else "(empty)", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        info = client.connection_summary()
        text = "\n".join(
            [
                f"address   : {info.get('address')}",
                f"name      : {info.get('name') or '-'}",
                f"adapter   : {info.get('adapter') or 'default'}",
                f"connected : {info.get('connected')}",
                f"services  : {info.get('services')}",
            ]
        )
        return {"output": text, "status": 0, "error": ""}

    def _cmd_services(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        services = client.get_services(refresh="--refresh" in args.split())
        lines = [f"Services ({len(services)}):"]
        for svc in services:
            lines.append(
                f"  {svc.uuid}  handle={svc.handle}  chars={len(svc.characteristics)}"
            )
        return {"output": "\n".join(lines), "status": 0, "error": ""}

    def _cmd_chars(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        filter_svc = normalize_uuid(args.strip()) if args.strip() and not args.strip().startswith("-") else ""
        services = client.get_services()
        lines = []
        count = 0
        for svc in services:
            if filter_svc and normalize_uuid(svc.uuid) != filter_svc:
                continue
            lines.append(f"Service {svc.uuid}")
            for char in svc.characteristics:
                props = ",".join(char.properties) if char.properties else "-"
                lines.append(f"  {char.uuid}  handle={char.handle}  [{props}]")
                count += 1
        if not lines:
            return {"output": "No characteristics found", "status": 0, "error": ""}
        lines.append(f"Total: {count}")
        return {"output": "\n".join(lines), "status": 0, "error": ""}

    def _cmd_read(self, args: str) -> Dict[str, Any]:
        uuid = args.strip()
        if not uuid:
            return {"output": "", "status": 1, "error": "Usage: read <uuid>"}
        client = self._require_client()
        data = client.read_characteristic(normalize_uuid(uuid) or uuid)
        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        text = f"hex  : {data.hex()}\nascii: {ascii_preview}\nlen  : {len(data)}"
        return {"output": text, "status": 0, "error": ""}

    def _cmd_write(self, args: str) -> Dict[str, Any]:
        parts = args.split(None, 1)
        if len(parts) < 2:
            return {
                "output": "",
                "status": 1,
                "error": "Usage: write <uuid> <hexbytes|ascii:text|utf8:text>",
            }
        uuid, payload_spec = parts[0], parts[1]
        if payload_spec.lower().startswith("ascii:"):
            payload = payload_spec[6:].encode("ascii", errors="replace")
        elif payload_spec.lower().startswith("utf8:"):
            payload = payload_spec[5:].encode("utf-8", errors="replace")
        else:
            cleaned = payload_spec.lower().replace("0x", " ").replace(",", " ").replace(":", " ")
            tokens = cleaned.split()
            if tokens:
                payload = bytes(int(t, 16) & 0xFF for t in tokens)
            else:
                hexstr = "".join(ch for ch in payload_spec.lower() if ch in "0123456789abcdef")
                if len(hexstr) % 2:
                    return {"output": "", "status": 1, "error": "odd-length hex string"}
                payload = bytes.fromhex(hexstr) if hexstr else b""

        client = self._require_client()
        client.write_characteristic(normalize_uuid(uuid) or uuid, payload)
        return {"output": f"Wrote {len(payload)} byte(s): {payload.hex()}", "status": 0, "error": ""}

    def _cmd_notify(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: notify <uuid> [seconds]"}
        uuid = parts[0]
        duration = 5.0
        if len(parts) > 1:
            try:
                duration = float(parts[1])
            except ValueError:
                return {"output": "", "status": 1, "error": "duration must be a number"}
        client = self._require_client()
        events = client.capture_notifications(
            [normalize_uuid(uuid) or uuid],
            duration=max(0.2, duration),
            clear=True,
        )
        if not events:
            return {"output": f"No notifications in {duration}s", "status": 0, "error": ""}
        lines = [f"Captured {len(events)} notification(s):"]
        for event in events[:50]:
            ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in event.data)
            lines.append(f"  {event.hex}  | {ascii_preview}")
        if len(events) > 50:
            lines.append(f"  ... {len(events) - 50} more")
        return {"output": "\n".join(lines), "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Returning to main shell (BLE session remains active)", "status": 0, "error": ""}
