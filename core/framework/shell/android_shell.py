#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Android shell implementation for ANDROID (ADB) sessions.

This shell expects the listener to store a ppadb device object in
listener._session_connections[session_id].
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base_shell import BaseShell
from core.output_handler import print_error, print_info


class AndroidShell(BaseShell):
    """ADB-backed interactive shell for Android sessions"""

    def __init__(self, session_id: str, session_type: str = "android", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework

        self.device: Optional[Any] = None  # ppadb.device.Device
        self.serial: Optional[str] = None
        self.is_connected: bool = False

        self._initialize_adb_device()

        # Built-ins kept intentionally small: everything else is forwarded to `device.shell()`.
        self.builtin_commands = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "back": self._cmd_exit,
            "background": self._cmd_exit,
            "status": self._cmd_status,
        }

    @property
    def shell_name(self) -> str:
        return "android"

    @property
    def prompt_template(self) -> str:
        return "android({serial})> "

    def get_prompt(self) -> str:
        if not self.is_connected or not self.device:
            return "[!] android(not connected)> "
        serial = self.serial or getattr(self.device, "serial", None) or "device"
        return self.prompt_template.format(serial=serial)

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
            except Exception as e:
                return {"output": "", "status": 1, "error": f"Built-in command error: {e}"}

        # Lazy reconnect attempt
        if not self.device or not self.is_connected:
            self._initialize_adb_device()

        if not self.device or not self.is_connected:
            return {"output": "", "status": 1, "error": "Not connected to Android device (ADB)."}

        try:
            # ppadb returns the command output as a string.
            out = self.device.shell(command)
            if out is None:
                out = ""
            # Normalize output to end with newline for the interactive loop display.
            if out and not out.endswith("\n"):
                out += "\n"
            return {"output": out, "status": 0, "error": ""}
        except Exception as e:
            # Most errors here mean ADB connection is gone.
            self.is_connected = False
            self.device = None
            return {"output": "", "status": 1, "error": f"ADB shell error: {e}"}

    def _initialize_adb_device(self) -> None:
        """Find the ppadb device object from the listener/session mapping."""
        try:
            if not self.framework or not hasattr(self.framework, "session_manager"):
                return

            session = self.framework.session_manager.get_session(self.session_id)
            if not session:
                return

            # Try active listener first (most reliable)
            listener_id = None
            if getattr(session, "data", None) and isinstance(session.data, dict):
                listener_id = session.data.get("listener_id")
                self.serial = session.data.get("adb_device_id") or session.host

            if listener_id and hasattr(self.framework, "active_listeners"):
                listener = self.framework.active_listeners.get(listener_id)
                if listener and hasattr(listener, "_session_connections") and self.session_id in listener._session_connections:
                    self.device = listener._session_connections[self.session_id]
                    self.serial = getattr(self.device, "serial", None) or self.serial or session.host
                    self.hostname = self.serial or "android"
                    self.username = "shell"
                    self.is_connected = self.device is not None
                    return

            # Fallback: current module
            if hasattr(self.framework, "current_module") and self.framework.current_module:
                listener = self.framework.current_module
                if hasattr(listener, "_session_connections") and self.session_id in listener._session_connections:
                    self.device = listener._session_connections[self.session_id]
                    self.serial = getattr(self.device, "serial", None) or self.serial or session.host
                    self.hostname = self.serial or "android"
                    self.username = "shell"
                    self.is_connected = self.device is not None
                    return

            # Fallback: scan loaded modules for a listener holding this session connection
            if hasattr(self.framework, "modules") and self.framework.modules:
                for _, module in self.framework.modules.items():
                    if hasattr(module, "_session_connections") and self.session_id in module._session_connections:
                        self.device = module._session_connections[self.session_id]
                        self.serial = getattr(self.device, "serial", None) or self.serial or session.host
                        self.hostname = self.serial or "android"
                        self.username = "shell"
                        self.is_connected = self.device is not None
                        return

        except Exception as e:
            # Don't crash shell creation; just mark as disconnected.
            self.device = None
            self.is_connected = False
            print_error(f"Error initializing Android ADB device: {e}")

    # Built-ins
    def _cmd_help(self, _args: str) -> Dict[str, Any]:
        help_text = """Android (ADB) shell:
  help                 Show this help
  status               Show ADB connection status
  exit/back/background Return to KittySploit main prompt

Any other command is executed via ADB: device.shell(<command>).
Example:
  id
  getprop ro.build.version.release
  pm list packages | head
"""
        return {"output": help_text, "status": 0, "error": ""}

    def _cmd_exit(self, _args: str) -> Dict[str, Any]:
        # We don't close ADB here; we just exit the interactive shell loop.
        self.deactivate()
        return {"output": "", "status": 0, "error": ""}

    def _cmd_status(self, _args: str) -> Dict[str, Any]:
        serial = self.serial or (getattr(self.device, "serial", None) if self.device else None) or "unknown"
        status = "connected" if self.is_connected and self.device else "disconnected"
        return {"output": f"ADB device: {serial}\nStatus: {status}\n", "status": 0, "error": ""}

