#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive SMB shell for file share operations."""

import os
import tempfile
from typing import Any, Dict, List

from core.output_handler import print_error, print_success, print_warning
from lib.protocols.smb.smb_client import SMBClient
from .base_shell import BaseShell


class SMBShell(BaseShell):
    """SMB shell — browse shares and transfer files over an authenticated SMB session."""

    def __init__(self, session_id: str, session_type: str = "smb", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.client: SMBClient | None = None
        self.host = "localhost"
        self.port = 445
        self.username = ""
        self.domain = ""
        self.current_share = ""
        self.current_path = "\\"
        self._shares: List[str] = []

        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "shares": self._cmd_shares,
            "use": self._cmd_use,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "ls": self._cmd_ls,
            "dir": self._cmd_ls,
            "get": self._cmd_get,
            "put": self._cmd_put,
            "download": self._cmd_get,
            "upload": self._cmd_put,
            "mkdir": self._cmd_mkdir,
            "rmdir": self._cmd_rmdir,
            "rm": self._cmd_rm,
            "delete": self._cmd_rm,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }

        self._initialize_connection()

    def _initialize_connection(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session or not session.data:
            return

        data = session.data if isinstance(session.data, dict) else {}
        self.host = data.get("host", "localhost")
        self.port = data.get("port", 445)
        self.username = data.get("username", "")
        self.domain = data.get("domain", "")
        self._shares = list(data.get("shares") or [])

        listener_id = data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(self.session_id)
                if isinstance(conn, SMBClient):
                    self.client = conn
                    return

        conn = data.get("connection")
        if isinstance(conn, SMBClient):
            self.client = conn

    @property
    def shell_name(self) -> str:
        return "smb"

    @property
    def prompt_template(self) -> str:
        if self.current_share:
            path = self.current_path.rstrip("\\") or "\\"
            return f"smb [{self.current_share}{path}]> "
        return f"smb [{self.host}]> "

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
            except Exception as e:
                return {"output": "", "status": 1, "error": str(e)}
        share_lookup = {share.lower(): share for share in self._shares}
        if cmd in share_lookup:
            return self._cmd_use(share_lookup[cmd])
        return {"output": "", "status": 1, "error": f"Unknown command: {cmd}. Type help."}

    def _require_client(self) -> SMBClient:
        if not self.client:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("SMB connection not available")
        return self.client

    def _normalize_remote_path(self, path: str) -> str:
        path = (path or "").strip()
        if not path:
            return self.current_path
        if path.startswith("\\\\"):
            parts = path.strip("\\").split("\\", 1)
            if len(parts) == 2:
                self.current_share = parts[0]
                return self._normalize_remote_path("\\" + parts[1])
            self.current_share = parts[0]
            return "\\"
        if not path.startswith("\\"):
            base = self.current_path.rstrip("\\")
            path = f"{base}\\{path}" if base else f"\\{path}"
        while "\\..\\" in path:
            path = path.replace("\\..\\", "\\")
        return path.replace("\\\\", "\\")

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        text = """
SMB Shell Commands:
====================
  shares              List available SMB shares
  use <share>         Select a share (e.g. use C$)
  pwd                 Show current share/path
  cd <path>           Change directory within current share
  ls / dir            List current remote directory
  get <remote> [local] Download a remote file
  put <local> [remote] Upload a local file
  mkdir <path>        Create remote directory
  rmdir <path>        Delete remote directory
  rm / delete <path>  Delete remote file
  exit / quit         Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_shares(self, args: str) -> Dict[str, Any]:
        client = self._require_client()
        shares = client.list_shares()
        self._shares = shares
        if not shares:
            return {"output": "No shares visible.\n", "status": 0, "error": ""}
        lines = [f"  {name}" for name in shares]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_use(self, args: str) -> Dict[str, Any]:
        share = (args or "").strip().strip("\\")
        if not share:
            return {"output": "", "status": 1, "error": "Usage: use <share>"}
        self.current_share = share
        self.current_path = "\\"
        return {"output": f"Using share {share}\n", "status": 0, "error": ""}

    def _cmd_pwd(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": f"\\\\{self.host}\n", "status": 0, "error": ""}
        return {"output": f"\\\\{self.host}\\{self.current_share}{self.current_path}\n", "status": 0, "error": ""}

    def _cmd_cd(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        new_path = self._normalize_remote_path(args or "\\")
        client = self._require_client()
        entries = client.list_path(self.current_share, new_path)
        if entries or new_path == "\\":
            self.current_path = new_path if new_path.endswith("\\") else new_path + "\\"
            return {"output": "", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"cd: {args}: No such directory"}

    def _cmd_ls(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        client = self._require_client()
        path = self._normalize_remote_path(args) if args else self.current_path
        entries = client.list_path(self.current_share, path)
        if not entries:
            return {"output": "(empty)\n", "status": 0, "error": ""}
        lines = []
        for entry in entries:
            marker = "d" if entry.get("is_dir") else "-"
            size = entry.get("size", 0)
            lines.append(f"{marker} {entry.get('name', ''):<40} {size:>10}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_get(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        parts = (args or "").split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: get <remote_path> [local_path]"}
        remote_path = self._normalize_remote_path(parts[0])
        local_path = parts[1] if len(parts) > 1 else os.path.basename(remote_path.strip("\\"))
        client = self._require_client()
        if client.get_file(self.current_share, remote_path, local_path):
            return {"output": f"Saved to {local_path}\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"Download failed: {remote_path}"}

    def _cmd_put(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        parts = (args or "").split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: put <local_path> [remote_path]"}
        local_path = parts[0]
        if not os.path.isfile(local_path):
            return {"output": "", "status": 1, "error": f"Local file not found: {local_path}"}
        remote_name = parts[1] if len(parts) > 1 else os.path.basename(local_path)
        remote_path = self._normalize_remote_path(remote_name)
        client = self._require_client()
        if client.put_file(self.current_share, local_path, remote_path):
            return {"output": f"Uploaded to \\\\{self.host}\\{self.current_share}{remote_path}\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"Upload failed: {remote_path}"}

    def _cmd_mkdir(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        if not args.strip():
            return {"output": "", "status": 1, "error": "Usage: mkdir <path>"}
        client = self._require_client()
        remote_path = self._normalize_remote_path(args.strip())
        if client.create_directory(self.current_share, remote_path):
            return {"output": f"Created {remote_path}\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"mkdir failed: {remote_path}"}

    def _cmd_rmdir(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        if not args.strip():
            return {"output": "", "status": 1, "error": "Usage: rmdir <path>"}
        client = self._require_client()
        remote_path = self._normalize_remote_path(args.strip())
        if client.delete_directory(self.current_share, remote_path):
            return {"output": f"Removed {remote_path}\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"rmdir failed: {remote_path}"}

    def _cmd_rm(self, args: str) -> Dict[str, Any]:
        if not self.current_share:
            return {"output": "", "status": 1, "error": "Select a share first with: use <share>"}
        if not args.strip():
            return {"output": "", "status": 1, "error": "Usage: rm <path>"}
        client = self._require_client()
        remote_path = self._normalize_remote_path(args.strip())
        if client.delete_file(self.current_share, remote_path):
            return {"output": f"Deleted {remote_path}\n", "status": 0, "error": ""}
        return {"output": "", "status": 1, "error": f"rm failed: {remote_path}"}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Disconnecting from SMB shell.\n", "status": 0, "error": "", "exit": True}
