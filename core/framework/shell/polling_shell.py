#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic shell for listener-backed polling transports."""

import shlex
import time
from typing import Any, Dict, List, Optional

from .base_shell import BaseShell


class PollingShell(BaseShell):
    """Queue commands through a listener and read buffered output."""

    def __init__(self, session_id: str, session_type: str = "polling", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.listener = None
        self.transport = session_type or "polling"
        self.client_id = ""
        self.client_ip = ""
        self._initialize_listener()

    def _initialize_listener(self):
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        self.transport = (
            session.data.get("protocol", session.session_type)
            if session.data
            else session.session_type
        )
        self.client_id = session.data.get("client_id", "") if session.data else ""
        self.client_ip = (
            session.data.get("client_ip", session.host) if session.data else session.host
        )
        listener_id = session.data.get("listener_id") if session.data else None
        if listener_id and hasattr(self.framework, "active_listeners"):
            self.listener = self.framework.active_listeners.get(listener_id)
            if self.listener:
                return
        active = getattr(self.framework, "active_listeners", None) or {}
        for listener in active.values():
            if hasattr(listener, "set_pending_command") and hasattr(
                listener, "get_output_lines"
            ):
                session_map = getattr(listener, "_session_to_client_id", {}) or {}
                if self.session_id in session_map:
                    self.listener = listener
                    return
        for module in getattr(self.framework, "modules", {}).values():
            if hasattr(module, "set_pending_command") and hasattr(
                module, "get_output_lines"
            ):
                session_map = getattr(module, "_session_to_client_id", {})
                if self.session_id in session_map:
                    self.listener = module
                    return

    @property
    def shell_name(self) -> str:
        return "polling"

    @property
    def prompt_template(self) -> str:
        label = self.client_id or self.session_id[:8]
        return f"{self.transport} [{label}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def get_available_commands(self) -> List[str]:
        return [
            "help",
            "info",
            "run",
            "cmd",
            "shell",
            "queue",
            "pwd",
            "whoami",
            "ls",
            "cat",
            "download",
            "upload",
            "socks",
            "kill_agent",
            "output",
            "out",
            "clear_output",
            "exit",
            "quit",
            "disconnect",
        ]

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {"output": "", "status": 0, "error": ""}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "help":
            return {"output": self._help(), "status": 0, "error": ""}
        if cmd == "info":
            return {"output": self._info(), "status": 0, "error": ""}
        if cmd in ("run", "cmd", "shell"):
            return self._queue_shell(args, wait=True)
        if cmd == "queue":
            return self._queue_shell(args, wait=False)
        if cmd in ("pwd", "whoami", "exit", "quit"):
            if cmd in ("exit", "quit") and not args.strip():
                # Prefer local shell exit unless "exit agent"
                if cmd == "exit" and args.strip().lower() in ("agent", "implant"):
                    return self._queue_task("exit", {}, wait=True)
                self.is_active = False
                return {"output": "Bye!", "status": 0, "error": ""}
            if cmd == "whoami":
                return self._queue_task("whoami", {}, wait=True)
            if cmd == "pwd":
                return self._queue_task("pwd", {}, wait=True)
        if cmd == "ls":
            path = args.strip() or "."
            return self._queue_task("ls", {"path": path}, wait=True)
        if cmd == "cat":
            if not args.strip():
                return {"output": "", "status": 1, "error": "Usage: cat <path>"}
            return self._queue_task("cat", {"path": args.strip()}, wait=True)
        if cmd == "download":
            if not args.strip():
                return {"output": "", "status": 1, "error": "Usage: download <remote_path>"}
            return self._queue_task("download", {"path": args.strip()}, wait=True)
        if cmd == "upload":
            return self._upload(args)
        if cmd == "kill_agent":
            return self._queue_task("exit", {}, wait=True)
        if cmd == "socks":
            sub = (args.strip().split(None, 1) + [""])[0].lower()
            rest = args.strip()[len(sub):].strip() if args.strip() else ""
            if sub in ("", "start"):
                port = 1080
                if rest.isdigit():
                    port = int(rest)
                elif sub == "start" and rest.isdigit():
                    port = int(rest)
                # also: socks start 1080
                parts = args.split()
                if len(parts) >= 2 and parts[0].lower() == "start" and parts[1].isdigit():
                    port = int(parts[1])
                elif len(parts) == 1 and parts[0].isdigit():
                    port = int(parts[0])
                return self._queue_task("socks_start", {"port": port}, wait=True)
            if sub == "stop":
                return self._queue_task("socks_stop", {}, wait=True)
            return {
                "output": "",
                "status": 1,
                "error": "Usage: socks start [port] | socks stop",
            }
        if cmd in ("output", "out"):
            return self._output(args)
        if cmd in ("clear_output", "output_clear"):
            return self._clear_output()
        if cmd in ("disconnect",):
            self.is_active = False
            return {"output": "Bye!", "status": 0, "error": ""}

        # Convenience: bare OS command → typed shell task
        return self._queue_shell(command.strip(), wait=True)

    def _help(self) -> str:
        return """Polling Shell Commands:
  <os command>       Run remote shell command (waits for poll result)
  run <command>      Same as above
  queue <command>    Queue only (then use 'output')
  pwd / whoami / ls [path] / cat <path>
  download <path>    Fetch remote file via agent
  upload <local> <remote>   Push file to agent
  socks start [port] Start SOCKS5 on implant (default 1080)
  socks stop         Stop implant SOCKS5
  kill_agent         Tell implant to exit
  output [N]         Show last N output chunks
  clear_output       Clear buffered output
  info               Show transport/session info
  help               This help
  exit / quit        Leave shell (agent keeps polling)

Tip: wait time ≈ agent poll_interval (default ~10s)."""

    def _info(self) -> str:
        return "\n".join(
            [
                f"Transport: {self.transport or '(unknown)'}",
                f"Client:    {self.client_id or '(unknown)'}",
                f"IP/Host:   {self.client_ip or '(unknown)'}",
                f"Session:   {self.session_id}",
            ]
        )

    def _wait_timeout(self) -> float:
        base = 10.0
        if self.listener is not None:
            raw = getattr(self.listener, "poll_interval", None)
            try:
                if hasattr(raw, "value"):
                    base = float(raw.value)
                elif raw is not None:
                    base = float(raw)
            except (TypeError, ValueError):
                base = 10.0
        return max(15.0, base * 2.5 + 5.0)

    def _ensure_listener(self) -> Optional[str]:
        if not self.listener:
            self._initialize_listener()
        if not self.listener:
            return "Polling listener not available (is it still running in background?)"
        return None

    def _snapshot_len(self) -> int:
        if not self.listener or not hasattr(self.listener, "get_output_lines"):
            return 0
        return len(self.listener.get_output_lines(self.session_id, last_n=500) or [])

    def _wait_for_new_output(self, before_n: int) -> Dict[str, Any]:
        timeout = self._wait_timeout()
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.4)
            lines = list(
                self.listener.get_output_lines(self.session_id, last_n=500) or []
            )
            if len(lines) > before_n:
                return {"output": "\n".join(lines[before_n:]), "status": 0, "error": ""}
        return {
            "output": (
                f"Command queued; no output within {int(timeout)}s.\n"
                "The agent may still be sleeping — try 'output' shortly."
            ),
            "status": 0,
            "error": "",
        }

    def _queue_task(
        self, command: str, args: Dict[str, Any], *, wait: bool = True
    ) -> Dict[str, Any]:
        err = self._ensure_listener()
        if err:
            return {"output": "", "status": 1, "error": err}
        before_n = self._snapshot_len()
        if hasattr(self.listener, "set_pending_task"):
            from lib.c2.task_protocol import AgentTask

            self.listener.set_pending_task(
                self.session_id, AgentTask(command=command, args=dict(args or {}))
            )
        elif hasattr(self.listener, "set_pending_command"):
            # Fallback: encode as shell-ish string
            if command == "shell":
                self.listener.set_pending_command(
                    self.session_id, str((args or {}).get("cmd") or "")
                )
            else:
                self.listener.set_pending_command(
                    self.session_id, f"{command} {args}".strip()
                )
        else:
            return {"output": "", "status": 1, "error": "Listener cannot queue tasks"}
        if not wait:
            return {
                "output": "Task queued. Use 'output' after the next agent poll.",
                "status": 0,
                "error": "",
            }
        return self._wait_for_new_output(before_n)

    def _queue_shell(self, args: str, *, wait: bool = True) -> Dict[str, Any]:
        if not str(args or "").strip():
            return {"output": "", "status": 1, "error": "Usage: run <command>"}
        return self._queue_task("shell", {"cmd": args.strip()}, wait=wait)

    def _upload(self, args: str) -> Dict[str, Any]:
        try:
            parts = shlex.split(args)
        except ValueError:
            parts = args.split()
        if len(parts) < 2:
            return {
                "output": "",
                "status": 1,
                "error": "Usage: upload <local_path> <remote_path>",
            }
        local_path, remote_path = parts[0], parts[1]
        try:
            import base64
            from pathlib import Path

            raw = Path(local_path).expanduser().read_bytes()
        except Exception as exc:
            return {"output": "", "status": 1, "error": f"Cannot read local file: {exc}"}
        b64 = base64.b64encode(raw).decode("ascii")
        return self._queue_task(
            "upload",
            {"path": remote_path, "data": b64, "encoding": "base64"},
            wait=True,
        )

    def _output(self, args: str) -> Dict[str, Any]:
        err = self._ensure_listener()
        if err:
            return {"output": "(no output)", "status": 0, "error": ""}
        if not hasattr(self.listener, "get_output_lines"):
            return {"output": "(no output)", "status": 0, "error": ""}
        n = 50
        if args.strip().isdigit():
            n = min(int(args.strip()), 500)
        lines = self.listener.get_output_lines(self.session_id, last_n=n)
        return {
            "output": "\n".join(lines) if lines else "(no output from agent yet)",
            "status": 0,
            "error": "",
        }

    def _clear_output(self) -> Dict[str, Any]:
        if self.listener and hasattr(self.listener, "get_output"):
            self.listener.get_output(self.session_id, clear=True)
        return {"output": "Output cleared", "status": 0, "error": ""}
