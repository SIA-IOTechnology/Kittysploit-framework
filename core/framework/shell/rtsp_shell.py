#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive RTSP shell for OPTIONS / DESCRIBE / SETUP / PLAY."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.rtsp.client import RtspClient
from lib.protocols.rtsp.session import RtspSessionMixin

from .base_shell import BaseShell


class RtspShell(BaseShell, RtspSessionMixin):
    def __init__(self, session_id: str, session_type: str = "rtsp", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: RtspClient | None = None
        self.host = "localhost"
        self.port = 554
        self.path = "/"
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "options": self._cmd_options,
            "describe": self._cmd_describe,
            "setup": self._cmd_setup,
            "play": self._cmd_play,
            "teardown": self._cmd_teardown,
            "probe": self._cmd_probe,
            "stream": self._cmd_stream,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.open_rtsp(connect=True)
            info = self.get_rtsp_connection_info()
            self.host = str(info.get("host") or getattr(self.client, "host", "localhost"))
            self.port = int(info.get("port") or getattr(self.client, "port", 554))
            self.path = str(info.get("path") or getattr(self.client, "path", "/"))
        except Exception as exc:
            print_warning(f"Could not initialize RTSP connection: {exc}")

    def _require(self) -> RtspClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("RTSP connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "rtsp"

    @property
    def prompt_template(self) -> str:
        return f"rtsp [{self.host}:{self.port}{self.path}]> "

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
RTSP Shell Commands:
========================
  info                 Show connection details
  options              Send OPTIONS
  describe             DESCRIBE + list SDP media tracks
  setup [control]      SETUP track (TCP interleaved; default=first video)
  play                 PLAY current session
  teardown             TEARDOWN session
  probe                OPTIONS + DESCRIBE summary
  stream               DESCRIBE→SETUP→PLAY + drain interleaved bytes
  exit / quit          Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self.client
        info = self.get_rtsp_connection_info()
        lines = [
            f"URL: {getattr(client, 'request_uri', info.get('url') or '')}",
            f"Host: {info.get('host')}:{info.get('port')}{info.get('path')}",
            f"Server: {getattr(client, 'server', '') or '-'}",
            f"Session: {getattr(client, 'session_id', '') or '-'}",
            f"Connected: {bool(client and client.connected)}",
            f"Playing: {bool(getattr(client, 'playing', False))}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_options(self, args: str) -> Dict[str, Any]:
        client = self._require()
        resp = client.options()
        public = list(client.last_options)
        if not public:
            for key, value in resp.headers.items():
                if key.lower() in {"public", "allow"}:
                    public = [m.strip() for m in value.split(",") if m.strip()]
                    client.last_options = public
                    break
        return {
            "output": f"{resp.status} {resp.reason} methods={public or ['?']}\n",
            "status": 0 if resp.ok or resp.status == 401 else 1,
            "error": "" if resp.ok or resp.status == 401 else f"OPTIONS failed ({resp.status})",
        }

    def _cmd_describe(self, args: str) -> Dict[str, Any]:
        client = self._require()
        result = client.describe()
        if result.error and not result.media:
            return {"output": "", "status": 1, "error": result.error}
        lines = [
            f"DESCRIBE {result.status} server={result.server or '-'}",
            f"tracks={len(result.media)} base={result.content_base or '-'}",
        ]
        for media in result.media:
            lines.append(
                f"  {media.media_type} enc={media.encoding or '?'} "
                f"control={media.control or '-'}"
            )
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_setup(self, args: str) -> Dict[str, Any]:
        client = self._require()
        control = args.strip()
        if not control:
            if not client.last_media:
                client.describe()
            for media in client.last_media:
                if media.media_type == "video":
                    control = media.control
                    break
            if not control and client.last_media:
                control = client.last_media[0].control
        resp = client.setup(control or "", transport="tcp")
        if not resp.ok:
            return {"output": "", "status": 1, "error": f"SETUP {resp.status} {resp.reason}"}
        return {
            "output": f"SETUP ok session={client.session_id} transport={client.transport}\n",
            "status": 0,
            "error": "",
        }

    def _cmd_play(self, args: str) -> Dict[str, Any]:
        client = self._require()
        resp = client.play()
        if not resp.ok:
            return {"output": "", "status": 1, "error": f"PLAY {resp.status} {resp.reason}"}
        return {"output": "PLAY ok\n", "status": 0, "error": ""}

    def _cmd_teardown(self, args: str) -> Dict[str, Any]:
        client = self._require()
        resp = client.teardown()
        return {
            "output": f"TEARDOWN {resp.status} {resp.reason}\n",
            "status": 0 if resp.ok or resp.status == 0 else 1,
            "error": "",
        }

    def _cmd_probe(self, args: str) -> Dict[str, Any]:
        client = self._require()
        info = client.probe()
        media = info.get("media") or []
        lines = [
            f"url={info.get('url')}",
            f"server={info.get('server') or '-'}",
            f"options={info.get('options') or []}",
            f"auth_required={info.get('auth_required')}",
            f"tracks={len(media)}",
        ]
        for item in media:
            lines.append(
                f"  {item.get('type')} enc={item.get('encoding') or '?'} "
                f"control={item.get('control') or '-'}"
            )
        if info.get("error"):
            lines.append(f"note: {info['error']}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_stream(self, args: str) -> Dict[str, Any]:
        client = self._require()
        result = client.open_stream_tcp()
        if result.get("error") and not result.get("play_ok"):
            return {"output": "", "status": 1, "error": str(result.get("error"))}
        return {
            "output": (
                f"stream track={result.get('track') or '-'} "
                f"setup={result.get('setup_ok')} play={result.get('play_ok')} "
                f"drained={result.get('bytes_drained')} bytes "
                f"transport={result.get('transport') or '-'}\n"
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting RTSP shell\n", "status": 0, "error": "", "exit": True}
