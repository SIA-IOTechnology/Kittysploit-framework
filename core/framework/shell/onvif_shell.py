#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive ONVIF camera shell."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.onvif.client import OnvifClient
from lib.protocols.onvif.session import OnvifSessionMixin

from .base_shell import BaseShell


class OnvifShell(BaseShell, OnvifSessionMixin):
    def __init__(self, session_id: str, session_type: str = "onvif", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: OnvifClient | None = None
        self.host = "localhost"
        self.port = 80
        self.profile_token = ""
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "device": self._cmd_device,
            "profiles": self._cmd_profiles,
            "snapshot": self._cmd_snapshot,
            "stream": self._cmd_stream,
            "ptz": self._cmd_ptz,
            "events": self._cmd_events,
            "profile": self._cmd_profile,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            self.client = self.open_onvif(discover=True)
            info = self.get_onvif_connection_info()
            self.host = str(info.get("host") or "localhost")
            self.port = int(info.get("port") or 80)
            if self.client and not self.profile_token:
                profiles = self.client.get_profiles()
                if profiles:
                    self.profile_token = profiles[0]
        except Exception as exc:
            print_warning(f"Could not initialize ONVIF connection: {exc}")

    def _require(self) -> OnvifClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("ONVIF connection not available")
        return self.client

    def _token(self, args: str = "") -> str:
        token = (args or "").strip() or self.profile_token
        if not token:
            profiles = self._require().get_profiles()
            if not profiles:
                raise RuntimeError("No media profiles found")
            token = profiles[0]
            self.profile_token = token
        return token

    @property
    def shell_name(self) -> str:
        return "onvif"

    @property
    def prompt_template(self) -> str:
        return f"onvif [{self.host}:{self.port}]> "

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
ONVIF Shell Commands:
========================
  info                         Connection / XAddrs
  device                       GetDeviceInformation
  profiles                     List media profiles
  profile [token]              Set default profile token
  snapshot [token]             Resolve GetSnapshotUri
  stream [token]               Resolve GetStreamUri (RTSP handoff)
  ptz [token]                  Get PTZ status
  events                       GetEventProperties / topics
  exit / quit                  Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        client = self._require()
        lines = [
            f"Host: {self.host}:{self.port}",
            f"Device path: {client.device_path}",
            f"Media XAddr: {client.media_xaddr or '-'}",
            f"PTZ XAddr: {client.ptz_xaddr or '-'}",
            f"Events XAddr: {client.events_xaddr or '-'}",
            f"Default profile: {self.profile_token or '-'}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_device(self, args: str) -> Dict[str, Any]:
        info = self._require().get_device_information()
        lines = [
            f"Manufacturer: {info.manufacturer or '?'}",
            f"Model: {info.model or '?'}",
            f"Firmware: {info.firmware or '?'}",
            f"Serial: {info.serial or '?'}",
            f"Hardware: {info.hardware or '?'}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_profiles(self, args: str) -> Dict[str, Any]:
        details = self._require().get_profiles_detail()
        if not details:
            return {"output": "(no profiles)\n", "status": 1, "error": "no profiles"}
        lines = [f"{i}. token={d['token']} name={d.get('name') or '-'}" for i, d in enumerate(details, 1)]
        if not self.profile_token and details:
            self.profile_token = details[0]["token"]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_profile(self, args: str) -> Dict[str, Any]:
        token = args.strip()
        if not token:
            return {"output": f"Current profile: {self.profile_token or '-'}\n", "status": 0, "error": ""}
        self.profile_token = token
        return {"output": f"Default profile set to {token}\n", "status": 0, "error": ""}

    def _cmd_snapshot(self, args: str) -> Dict[str, Any]:
        token = self._token(args)
        uri = self._require().get_snapshot_uri(token)
        if not uri:
            return {"output": "", "status": 1, "error": self._require().last_error or "GetSnapshotUri failed"}
        return {"output": f"profile={token}\n{uri}\n", "status": 0, "error": ""}

    def _cmd_stream(self, args: str) -> Dict[str, Any]:
        token = self._token(args)
        uri = self._require().get_stream_uri(token, protocol="RTSP")
        if not uri:
            return {"output": "", "status": 1, "error": self._require().last_error or "GetStreamUri failed"}
        return {
            "output": (
                f"profile={token}\nRTSP URI: {uri}\n"
                f"Handoff: listeners/iot/rtsp_client url={uri}\n"
            ),
            "status": 0,
            "error": "",
        }

    def _cmd_ptz(self, args: str) -> Dict[str, Any]:
        token = self._token(args)
        status = self._require().get_ptz_status(token)
        if not status.get("ok"):
            return {"output": "", "status": 1, "error": self._require().last_error or "GetStatus failed"}
        lines = [
            f"profile={token}",
            f"pan={status.get('pan') or '?'} tilt={status.get('tilt') or '?'} zoom={status.get('zoom') or '?'}",
        ]
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_events(self, args: str) -> Dict[str, Any]:
        props = self._require().get_event_properties()
        if not props.get("ok"):
            return {"output": "", "status": 1, "error": self._require().last_error or "GetEventProperties failed"}
        topics = props.get("topics") or []
        lines = [f"Event topics ({len(topics)}):"]
        lines.extend(f"  - {t}" for t in topics[:30])
        if not topics:
            lines.append("  (none parsed — service may require auth or PullPoint)")
            preview = props.get("raw_preview") or ""
            if preview:
                lines.append(preview[:300])
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting ONVIF shell\n", "status": 0, "error": "", "exit": True}
