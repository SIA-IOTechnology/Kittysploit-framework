#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive CoAP shell."""

from typing import Any, Dict, List

from core.output_handler import print_warning
from lib.protocols.coap.client import CoapClient, dtls_support
from lib.protocols.ics.ics_session_mixin import IcsSessionMixin

from .base_shell import BaseShell


class CoapShell(BaseShell, IcsSessionMixin):
    def __init__(self, session_id: str, session_type: str = "coap", framework=None):
        BaseShell.__init__(self, session_id, session_type)
        self.framework = framework
        self.client: CoapClient | None = None
        self.host = "localhost"
        self.port = 5683
        self.dtls = False
        self.builtin_commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "info": self._cmd_info,
            "get": self._cmd_get,
            "post": self._cmd_post,
            "put": self._cmd_put,
            "delete": self._cmd_delete,
            "del": self._cmd_delete,
            "observe": self._cmd_observe,
            "well-known": self._cmd_well_known,
            "wk": self._cmd_well_known,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "disconnect": self._cmd_exit,
        }
        self._initialize_connection()

    def _initialize_connection(self):
        try:
            session = self._resolve_session()
            if session:
                data = self._session_data(session)
                self.host = str(data.get("host") or "localhost")
                self.dtls = bool(data.get("dtls"))
                self.port = int(data.get("port") or (5684 if self.dtls else 5683))
                timeout = float(data.get("timeout") or 5)
                sid = self._session_id(session)
                registry = self._ics_registry()
                existing = registry.get(sid)
                if isinstance(existing, CoapClient) and existing.connected:
                    self.client = existing
                    self.dtls = bool(existing.dtls)
                    return
                listener_client = self._client_from_listener(session, CoapClient)
                if listener_client and listener_client.connected:
                    self.client = listener_client
                    self.dtls = bool(listener_client.dtls)
                    return
                client = CoapClient(self.host, self.port, timeout, dtls=self.dtls)
                if client.connect():
                    registry[sid] = client
                    self.client = client
                elif client.last_error:
                    print_warning(client.last_error)
        except Exception as exc:
            print_warning(f"Could not initialize CoAP connection: {exc}")

    def _require(self) -> CoapClient:
        if not self.client or not self.client.connected:
            self._initialize_connection()
        if not self.client or not self.client.connected:
            raise RuntimeError("CoAP connection not available")
        return self.client

    @property
    def shell_name(self) -> str:
        return "coap"

    @property
    def prompt_template(self) -> str:
        scheme = "coaps" if self.dtls else "coap"
        return f"{scheme} [{self.host}:{self.port}]> "

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
CoAP Shell Commands:
========================
  info                          Show connection details
  well-known / wk               GET .well-known/core
  get <path>                    CON GET resource
  post <path> [payload]         CON POST resource
  put <path> [payload]          CON PUT resource
  delete|del <path>             CON DELETE resource
  observe <path> [seconds]      Observe stream (default 8s)
  exit / quit                   Leave the shell
"""
        return {"output": text.strip() + "\n", "status": 0, "error": ""}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        return {"output": "\033[2J\033[H", "status": 0, "error": ""}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        return {"output": "\n".join(self.command_history) + "\n", "status": 0, "error": ""}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        support = dtls_support()
        lines = [
            f"Host: {self.host}:{self.port}",
            f"Scheme: {'coaps' if self.dtls else 'coap'}",
            f"Connected: {bool(self.client and self.client.connected)}",
            f"DTLS support: {support['available']} ({', '.join(support['protocols']) or 'none'})",
        ]
        if self.client and self.client.last_well_known:
            wk = self.client.last_well_known
            lines.append(f"well-known: {wk[:200]}{'...' if len(wk) > 200 else ''}")
        if self.client and self.client.last_error:
            lines.append(f"last_error: {self.client.last_error}")
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _fmt(self, resp) -> str:
        if not resp:
            return "(no response / timeout)"
        obs = f" obs={resp.observe}" if resp.observe is not None else ""
        body = resp.text()
        return f"code={resp.code_class}.{resp.code_detail:02d} bytes={len(resp.payload)}{obs}\n{body}"

    def _cmd_well_known(self, args: str) -> Dict[str, Any]:
        client = self._require()
        text = client.well_known()
        return {"output": (text or "(empty)") + "\n", "status": 0, "error": ""}

    def _cmd_get(self, args: str) -> Dict[str, Any]:
        path = args.strip() or ".well-known/core"
        resp = self._require().get(path)
        return {"output": self._fmt(resp) + "\n", "status": 0 if resp else 1, "error": "" if resp else "timeout"}

    def _cmd_post(self, args: str) -> Dict[str, Any]:
        parts = args.split(None, 1)
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: post <path> [payload]"}
        path = parts[0]
        payload = parts[1] if len(parts) > 1 else ""
        resp = self._require().post(path, payload)
        return {"output": self._fmt(resp) + "\n", "status": 0 if resp else 1, "error": "" if resp else "timeout"}

    def _cmd_put(self, args: str) -> Dict[str, Any]:
        parts = args.split(None, 1)
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: put <path> [payload]"}
        path = parts[0]
        payload = parts[1] if len(parts) > 1 else ""
        resp = self._require().put(path, payload)
        return {"output": self._fmt(resp) + "\n", "status": 0 if resp else 1, "error": "" if resp else "timeout"}

    def _cmd_delete(self, args: str) -> Dict[str, Any]:
        path = args.strip()
        if not path:
            return {"output": "", "status": 1, "error": "Usage: delete <path>"}
        resp = self._require().delete(path)
        return {"output": self._fmt(resp) + "\n", "status": 0 if resp else 1, "error": "" if resp else "timeout"}

    def _cmd_observe(self, args: str) -> Dict[str, Any]:
        parts = args.split()
        if not parts:
            return {"output": "", "status": 1, "error": "Usage: observe <path> [seconds]"}
        path = parts[0]
        seconds = 8.0
        if len(parts) > 1:
            try:
                seconds = float(parts[1])
            except ValueError:
                return {"output": "", "status": 1, "error": "seconds must be a number"}
        notes = self._require().observe_stream(path, duration=seconds, max_notifications=100)
        if not notes:
            return {"output": "(no notifications / timeout)\n", "status": 1, "error": "timeout"}
        lines = [f"Collected {len(notes)} notification(s) over {seconds}s:"]
        for i, resp in enumerate(notes, 1):
            obs = f" obs={resp.observe}" if resp.observe is not None else ""
            preview = resp.text().replace("\n", " ")[:120]
            lines.append(
                f"  [{i}] code={resp.code_class}.{resp.code_detail:02d}{obs} "
                f"bytes={len(resp.payload)} {preview}"
            )
        return {"output": "\n".join(lines) + "\n", "status": 0, "error": ""}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        return {"output": "Exiting CoAP shell\n", "status": 0, "error": "", "exit": True}
