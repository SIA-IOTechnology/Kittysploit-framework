#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WinRM session helpers for post-exploitation modules."""

import base64
import os
import time
from typing import Any, Tuple


class WinRMSessionMixin:
	"""Retrieve a pypsrp Client from an active WinRM session."""

	def _opt_value(self, name: str) -> Any:
		raw = getattr(self, name, None)
		if raw is None:
			return None
		if hasattr(raw, "value"):
			return raw.value
		return raw

	def _bool_opt(self, val, default: bool = False) -> bool:
		if val is None:
			return default
		if isinstance(val, bool):
			return val
		return str(val).strip().lower() in ("1", "true", "yes", "on")

	def winrm_encode_ps(self, script: str) -> str:
		return base64.b64encode(script.encode("utf-16-le")).decode("ascii")

	def winrm_run_encoded_ps(self, script: str) -> str:
		"""Run a PowerShell script via EncodedCommand over the session shell."""
		encoded = self.winrm_encode_ps(script)
		cmd = f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
		if hasattr(self, "cmd_execute"):
			return (self.cmd_execute(cmd) or "").strip()
		stdout, _stderr, _rc = self.winrm_execute_cmd(cmd)
		return (stdout or "").strip()

	def winrm_save_loot(self, content: str, prefix: str, out_dir: str = "output") -> str:
		os.makedirs(out_dir, exist_ok=True)
		stamp = time.strftime("%Y%m%d_%H%M%S")
		local_path = os.path.join(out_dir, f"{prefix}_{stamp}.txt")
		with open(local_path, "w", encoding="utf-8", errors="replace") as handle:
			handle.write(content if content.endswith("\n") else content + "\n")
		return local_path

	def _resolve_session(self):
		if hasattr(self, "session") and self.session:
			return self.session
		session_id = self._opt_value("session_id")
		if session_id and getattr(self, "framework", None):
			mgr = getattr(self.framework, "session_manager", None)
			if mgr:
				return mgr.get_session(str(session_id).strip())
		return None

	def get_winrm_connection(self):
		"""Return the live pypsrp Client for the current WinRM session."""
		session = self._resolve_session()
		if not session:
			raise RuntimeError("WinRM session not found")

		data = getattr(session, "data", None)
		if isinstance(data, dict):
			conn = data.get("connection")
			if conn is not None and hasattr(conn, "execute_cmd"):
				return conn

		framework = getattr(self, "framework", None)
		session_id = getattr(session, "session_id", getattr(session, "id", None))
		if framework and isinstance(data, dict):
			listener_id = data.get("listener_id")
			if listener_id and session_id and hasattr(framework, "active_listeners"):
				listener = framework.active_listeners.get(listener_id)
				if listener and hasattr(listener, "_session_connections"):
					conn = listener._session_connections.get(session_id)
					if conn is not None and hasattr(conn, "execute_cmd"):
						return conn

		if framework and session_id:
			for module in getattr(framework, "modules", {}).values():
				if hasattr(module, "_session_connections") and session_id in module._session_connections:
					conn = module._session_connections[session_id]
					if conn is not None and hasattr(conn, "execute_cmd"):
						return conn

		raise RuntimeError("WinRM connection not available for this session")

	def winrm_execute_cmd(self, command: str) -> Tuple[str, str, int]:
		client = self.get_winrm_connection()
		stdout, stderr, rc = client.execute_cmd(command)
		return (stdout or ""), (stderr or ""), int(rc or 0)

	def winrm_execute_ps(self, script: str) -> Tuple[str, str, int]:
		client = self.get_winrm_connection()
		if hasattr(client, "execute_ps"):
			stdout, streams, had_errors = client.execute_ps(script)
			stderr = ""
			if streams is not None and getattr(streams, "error", None):
				try:
					stderr = "\n".join(str(e) for e in streams.error)
				except Exception:
					stderr = str(streams.error)
			return (stdout or ""), stderr, (1 if had_errors else 0)
		stdout, stderr, rc = client.execute_cmd(
			f'powershell -NoProfile -NonInteractive -Command "{script.replace(chr(34), chr(39))}"'
		)
		return (stdout or ""), (stderr or ""), int(rc or 0)

	def winrm_copy(self, local_path: str, remote_path: str) -> None:
		client = self.get_winrm_connection()
		if not hasattr(client, "copy"):
			raise RuntimeError("pypsrp Client.copy is not available")
		client.copy(local_path, remote_path)

	def winrm_fetch(self, remote_path: str, local_path: str) -> None:
		client = self.get_winrm_connection()
		if not hasattr(client, "fetch"):
			raise RuntimeError("pypsrp Client.fetch is not available")
		client.fetch(remote_path, local_path)

	def winrm_session_info(self) -> dict:
		session = self._resolve_session()
		if not session:
			return {}
		data = getattr(session, "data", None) or {}
		if not isinstance(data, dict):
			data = {}
		return {
			"host": getattr(session, "host", "") or data.get("host", ""),
			"port": getattr(session, "port", None) or data.get("port", ""),
			"username": data.get("username", ""),
			"ssl": data.get("ssl", False),
			"auth": data.get("auth", ""),
		}
