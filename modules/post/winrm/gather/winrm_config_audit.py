#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Post):
	__info__ = {
		"name": "WinRM Config Audit",
		"description": "Audit local WinRM service configuration, listeners, authentication, and TrustedHosts",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 6,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["winrm_config"],
				"suggested_followups": [
					"post/winrm/manage/lateral_winrm",
					"post/winrm/manage/spawn_reverse_shell",
					"post/winrm/manage/powershell_exec",
				],
			},
		},
	}

	def _run_cmd(self, command: str, title: str = "", max_lines: int = 80) -> str:
		if title:
			print_status(title)
		output = (self.cmd_execute(command) or "").strip()
		if output:
			lines = output.splitlines()
			for line in lines[:max_lines]:
				if line.strip():
					print_info(f"  {line}")
			extra = len(lines) - max_lines
			if extra > 0:
				print_info(f"  ... ({extra} more lines)")
		else:
			print_info("  (no output)")
		return output

	def run(self):
		try:
			print_info("=" * 80)
			print_success("Starting WinRM configuration audit")
			print_info("")

			print_info("=" * 70)
			print_info("Service Status")
			print_info("=" * 70)
			self._run_cmd("sc query WinRM", "WinRM service")
			self._run_cmd(
				'powershell -NoProfile -Command "Get-Service WinRM | Format-List *"',
				"WinRM service details",
			)

			print_info("")
			print_info("=" * 70)
			print_info("WinRM Configuration")
			print_info("=" * 70)
			self._run_cmd("winrm get winrm/config", "winrm/config")
			self._run_cmd("winrm get winrm/config/service", "winrm/config/service")
			self._run_cmd("winrm get winrm/config/service/auth", "Service authentication")
			self._run_cmd("winrm get winrm/config/client", "Client configuration")
			self._run_cmd("winrm get winrm/config/client/auth", "Client authentication")

			print_info("")
			print_info("=" * 70)
			print_info("Listeners and TrustedHosts")
			print_info("=" * 70)
			self._run_cmd("winrm enumerate winrm/config/listener", "Listeners")
			self._run_cmd(
				'powershell -NoProfile -Command "Get-Item WSMan:\\localhost\\Client\\TrustedHosts | Format-List *"',
				"TrustedHosts",
			)
			self._run_cmd(
				'powershell -NoProfile -Command "Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate | Format-List *"',
				"WSMan listeners (PowerShell)",
			)

			print_info("=" * 80)
			print_success("WinRM configuration audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM config audit error: {exc}"
			)
