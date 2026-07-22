#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Post):
	__info__ = {
		"name": "WinRM Gather System Information",
		"description": "Enumerate Windows system information through a WinRM session",
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
				"produces_capabilities": ["shell"],
				"suggested_followups": [
					"post/winrm/gather/enum_users",
					"post/winrm/gather/enum_network",
					"post/winrm/manage/spawn_reverse_shell",
				],
			},
		},
	}

	def _run_cmd(self, command: str, title: str = "") -> str:
		if title:
			print_status(title)
		output = (self.cmd_execute(command) or "").strip()
		if output:
			for line in output.splitlines()[:40]:
				if line.strip():
					print_info(f"  {line}")
			extra = len(output.splitlines()) - 40
			if extra > 0:
				print_info(f"  ... ({extra} more lines)")
		return output

	def run(self):
		try:
			print_info("=" * 80)
			print_success("Starting WinRM system enumeration")
			print_info("")

			print_info("=" * 70)
			print_info("System Information")
			print_info("=" * 70)
			self._run_cmd("hostname", "Hostname")
			self._run_cmd("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Domain\"", "OS details")

			print_info("")
			print_info("=" * 70)
			print_info("User Information")
			print_info("=" * 70)
			self._run_cmd("whoami", "Current user")
			self._run_cmd("whoami /groups", "Group membership")
			self._run_cmd("whoami /priv", "Privileges")

			print_info("")
			print_info("=" * 70)
			print_info("Network Configuration")
			print_info("=" * 70)
			self._run_cmd("ipconfig", "IP configuration")
			self._run_cmd("netstat -ano", "Active connections")

			print_info("")
			print_info("=" * 70)
			print_info("Processes and Services")
			print_info("=" * 70)
			self._run_cmd("tasklist", "Running processes")
			self._run_cmd("sc query state= all", "Windows services")

			print_info("")
			print_info("=" * 70)
			print_info("Security Settings")
			print_info("=" * 70)
			self._run_cmd(
				'powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -AutoSize"',
				"Firewall profile status",
			)
			self._run_cmd("net accounts", "Password policy")

			print_info("=" * 80)
			print_success("WinRM system enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM enumeration error: {exc}"
			)
