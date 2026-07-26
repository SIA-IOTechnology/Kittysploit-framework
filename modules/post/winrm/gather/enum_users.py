#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Post):
	__info__ = {
		"name": "WinRM Gather Users",
		"description": "Enumerate current user, local users/groups, and interactive sessions through a WinRM session",
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
				"produces_capabilities": ["user_enum"],
				"suggested_followups": [
					"post/winrm/gather/enum_network",
					"post/winrm/gather/winrm_config_audit",
				],
			},
		},
	}

	def _run_cmd(self, command: str, title: str = "", max_lines: int = 50) -> str:
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
			print_success("Starting WinRM user enumeration")
			print_info("")

			print_info("=" * 70)
			print_info("Current Identity")
			print_info("=" * 70)
			self._run_cmd("whoami", "Current user")
			self._run_cmd("whoami /all", "whoami /all")
			self._run_cmd("whoami /priv", "Privileges")

			print_info("")
			print_info("=" * 70)
			print_info("Local Users and Groups")
			print_info("=" * 70)
			self._run_cmd("net user", "Local users")
			self._run_cmd("net localgroup", "Local groups")
			self._run_cmd("net localgroup Administrators", "Administrators group")

			print_info("")
			print_info("=" * 70)
			print_info("Sessions")
			print_info("=" * 70)
			self._run_cmd("query user", "Interactive sessions (query user)")
			self._run_cmd(
				'powershell -NoProfile -Command "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired | Format-Table -AutoSize"',
				"LocalUser objects",
			)

			print_info("=" * 80)
			print_success("WinRM user enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM user enumeration error: {exc}"
			)
