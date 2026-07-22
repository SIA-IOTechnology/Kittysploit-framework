#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Post):
	__info__ = {
		"name": "WinRM Gather Network",
		"description": "Enumerate network interfaces, routes, DNS, ARP, connections, and shares through a WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 8,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["network_map"],
				"suggested_followups": [
					"post/winrm/manage/spawn_reverse_shell",
					"post/winrm/gather/winrm_config_audit",
				],
			},
		},
	}

	def _run_cmd(self, command: str, title: str = "", max_lines: int = 60) -> str:
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
			print_success("Starting WinRM network enumeration")
			print_info("")

			print_info("=" * 70)
			print_info("Interfaces and Addressing")
			print_info("=" * 70)
			self._run_cmd("ipconfig /all", "IP configuration")
			self._run_cmd("route print", "Routing table")

			print_info("")
			print_info("=" * 70)
			print_info("Name Resolution and Neighbors")
			print_info("=" * 70)
			self._run_cmd("nslookup", "DNS (nslookup default)")
			self._run_cmd("arp -a", "ARP cache")
			self._run_cmd(
				'powershell -NoProfile -Command "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | Format-Table -AutoSize"',
				"DNS client servers",
			)

			print_info("")
			print_info("=" * 70)
			print_info("Connections and Shares")
			print_info("=" * 70)
			self._run_cmd("netstat -ano", "Active connections", max_lines=80)
			self._run_cmd("net share", "Local shares")
			self._run_cmd("net use", "Mapped drives")
			self._run_cmd(
				'powershell -NoProfile -Command "Get-NetTCPConnection -State Listen,Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize"',
				"TCP connections (PowerShell)",
				max_lines=80,
			)

			print_info("=" * 80)
			print_success("WinRM network enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"WinRM network enumeration error: {exc}"
			)
