#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gather current WLAN connection details on each wireless interface
(Metasploit-style post/windows/wlan/wlan_current_connection).
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather Wireless Current Connection Info",
        "description": (
            "Gather information about the current connection on each wireless "
            "LAN interface via 'netsh wlan show interfaces' on a Windows shell "
            "or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/wlan/wlan_current_connection.rb",
        ],
        "tags": ["windows", "post", "gather", "wlan", "wifi"],
        "agent": {
            "risk": "passive",
            "effects": [],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.1,
            "value": 1.0,
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["network_recon"],
                "suggested_followups": [
                    "post/shell/windows/wlan/wlan_profile",
                    "post/shell/windows/gather/dump_wifi_keys",
                ],
            },
        },
    }

    save_local = OptBool(True, "Save results under ./output", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _run_powershell(self, script: str) -> str:
        encoded = self._encode_powershell(script)
        return self._execute_cmd(f"powershell -NoP -NonI -EncodedCommand {encoded}")

    def _bool_opt(self, val, default=False) -> bool:
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on")

    def _powershell_script(self) -> str:
        return r"""
$ErrorActionPreference = 'Continue'
$raw = netsh wlan show interfaces 2>&1
if (-not $raw) {
  Write-Output 'WLAN_ERROR: netsh wlan show interfaces returned no output'
  return
}
$joined = ($raw | Out-String)
if ($joined -match '(?i)(not supported|not available|not present|n.?est pas|nicht verf)') {
  Write-Output "WLAN_ERROR: WLAN stack unavailable`n$joined"
  return
}

function Get-WlanField([string]$src, [string]$pattern) {
  if ($src -match $pattern) { return $matches[1].Trim() }
  return ''
}

$sections = New-Object System.Collections.Generic.List[string]
$sections.Add('Wireless LAN Active Connections:')

# Split on blank lines between interface blocks when possible
$blocks = [regex]::Split($joined, '(?m)^\s*$') | Where-Object { $_ -match '(?i)Name\s*:' }
if (-not $blocks) { $blocks = @($joined) }

$ifaceCount = 0
foreach ($block in $blocks) {
  $text = ($block -replace "`r", '').Trim()
  if (-not $text) { continue }

  $name    = Get-WlanField $text '(?im)^\s*Name\s*:\s*(.+)$'
  $desc    = Get-WlanField $text '(?im)^\s*Description\s*:\s*(.+)$'
  $guid    = Get-WlanField $text '(?im)^\s*GUID\s*:\s*(.+)$'
  $mac     = Get-WlanField $text '(?im)^\s*Physical address\s*:\s*(.+)$'
  $state   = Get-WlanField $text '(?im)^\s*State\s*:\s*(.+)$'
  $ssid    = Get-WlanField $text '(?im)^\s*SSID\s*:\s*(.+)$'
  $bssid   = Get-WlanField $text '(?im)^\s*BSSID\s*:\s*(.+)$'
  $ntype   = Get-WlanField $text '(?im)^\s*Network type\s*:\s*(.+)$'
  $radio   = Get-WlanField $text '(?im)^\s*Radio type\s*:\s*(.+)$'
  $auth    = Get-WlanField $text '(?im)^\s*Authentication\s*:\s*(.+)$'
  $cipher  = Get-WlanField $text '(?im)^\s*Cipher\s*:\s*(.+)$'
  $mode    = Get-WlanField $text '(?im)^\s*Connection mode\s*:\s*(.+)$'
  $chan    = Get-WlanField $text '(?im)^\s*Channel\s*:\s*(.+)$'
  $rx      = Get-WlanField $text '(?im)^\s*Receive rate \(Mbps\)\s*:\s*(.+)$'
  $tx      = Get-WlanField $text '(?im)^\s*Transmit rate \(Mbps\)\s*:\s*(.+)$'
  $signal  = Get-WlanField $text '(?im)^\s*Signal\s*:\s*(.+)$'
  $profile = Get-WlanField $text '(?im)^\s*Profile\s*:\s*(.+)$'

  if (-not $name -and -not $guid -and -not $state) { continue }
  $ifaceCount++

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("GUID: $guid")
  [void]$sb.AppendLine("Name: $name")
  [void]$sb.AppendLine("Description: $desc")
  [void]$sb.AppendLine("Physical address: $mac")
  [void]$sb.AppendLine("State: $state")

  $connected = $state -match '(?i)connected|connect'
  if ($connected -and $ssid) {
    [void]$sb.AppendLine("  Mode: $mode")
    [void]$sb.AppendLine("  Profile: $profile")
    [void]$sb.AppendLine("  SSID: $ssid")
    [void]$sb.AppendLine("  AP MAC (BSSID): $bssid")
    [void]$sb.AppendLine("  BSS Type: $ntype")
    [void]$sb.AppendLine("  Physical Type: $radio")
    [void]$sb.AppendLine("  Channel: $chan")
    [void]$sb.AppendLine("  Signal Strength: $signal")
    [void]$sb.AppendLine("  RX Rate (Mbps): $rx")
    [void]$sb.AppendLine("  TX Rate (Mbps): $tx")
    [void]$sb.AppendLine("  Authentication Algorithm: $auth")
    [void]$sb.AppendLine("  Cipher Algorithm: $cipher")
  } else {
    [void]$sb.AppendLine('  This interface is not currently connected to a network')
  }

  $sections.Add($sb.ToString().TrimEnd())
}

if ($ifaceCount -eq 0) {
  Write-Output "No wireless interfaces found.`n`n--- raw netsh output ---`n$joined"
} else {
  $sections -join "`n`n"
}
"""

    def check(self):
        netsh_check = self._execute_cmd("where netsh")
        if not netsh_check or "netsh" not in netsh_check.lower():
            print_error("netsh.exe is not available on the target")
            return False

        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"wlan_current_connection_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(
                FailureType.NotCompatible,
                "WLAN current-connection prerequisites not met",
            )

        print_status("Querying wireless LAN current connections...")
        result = self._run_powershell(self._powershell_script())

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"WLAN_ERROR:", result, re.I):
            print_error(result)
            raise ProcedureError(FailureType.NotCompatible, result)

        if re.search(r"No wireless interfaces found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("WLAN current connection enumeration completed")
        print_info(result)
        return True
