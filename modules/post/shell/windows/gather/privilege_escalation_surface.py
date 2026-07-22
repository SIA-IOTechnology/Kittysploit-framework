#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Privilege Escalation Surface",
        "description": "Check token privileges, UAC, services, tasks, and stored creds for LPE",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1068/",
            "https://attack.mitre.org/techniques/T1548.002/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.6,
            "noise": 0.25,
            "value": 0.95,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    include_services = OptBool(True, "Check service path misconfigurations", False)
    include_tasks = OptBool(True, "List non-Microsoft scheduled tasks", False)

    def _collect_script(self) -> str:
        include_services = "true" if self.include_services else "false"
        include_tasks = "true" if self.include_tasks else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$includeServices = ${include_services}
$includeTasks = ${include_tasks}

function Test-AlwaysInstallElevated {{
    $hkcu = (reg query 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' /v AlwaysInstallElevated 2>$null) -join "`n"
    $hklm = (reg query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' /v AlwaysInstallElevated 2>$null) -join "`n"
    $cu = $hkcu -match '0x1'
    $lm = $hklm -match '0x1'
    return [PSCustomObject]@{{
        HKCU = $cu
        HKLM = $lm
        Enabled = ($cu -and $lm)
        RawHKCU = $hkcu
        RawHKLM = $hklm
    }}
}}

function Get-UnquotedServices {{
    $rows = @()
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {{ $_.PathName -and $_.PathName -match '\.exe' }}
    foreach ($svc in $services) {{
        $path = $svc.PathName.Trim()
        if ($path.StartsWith('"')) {{ continue }}
        if ($path -notmatch '\s') {{ continue }}
        if ($path -match '^C:\\Windows\\') {{ continue }}
        $rows += [PSCustomObject]@{{
            Name = $svc.Name
            StartName = $svc.StartName
            StartMode = $svc.StartMode
            PathName = $svc.PathName
            State = $svc.State
        }}
    }}
    return $rows | Select-Object -First 25
}}

function Get-WritableServiceBinaries {{
    $rows = @()
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {{ $_.PathName -and $_.PathName -match '\.exe' }}
    foreach ($svc in $services) {{
        $raw = $svc.PathName.Trim()
        $exe = $raw
        if ($exe.StartsWith('"')) {{
            $exe = ($exe -replace '^"([^"]+)".*$', '$1')
        }} else {{
            $exe = ($exe -split '\s+')[0]
        }}
        if (-not (Test-Path -LiteralPath $exe)) {{ continue }}
        try {{
            $acl = Get-Acl -LiteralPath $exe -ErrorAction Stop
            $rule = $acl.Access |
                Where-Object {{
                    $_.IdentityReference -match 'Users|Authenticated Users|Everyone' -and
                    $_.FileSystemRights -match 'Write|Modify|FullControl'
                }} |
                Select-Object -First 1
            if ($rule) {{
                $rows += [PSCustomObject]@{{
                    Name = $svc.Name
                    StartName = $svc.StartName
                    Binary = $exe
                    Identity = $rule.IdentityReference
                    Rights = $rule.FileSystemRights
                }}
            }}
        }} catch {{}}
    }}
    return $rows | Select-Object -First 20
}}

function Get-UserScheduledTasks {{
    return Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {{ $_.TaskPath -notlike '\Microsoft\*' }} |
        Select-Object -First 25 TaskName, TaskPath, State |
        ForEach-Object {{
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [PSCustomObject]@{{
                Task = ($_.TaskPath + $_.TaskName)
                State = $_.State
                LastResult = $info.LastTaskResult
                NextRun = $info.NextRunTime
            }}
        }}
}}

$uacKeys = @(
    'EnableLUA',
    'ConsentPromptBehaviorAdmin',
    'PromptOnSecureDesktop',
    'LocalAccountTokenFilterPolicy'
)
$uac = @{{}}
foreach ($k in $uacKeys) {{
    $uac[$k] = (reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v $k 2>$null) -join ' '
}}

$report = [PSCustomObject]@{{
    Identity = (whoami /all 2>$null | Out-String).Trim()
    Privileges = (whoami /priv 2>$null | Out-String).Trim()
    Groups = (whoami /groups 2>$null | Out-String).Trim()
    AlwaysInstallElevated = Test-AlwaysInstallElevated
    UacPolicy = $uac
    StoredCredentials = (cmdkey /list 2>$null | Out-String).Trim()
    AutoLogon = @{{
        DefaultUserName = (reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v DefaultUserName 2>$null) -join ' '
        AutoAdminLogon = (reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v AutoAdminLogon 2>$null) -join ' '
        DefaultPasswordSet = [bool](reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v DefaultPassword 2>$null)
    }}
    UnquotedServices = @()
    WritableServiceBinaries = @()
    ScheduledTasks = @()
}}

if ($includeServices) {{
    $report.UnquotedServices = Get-UnquotedServices
    $report.WritableServiceBinaries = Get-WritableServiceBinaries
}}
if ($includeTasks) {{
    $report.ScheduledTasks = Get-UserScheduledTasks
}}

$report | ConvertTo-Json -Depth 6 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Privilege escalation surface")

        raw = self.win_run_powershell(self._collect_script(), timeout=45)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            payload = raw.strip().splitlines()[-1]
            data = json.loads(payload)
        except Exception as exc:
            print_error(f"Failed to parse surface audit output: {exc}")
            print_info(raw[:2500])
            return False

        print_info("-" * 60)
        print_info("Identity snapshot")
        for line in (data.get("Identity") or "").splitlines()[:12]:
            if line.strip():
                print_info(f"  {line}")

        print_info("-" * 60)
        print_info("Enabled privileges")
        enabled = [
            line.strip()
            for line in (data.get("Privileges") or "").splitlines()
            if "enabled" in line.lower()
        ]
        if enabled:
            for line in enabled[:15]:
                print_info(f"  {line}")
        else:
            print_status("  (no enabled privileges parsed)")

        if self.include_services:
            unquoted = data.get("UnquotedServices") or []
            writable = data.get("WritableServiceBinaries") or []
            print_info("-" * 60)
            print_info(f"Service misconfigurations: {len(unquoted)} unquoted, {len(writable)} writable binaries")
            for svc in unquoted[:8]:
                print_info(f"  unquoted: {svc.get('Name', '?')} -> {svc.get('PathName', '')}")
            for svc in writable[:8]:
                print_info(f"  writable: {svc.get('Name', '?')} -> {svc.get('Binary', '')}")

        if self.include_tasks:
            tasks = data.get("ScheduledTasks") or []
            print_info("-" * 60)
            print_info(f"Non-Microsoft scheduled tasks: {len(tasks)}")
            for task in tasks[:8]:
                print_info(f"  {task.get('Task', '?')} [{task.get('State', '?')}]")

        joined = json.dumps(data, ensure_ascii=False).lower()
        privs = (data.get("Privileges") or "").lower().replace(" ", "")
        if "seimpersonateprivilege" in privs or "seassignprimarytokenprivilege" in privs:
            print_warning("SeImpersonate/SeAssignPrimaryToken present")
        if (data.get("AlwaysInstallElevated") or {}).get("Enabled"):
            print_warning("AlwaysInstallElevated is set")
        if "0x0" in (str((data.get("UacPolicy") or {}).get("EnableLUA", "")).replace(" ", "")):
            print_warning("EnableLUA=0 (UAC disabled)")
        if "krbtgt" in joined:
            print_warning("krbtgt reference in token output")
        if "trustedfordelegation" in joined.replace(" ", ""):
            print_warning("TrustedForDelegation in token")
        if (data.get("AutoLogon") or {}).get("DefaultPasswordSet"):
            print_warning("Winlogon DefaultPassword value present")

        print_info("=" * 60)
        return True
