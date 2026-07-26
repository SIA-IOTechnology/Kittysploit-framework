#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather AppLocker & WDAC Audit",
        "description": "Audit AppLocker and WDAC enforcement",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1518.001/",
            "https://attack.mitre.org/techniques/T1218/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    include_policy_xml = OptBool(False, "Dump effective AppLocker policy XML (verbose)", False)

    def _collect_script(self) -> str:
        include_xml = "true" if self.include_policy_xml else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$includeXml = ${include_xml}

function Get-PolicyFileInfo($path) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return $null }}
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) {{ return $null }}
    return [PSCustomObject]@{{
        Path = $path
        Size = $item.Length
        LastWrite = $item.LastWriteTime.ToString('s')
    }}
}}

$report = [PSCustomObject]@{{
    AppLockerService = (Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue |
        Select-Object Status, StartType, Name)
    AppLockerPolicies = @()
    WdacPolicies = @()
    CiPolicyKeys = @()
    EffectiveAppLocker = $null
    CiTool = $null
    CodeIntegrity = @{{}}
}}

$policyPaths = @(
    "$env:WINDIR\System32\AppLocker\MDM",
    "$env:WINDIR\System32\AppLocker\SAP",
    "$env:WINDIR\System32\AppLocker\EXE",
    "$env:WINDIR\System32\AppLocker\DLL",
    "$env:WINDIR\System32\AppLocker\MSI",
    "$env:WINDIR\System32\AppLocker\Script",
    "$env:WINDIR\System32\AppLocker\Policy",
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi'
)

foreach ($p in $policyPaths) {{
    if ($p -like 'HKLM:*') {{
        if (Test-Path -LiteralPath $p) {{
            $report.AppLockerPolicies += [PSCustomObject]@{{
                Type = 'Registry'
                Path = $p
                Present = $true
            }}
        }}
    }} else {{
        $info = Get-PolicyFileInfo $p
        if ($info) {{ $report.AppLockerPolicies += $info }}
    }}
}}

$wdacRoots = @(
    "$env:WINDIR\System32\CodeIntegrity\CiPolicies\Active",
    "$env:WINDIR\System32\CodeIntegrity",
    'C:\Windows\System32\CodeIntegrity\CiPolicies'
)
foreach ($root in $wdacRoots) {{
    if (Test-Path -LiteralPath $root) {{
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {{ $_.Extension -in '.cip', '.p7b', '.bin' }} |
            Select-Object -First 20 |
            ForEach-Object {{
                $report.WdacPolicies += [PSCustomObject]@{{
                    Path = $_.FullName
                    Size = $_.Length
                    LastWrite = $_.LastWriteTime.ToString('s')
                }}
            }}
    }}
}}

$ciKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy',
    'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config',
    'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
)
foreach ($k in $ciKeys) {{
    if (Test-Path -LiteralPath $k) {{
        $vals = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if ($vals) {{
            $report.CiPolicyKeys += [PSCustomObject]@{{
                Key = $k
                Values = ($vals | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider)
            }}
        }}
    }}
}}

try {{
    $report.CodeIntegrity.HvciEnabled = (Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning -contains 2
}} catch {{}}

try {{
    $report.EffectiveAppLocker = Get-AppLockerPolicy -Effective -ErrorAction Stop
    if ($includeXml -and $report.EffectiveAppLocker) {{
        $report.EffectiveAppLockerXml = ($report.EffectiveAppLocker | Format-List * | Out-String)
    }}
}} catch {{
    $report.EffectiveAppLockerError = $_.Exception.Message
}}

$citool = Join-Path $env:WINDIR 'System32\CiTool.exe'
if (Test-Path -LiteralPath $citool) {{
    $report.CiTool = (& $citool -lp 2>&1 | Out-String).Trim()
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("AppLocker / WDAC")

        raw = self.win_run_powershell(self._collect_script(), timeout=40)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse audit output: {exc}")
            print_info(raw[:2500])
            return False

        svc = data.get("AppLockerService") or {}
        print_info("-" * 60)
        print_info(f"AppIDSvc: {svc.get('Status', '?')} ({svc.get('StartType', '?')})")

        policies = data.get("AppLockerPolicies") or []
        print_info(f"AppLocker artifacts: {len(policies)}")
        for item in policies[:12]:
            if isinstance(item, dict):
                print_info(f"  {item.get('Path', item.get('Type', '?'))}")

        wdac = data.get("WdacPolicies") or []
        print_info("-" * 60)
        print_info(f"WDAC policy files: {len(wdac)}")
        for item in wdac[:10]:
            print_info(f"  {item.get('Path', '?')} [{item.get('Size', 0)} bytes]")

        if data.get("CiTool"):
            print_info("-" * 60)
            print_info("CiTool -lp")
            for line in data["CiTool"].splitlines()[:20]:
                print_info(f"  {line}")

        print_info("=" * 60)
        return True
