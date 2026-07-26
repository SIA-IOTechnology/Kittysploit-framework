#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather PowerShell Logging Audit",
        "description": "Check Script Block, Module, and Transcription logging",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1059.001/",
            "https://attack.mitre.org/techniques/T1562.002/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.4,
            "noise": 0.15,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    check_recent_events = OptBool(True, "Count recent PowerShell operational log events", False)

    def _collect_script(self) -> str:
        check_events = "true" if self.check_recent_events else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$checkEvents = ${check_events}

$report = [PSCustomObject]@{{
    Policies = @()
    LanguageMode = $null
    ExecutionPolicy = $null
    PsVersion = $PSVersionTable.PSVersion.ToString()
    RecentScriptBlockEvents = $null
    RecentOperationalEvents = $null
}}

foreach ($pair in @(
    @{{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Values = @('EnableScriptBlockLogging') }},
    @{{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Values = @('EnableModuleLogging') }},
    @{{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Values = @('EnableTranscripting','EnableInvocationHeader','OutputDirectory') }}
)) {{
    if (Test-Path -LiteralPath $pair.Path) {{
        $props = Get-ItemProperty -LiteralPath $pair.Path -ErrorAction SilentlyContinue
        foreach ($name in $pair.Values) {{
            if ($props.$name -ne $null) {{
                $report.Policies += [PSCustomObject]@{{
                    Key = $pair.Path
                    Name = $name
                    Value = [string]$props.$name
                }}
            }}
        }}
    }}
}}

try {{
    $report.LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
}} catch {{}}
try {{
    $report.ExecutionPolicy = (Get-ExecutionPolicy -List | Out-String).Trim()
}} catch {{}}

if ($checkEvents) {{
    try {{
        $report.RecentScriptBlockEvents = (Get-WinEvent -FilterHashtable @{{
            LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = (Get-Date).AddDays(-1)
        }} -MaxEvents 5 -ErrorAction Stop | Measure-Object).Count
    }} catch {{
        $report.RecentScriptBlockEvents = -1
    }}
    try {{
        $report.RecentOperationalEvents = (Get-WinEvent -FilterHashtable @{{
            LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = (Get-Date).AddDays(-1)
        }} -MaxEvents 1 -ErrorAction Stop | Measure-Object).Count
    }} catch {{
        $report.RecentOperationalEvents = -1
    }}
}}

$report | ConvertTo-Json -Depth 6 -Compress
"""

    def _is_enabled(self, policies: list, name: str) -> bool | None:
        for item in policies:
            if item.get("Name") == name:
                val = str(item.get("Value", "")).strip().lower()
                return val in ("1", "0x1", "true")
        return None

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("PowerShell logging")

        raw = self.win_run_powershell(self._collect_script(), timeout=30)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse logging audit output: {exc}")
            print_info(raw[:2000])
            return False

        print_info(f"PowerShell version: {data.get('PsVersion', '?')}")
        if data.get("LanguageMode"):
            print_info(f"LanguageMode: {data['LanguageMode']}")

        policies = data.get("Policies") or []
        print_info("-" * 60)
        if policies:
            for item in policies:
                print_info(f"  {item.get('Name', '?')} = {item.get('Value', '?')}")
        else:
            print_status("  No explicit PS logging policy values found")

        if self.check_recent_events:
            print_info("-" * 60)
            print_info(f"Recent 4104 events (24h): {data.get('RecentScriptBlockEvents', '?')}")

        print_info("=" * 60)
        return True
