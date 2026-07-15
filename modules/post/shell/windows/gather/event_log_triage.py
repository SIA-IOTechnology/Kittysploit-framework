#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Event Log Triage",
        "description": "Pull recent security events (logons, 4688, task creation)",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1070.001/",
            "https://attack.mitre.org/techniques/T1059/",
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

    hours = OptInteger(24, "Lookback window in hours", False)
    max_events = OptInteger(15, "Maximum events per category", False)
    include_sysmon = OptBool(True, "Include Sysmon Event ID 1 if channel exists", False)

    _LOLBIN_PATTERNS = (
        "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript",
        "cscript", "certutil", "bitsadmin", "msiexec", "cmstp", "installutil",
    )

    def _collect_script(self) -> str:
        hours = int(self.hours or 24)
        max_events = int(self.max_events or 15)
        include_sysmon = "true" if self.include_sysmon else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$hours = {hours}
$maxEvents = {max_events}
$includeSysmon = ${include_sysmon}
$start = (Get-Date).AddHours(-1 * $hours)

function Get-Events($logName, $ids) {{
    $events = @()
    foreach ($id in $ids) {{
        try {{
            $found = Get-WinEvent -FilterHashtable @{{
                LogName = $logName
                Id = $id
                StartTime = $start
            }} -MaxEvents $maxEvents -ErrorAction Stop
            foreach ($e in $found) {{
                $events += [PSCustomObject]@{{
                    Log = $logName
                    Id = $e.Id
                    Time = $e.TimeCreated.ToString('s')
                    Provider = $e.ProviderName
                    Message = ($e.Message -split "`n" | Select-Object -First 4) -join ' | '
                }}
            }}
        }} catch {{}}
    }}
    return $events
}}

$report = [PSCustomObject]@{{
    LookbackHours = $hours
    SecurityLogCleared = Get-Events 'Security' @(1102)
    SystemLogCleared = Get-Events 'System' @(104)
    FailedLogons = Get-Events 'Security' @(4625)
    SuccessfulLogons = Get-Events 'Security' @(4624)
    ProcessCreate = Get-Events 'Security' @(4688)
    TaskCreated = Get-Events 'Security' @(4698)
    SysmonProcessCreate = @()
    AccessErrors = @()
}}

if ($includeSysmon) {{
    try {{
        $sysmon = Get-WinEvent -FilterHashtable @{{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            Id = 1
            StartTime = $start
        }} -MaxEvents $maxEvents -ErrorAction Stop
        foreach ($e in $sysmon) {{
            $report.SysmonProcessCreate += [PSCustomObject]@{{
                Log = 'Sysmon/Operational'
                Id = 1
                Time = $e.TimeCreated.ToString('s')
                Message = ($e.Message -split "`n" | Select-Object -First 3) -join ' | '
            }}
        }}
    }} catch {{
        $report.AccessErrors += 'Sysmon channel unavailable: ' + $_.Exception.Message
    }}
}}

foreach ($log in @('Security','System')) {{
    try {{
        $null = Get-WinEvent -ListLog $log -ErrorAction Stop
    }} catch {{
        $report.AccessErrors += "Cannot read $log log: $($_.Exception.Message)"
    }}
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def _lolbin_hits(self, events: list) -> list[str]:
        hits = []
        for event in events or []:
            msg = (event.get("Message") or "").lower()
            for pattern in self._LOLBIN_PATTERNS:
                if pattern in msg and pattern not in hits:
                    hits.append(pattern)
        return hits

    def _print_events(self, title: str, events: list):
        print_info("-" * 60)
        print_info(f"{title}: {len(events)}")
        for event in events[: int(self.max_events or 15)]:
            print_info(f"  [{event.get('Time', '?')}] ID {event.get('Id', '?')} — {event.get('Message', '')[:160]}")

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info(f"Event log triage (last {int(self.hours or 24)}h)")

        raw = self.win_run_powershell(self._collect_script(), timeout=45)
        if not raw:
            print_warning("Collector returned no output — admin rights may be required for Security log")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse event triage output: {exc}")
            print_info(raw[:2500])
            return False

        for err in data.get("AccessErrors") or []:
            print_warning(err)

        self._print_events("Security log cleared (1102)", data.get("SecurityLogCleared") or [])
        self._print_events("System log cleared (104)", data.get("SystemLogCleared") or [])
        self._print_events("Failed logons (4625)", data.get("FailedLogons") or [])
        self._print_events("Successful logons (4624)", data.get("SuccessfulLogons") or [])
        self._print_events("Process create (4688)", data.get("ProcessCreate") or [])
        self._print_events("Scheduled task created (4698)", data.get("TaskCreated") or [])
        if self.include_sysmon:
            self._print_events("Sysmon process create (1)", data.get("SysmonProcessCreate") or [])

        cleared = (data.get("SecurityLogCleared") or []) + (data.get("SystemLogCleared") or [])
        if cleared:
            print_warning(f"Log clearing events: {len(cleared)}")
        lolbins = self._lolbin_hits(data.get("ProcessCreate") or [])
        if lolbins:
            print_warning(f"LOLBin strings in 4688 events: {', '.join(lolbins)}")

        if not self.win_is_admin():
            print_status("Non-admin session — Security log access may be incomplete.")

        print_info("=" * 60)
        return True
