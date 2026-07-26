#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Autoruns Surface",
        "description": "Enumerate Run keys, services, tasks, and startup folders",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1547/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 5,
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

    include_wmi = OptBool(True, "Include WMI event subscription persistence checks", False)
    max_items = OptInteger(30, "Maximum entries per category", False)

    def _collect_script(self) -> str:
        max_items = int(self.max_items or 30)
        include_wmi = "true" if self.include_wmi else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$maxItems = {max_items}
$includeWmi = ${include_wmi}

function Get-RegValues($path) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return @() }}
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) {{ return @() }}
    return $item.Property | ForEach-Object {{
        $name = $_
        $value = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
        [PSCustomObject]@{{
            Hive = $path
            Name = $name
            Value = [string]$value
        }}
    }}
}}

$report = [PSCustomObject]@{{
    RunKeys = @()
    StartupFolders = @()
    Services = @()
    ScheduledTasks = @()
    WmiConsumers = @()
}}

$runPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
foreach ($p in $runPaths) {{
    $report.RunKeys += Get-RegValues $p
}}
$report.RunKeys = $report.RunKeys | Select-Object -First $maxItems

$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $startupDirs) {{
    if (Test-Path -LiteralPath $dir) {{
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue |
            Select-Object -First $maxItems |
            ForEach-Object {{
                $report.StartupFolders += [PSCustomObject]@{{
                    Path = $_.FullName
                    LastWrite = $_.LastWriteTime.ToString('s')
                }}
            }}
    }}
}}

$report.Services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {{ $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName -notmatch '^"?C:\\Windows\\' }} |
    Select-Object -First $maxItems Name, StartName, PathName, State

$report.ScheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object {{ $_.TaskPath -notlike '\Microsoft\*' }} |
    Select-Object -First $maxItems TaskName, TaskPath, State |
    ForEach-Object {{
        $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        $actions = (Get-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue).Actions
        [PSCustomObject]@{{
            Task = ($_.TaskPath + $_.TaskName)
            State = $_.State
            LastResult = $info.LastTaskResult
            Actions = ($actions | ForEach-Object {{ $_.Execute + ' ' + $_.Arguments }} | Where-Object {{ $_ }})
        }}
    }}

if ($includeWmi) {{
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Select-Object -First $maxItems *
    foreach ($c in $consumers) {{
        $report.WmiConsumers += [PSCustomObject]@{{
            Name = $c.Name
            Type = $c.CimClass.CimClassName
        }}
    }}
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Autoruns / persistence surface audit")

        raw = self.win_run_powershell(self._collect_script(), timeout=45)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse autoruns audit output: {exc}")
            print_info(raw[:2500])
            return False

        run_keys = data.get("RunKeys") or []
        print_info(f"Run/RunOnce entries: {len(run_keys)}")
        for entry in run_keys[:15]:
            print_info(f"  [{entry.get('Hive', '?')}] {entry.get('Name', '?')} = {entry.get('Value', '')[:120]}")

        startup = data.get("StartupFolders") or []
        print_info("-" * 60)
        print_info(f"Startup folder items: {len(startup)}")
        for item in startup[:10]:
            print_info(f"  {item.get('Path', '?')}")

        services = data.get("Services") or []
        print_info("-" * 60)
        print_info(f"Non-Windows auto-start services: {len(services)}")
        for svc in services[:10]:
            print_info(f"  {svc.get('Name', '?')} ({svc.get('StartName', '?')}) -> {svc.get('PathName', '')[:100]}")

        tasks = data.get("ScheduledTasks") or []
        print_info("-" * 60)
        print_info(f"Non-Microsoft scheduled tasks: {len(tasks)}")
        for task in tasks[:10]:
            print_info(f"  {task.get('Task', '?')} [{task.get('State', '?')}]")

        wmi = data.get("WmiConsumers") or []
        if wmi:
            print_info("-" * 60)
            print_warning(f"WMI event consumers: {len(wmi)}")
            for consumer in wmi[:8]:
                print_warning(f"  {consumer.get('Name', '?')} ({consumer.get('Type', '?')})")

        print_info("=" * 60)
        return True
