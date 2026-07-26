#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather AMSI & ETW Posture Audit",
        "description": "Probe AMSI blocking and ETW/PowerShell logging channels",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562.001/",
            "https://attack.mitre.org/techniques/T1562.006/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.4,
            "noise": 0.2,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    probe_amsi = OptBool(True, "Run a benign AMSI signature probe string", False)

    def _collect_script(self) -> str:
        probe = "true" if self.probe_amsi else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$probeAmsi = ${probe}

$report = [PSCustomObject]@{{
    AmsiDllLoaded = $false
    AmsiProbeBlocked = $null
    AmsiProbeOutput = $null
    AmsiProviders = @()
    EtwAutologgers = @()
    DotNetEtwEnabled = $null
    PowerShellChannelEnabled = $null
}}

$proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
if ($proc -and $proc.Modules) {{
    $report.AmsiDllLoaded = [bool]($proc.Modules | Where-Object {{ $_.ModuleName -eq 'amsi.dll' }})
}}

if ($probeAmsi) {{
    try {{
        $report.AmsiProbeOutput = ('amsiutils' + 'amsicontext')
        $report.AmsiProbeBlocked = $false
    }} catch {{
        $report.AmsiProbeBlocked = $true
        $report.AmsiProbeOutput = $_.Exception.Message
    }}
}}

try {{
    $providers = Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Name -match 'AMSI|Defender|PowerShell|DotNETRuntime' }} |
        Select-Object -First 20 Name, LogLinks
    foreach ($p in $providers) {{
        $report.AmsiProviders += [PSCustomObject]@{{
            Name = $p.Name
            Logs = ($p.LogLinks | ForEach-Object {{ $_.LogName }})
        }}
    }}
}} catch {{}}

$autologgerRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
if (Test-Path -LiteralPath $autologgerRoot) {{
    Get-ChildItem -LiteralPath $autologgerRoot -ErrorAction SilentlyContinue |
        Where-Object {{ $_.PSChildName -match 'PowerShell|DotNET|Defender|AMSI|EventLog' }} |
        Select-Object -First 20 |
        ForEach-Object {{
            $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            $report.EtwAutologgers += [PSCustomObject]@{{
                Name = $_.PSChildName
                Start = $props.Start
                Enabled = $props.Enabled
            }}
        }}
}}

try {{
    $psChan = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop
    $report.PowerShellChannelEnabled = $psChan.IsEnabled
}} catch {{
    $report.PowerShellChannelEnabled = $null
}}

try {{
    $dotNet = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\.NETFramework' -Name 'ETWEnabled' -ErrorAction Stop
    $report.DotNetEtwEnabled = $dotNet.ETWEnabled
}} catch {{
    $report.DotNetEtwEnabled = $null
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("AMSI & ETW")

        raw = self.win_run_powershell(self._collect_script(), timeout=30)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse AMSI/ETW audit output: {exc}")
            print_info(raw[:2000])
            return False

        print_info(f"amsi.dll loaded: {data.get('AmsiDllLoaded', False)}")
        if self.probe_amsi:
            blocked = data.get("AmsiProbeBlocked")
            print_info(f"AMSI probe blocked: {blocked}")
            if data.get("AmsiProbeOutput"):
                print_info(f"  Probe output: {data['AmsiProbeOutput']}")

        providers = data.get("AmsiProviders") or []
        if providers:
            print_info("-" * 60)
            print_info(f"Relevant ETW providers: {len(providers)}")
            for prov in providers[:8]:
                logs = ", ".join(prov.get("Logs") or []) or "(none)"
                print_info(f"  {prov.get('Name', '?')} -> {logs}")

        autologgers = data.get("EtwAutologgers") or []
        if autologgers:
            print_info("-" * 60)
            print_info(f"ETW autologgers: {len(autologgers)}")
            for item in autologgers[:10]:
                print_info(f"  {item.get('Name', '?')} start={item.get('Start', '?')} enabled={item.get('Enabled', '?')}")

        print_info("=" * 60)
        return True
