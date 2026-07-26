#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather WSL Posture Audit",
        "description": "List WSL distros, version, and host processes",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1059.004/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.4,
            "noise": 0.15,
            "value": 0.85,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    probe_default_distro = OptBool(True, "Query default WSL distribution details", False)

    def _collect_script(self) -> str:
        probe = "true" if self.probe_default_distro else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$probeDefault = ${probe}

$report = [PSCustomObject]@{{
    WslInstalled = $false
    WslStatus = (wsl --status 2>&1 | Out-String).Trim()
    WslVersion = (wsl --version 2>&1 | Out-String).Trim()
    Distros = @()
    WslConfig = $null
    WslConfigPath = Join-Path $env:USERPROFILE '.wslconfig'
    Processes = @()
    DefaultDistroUser = $null
}}

if ($report.WslStatus -notmatch 'not recognized|n.?est pas reconnu|subsystem is not installed') {{
    $report.WslInstalled = $true
}}

$rawList = (wsl --list --verbose 2>&1 | Out-String)
$report.RawDistroList = $rawList
foreach ($line in ($rawList -split "`n")) {{
    $trim = $line.Trim()
    if (-not $trim -or $trim -like '*docker*' -or $trim -like '*DISTRIBUTION*' -or $trim -like '*STATE*') {{ continue }}
    if ($trim -match '^\*?\s*(\S+)\s+(\S+)\s+(\d+)$') {{
        $report.Distros += [PSCustomObject]@{{
            Name = $matches[1]
            State = $matches[2]
            Version = $matches[3]
            Default = $trim.StartsWith('*')
        }}
    }}
}}

if (Test-Path -LiteralPath $report.WslConfigPath) {{
    $report.WslConfig = (Get-Content -LiteralPath $report.WslConfigPath -ErrorAction SilentlyContinue | Out-String).Trim()
}}

Get-Process -ErrorAction SilentlyContinue |
    Where-Object {{ $_.ProcessName -in @('vmmem','vmmemWSL','wsl','wslservice','wslhost') }} |
    Select-Object ProcessName, Id |
    ForEach-Object {{ $report.Processes += $_ }}

if ($probeDefault -and $report.WslInstalled -and $report.Distros.Count -gt 0) {{
    $default = ($report.Distros | Where-Object {{ $_.Default }} | Select-Object -First 1)
    if (-not $default) {{ $default = $report.Distros[0] }}
    $distro = $default.Name
    $user = (wsl -d $distro whoami 2>&1 | Out-String).Trim()
    $id = (wsl -d $distro id 2>&1 | Out-String).Trim()
    $report.DefaultDistroUser = [PSCustomObject]@{{
        Distro = $distro
        WhoAmI = $user
        Id = $id
    }}
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False

        print_info("=" * 60)
        print_info("WSL")

        raw = self.win_run_powershell(self._collect_script(), timeout=35)
        if not raw:
            # fallback without PS-only parts
            status = self.win_execute("wsl --status", timeout=10)
            print_info(status or "(wsl command unavailable)")
            return True

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse WSL audit output: {exc}")
            print_info(raw[:2000])
            return False

        if not data.get("WslInstalled"):
            print_status("WSL is not installed on this host")
            print_info("=" * 60)
            return True

        if data.get("WslVersion"):
            print_info(data["WslVersion"].splitlines()[0])
        if data.get("WslStatus"):
            for line in data["WslStatus"].splitlines()[:6]:
                print_info(f"  {line}")

        distros = data.get("Distros") or []
        print_info("-" * 60)
        print_info(f"Distributions: {len(distros)}")
        for distro in distros:
            default = " (default)" if distro.get("Default") else ""
            print_info(
                f"  {distro.get('Name', '?')}{default} "
                f"[{distro.get('State', '?')}] WSL{distro.get('Version', '?')}"
            )

        if data.get("WslConfig"):
            print_info("-" * 60)
            print_info(f".wslconfig ({data.get('WslConfigPath', '')}):")
            for line in data["WslConfig"].splitlines()[:15]:
                print_info(f"  {line}")

        procs = data.get("Processes") or []
        if procs:
            print_info("-" * 60)
            print_info("WSL processes:")
            for proc in procs:
                print_info(f"  {proc.get('ProcessName', '?')} (pid {proc.get('Id', '?')})")

        print_info("=" * 60)
        return True
