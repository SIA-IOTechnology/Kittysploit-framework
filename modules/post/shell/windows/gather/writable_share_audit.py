#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Writable Share Audit",
        "description": "Find SMB shares writable by the current user",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1021.002/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.25,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    test_write = OptBool(True, "Probe write access with a temporary marker file", False)

    def _collect_script(self) -> str:
        test_write = "true" if self.test_write else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$testWrite = ${test_write}
$marker = '.ks_share_write_test'

function Test-ShareWrite($unc) {{
    if (-not $testWrite) {{ return $null }}
    $probe = Join-Path $unc ($marker + '_' + [guid]::NewGuid().ToString('N'))
    try {{
        Set-Content -LiteralPath $probe -Value 'ks' -Force -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force
        return $true
    }} catch {{
        return $false
    }}
}}

$report = [PSCustomObject]@{{
    LocalShares = @()
    MappedDrives = @()
    WritableTargets = @()
}}

try {{
    $report.LocalShares = Get-SmbShare -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Name -notmatch '^\$$' }} |
        Select-Object Name, Path, Description, CurrentUsers |
        ForEach-Object {{
            $access = Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
                Select-Object AccountName, AccessRight, AccessControlType
            [PSCustomObject]@{{
                Name = $_.Name
                Path = $_.Path
                Description = $_.Description
                Access = $access
            }}
        }}
}} catch {{}}

$netUse = (net use 2>&1 | Out-String)
$report.NetUseRaw = $netUse
foreach ($line in ($netUse -split "`n")) {{
    if ($line -match '^\s*([A-Z]):\s+\\\\([^\\]+)\\(.+?)\s') {{
        $drive = $matches[1]
        $server = $matches[2]
        $share = $matches[3]
        $unc = "\\$server\$share"
        $writable = Test-ShareWrite $unc
        $entry = [PSCustomObject]@{{
            Drive = $drive
            Unc = $unc
            Server = $server
            Share = $share
            Writable = $writable
        }}
        $report.MappedDrives += $entry
        if ($writable) {{
            $report.WritableTargets += [PSCustomObject]@{{
                Type = 'MappedDrive'
                Target = "$drive`: -> $unc"
                Unc = $unc
            }}
        }}
    }}
}}

try {{
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object {{ $_.DisplayRoot -like '\\*' }} |
        ForEach-Object {{
            $unc = $_.DisplayRoot
            if ($report.MappedDrives.Unc -contains $unc) {{ return }}
            $writable = Test-ShareWrite $unc
            $entry = [PSCustomObject]@{{
                Drive = $_.Name
                Unc = $unc
                Server = ($unc -replace '^\\\\([^\\]+)\\.*','$1')
                Share = ($unc -replace '^\\\\[^\\]+\\(.*)','$1')
                Writable = $writable
            }}
            $report.MappedDrives += $entry
            if ($writable) {{
                $report.WritableTargets += [PSCustomObject]@{{
                    Type = 'PSDrive'
                    Target = "$($_.Name): -> $unc"
                    Unc = $unc
                }}
            }}
        }}
}} catch {{}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Writable SMB share audit")

        raw = self.win_run_powershell(self._collect_script(), timeout=35)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse share audit output: {exc}")
            print_info(raw[:2500])
            return False

        local = data.get("LocalShares") or []
        print_info(f"Local shares: {len(local)}")
        for share in local[:10]:
            print_info(f"  {share.get('Name', '?')} -> {share.get('Path', '')}")

        mapped = data.get("MappedDrives") or []
        print_info("-" * 60)
        print_info(f"Mapped network paths: {len(mapped)}")
        for item in mapped[:12]:
            wr = item.get("Writable")
            flag = "WRITABLE" if wr is True else ("read-only" if wr is False else "not tested")
            print_info(f"  {item.get('Drive', '?')}: {item.get('Unc', '?')} [{flag}]")

        writable = data.get("WritableTargets") or []
        print_info("-" * 60)
        if writable:
            print_warning(f"Writable targets for staging: {len(writable)}")
            for target in writable:
                print_warning(f"  {target.get('Target', target.get('Unc', '?'))}")
            print_info("Use writable UNC paths for tool staging or lateral drop zones")
        else:
            print_status("No writable mapped shares detected (local admin may reveal more via Get-SmbShare)")

        print_info("=" * 60)
        return True
