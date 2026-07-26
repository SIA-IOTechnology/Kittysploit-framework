#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather DLL & COM Hijack Surface",
        "description": "Find writable PATH dirs and HKCU COM overrides",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1574.001/",
            "https://attack.mitre.org/techniques/T1546.015/",
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

    include_com = OptBool(True, "Scan HKCU CLSID InprocServer32 overrides", False)
    max_findings = OptInteger(25, "Maximum findings per category", False)

    def _collect_script(self) -> str:
        max_findings = int(self.max_findings or 25)
        include_com = "true" if self.include_com else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$maxFindings = {max_findings}
$includeCom = ${include_com}

function Test-DirWritable($path) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return $false }}
    try {{
        $probe = Join-Path $path ('.ks_write_test_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType File -Path $probe -Force | Out-Null
        Remove-Item -LiteralPath $probe -Force
        return $true
    }} catch {{
        return $false
    }}
}}

$report = [PSCustomObject]@{{
    WritablePathDirs = @()
    WritableAppDirs = @()
    ComOverrides = @()
    MissingSystemDllHints = @()
}}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$allPaths = @()
if ($machinePath) {{ $allPaths += $machinePath -split ';' }}
if ($userPath) {{ $allPaths += $userPath -split ';' }}
foreach ($dir in ($allPaths | Where-Object {{ $_ -and (Test-Path -LiteralPath $_) }} | Select-Object -Unique)) {{
    if (Test-DirWritable $dir) {{
        $report.WritablePathDirs += [PSCustomObject]@{{
            Path = $dir
            Scope = if (($machinePath -split ';') -contains $dir) {{ 'Machine' }} else {{ 'User' }}
        }}
    }}
}}
$report.WritablePathDirs = $report.WritablePathDirs | Select-Object -First $maxFindings

$appDirs = @(
    $env:TEMP,
    $env:APPDATA,
    $env:LOCALAPPDATA,
    (Join-Path $env:USERPROFILE 'Downloads'),
    'C:\ProgramData'
)
foreach ($dir in ($appDirs | Where-Object {{ $_ -and (Test-Path -LiteralPath $_) }} | Select-Object -Unique)) {{
    if (Test-DirWritable $dir) {{
        $report.WritableAppDirs += [PSCustomObject]@{{
            Path = $dir
            Writable = $true
        }}
    }}
}}
$report.WritableAppDirs = $report.WritableAppDirs | Select-Object -First $maxFindings

if ($includeCom) {{
    $hkcuClsid = 'HKCU:\Software\Classes\CLSID'
    if (Test-Path -LiteralPath $hkcuClsid) {{
        Get-ChildItem -LiteralPath $hkcuClsid -ErrorAction SilentlyContinue |
            Select-Object -First $maxFindings |
            ForEach-Object {{
                $inproc = Join-Path $_.PSPath 'InprocServer32'
                if (Test-Path -LiteralPath $inproc) {{
                    $val = (Get-ItemProperty -LiteralPath $inproc -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                    if ($val) {{
                        $guid = Split-Path $_.PSPath -Leaf
                        $hklm = "HKLM:\Software\Classes\CLSID\$guid\InprocServer32"
                        $report.ComOverrides += [PSCustomObject]@{{
                            Clsid = $guid
                            HkcuDll = [string]$val
                            HklmPresent = Test-Path -LiteralPath $hklm
                        }}
                    }}
                }}
            }}
    }}
}}

$commonDlls = @('dbghelp.dll','version.dll','wlbsctrl.dll','WptsExtensions.dll')
foreach ($dll in $commonDlls) {{
    $sys = Join-Path $env:WINDIR "System32\$dll"
    if (-not (Test-Path -LiteralPath $sys)) {{
        foreach ($dir in $report.WritablePathDirs.Path) {{
            $candidate = Join-Path $dir $dll
            $report.MissingSystemDllHints += [PSCustomObject]@{{
                Dll = $dll
                MissingFromSystem32 = $true
                WritableSearchDir = $dir
                CandidatePath = $candidate
            }}
            break
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
        print_info("DLL & COM hijack surface audit")

        raw = self.win_run_powershell(self._collect_script(), timeout=40)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse hijack surface output: {exc}")
            print_info(raw[:2500])
            return False

        path_dirs = data.get("WritablePathDirs") or []
        print_info(f"Writable PATH directories: {len(path_dirs)}")
        for item in path_dirs[:12]:
            print_warning(f"  [{item.get('Scope', '?')}] {item.get('Path', '?')}")

        app_dirs = data.get("WritableAppDirs") or []
        print_info("-" * 60)
        print_info(f"Writable staging directories: {len(app_dirs)}")
        for item in app_dirs[:8]:
            print_info(f"  {item.get('Path', '?')}")

        com = data.get("ComOverrides") or []
        if com:
            print_info("-" * 60)
            print_warning(f"HKCU COM InprocServer32 overrides: {len(com)}")
            for item in com[:10]:
                print_warning(f"  {item.get('Clsid', '?')} -> {item.get('HkcuDll', '')}")

        hints = data.get("MissingSystemDllHints") or []
        if hints:
            print_info("-" * 60)
            print_warning("Missing System32 DLL + writable PATH hint(s):")
            for item in hints[:8]:
                print_warning(f"  {item.get('Dll', '?')} via {item.get('WritableSearchDir', '?')}")

        if not path_dirs and not com and not hints:
            print_status("No obvious DLL/COM hijack surface detected with these checks")

        print_info("=" * 60)
        return True
