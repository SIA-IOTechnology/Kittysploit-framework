#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Installed Software Audit",
        "description": "Inventory installed software with version hints",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1518/",
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

    max_entries = OptInteger(60, "Maximum installed products to return", False)

    _SENSITIVE_PATTERNS = (
        (r"java|jre|jdk|openjdk", "Java runtime — frequent deserialization/RCE target"),
        (r"google chrome|chromium|microsoft edge|mozilla firefox", "Browser — client-side exploit surface"),
        (r"microsoft office|word|excel|outlook", "Office suite — macro / OLE attack surface"),
        (r"teamviewer|anydesk|vnc|remote desktop|screenconnect", "Remote access tool — lateral/persistence"),
        (r"python|perl|ruby|node\.js|php", "Scripting runtime — execution/staging"),
        (r"visual c\+\+|\.net|powershell", "Runtime/framework present"),
        (r"vmware|virtualbox|hyper-v|citrix", "Virtualization / VDI stack"),
        (r"openssl|putty|winscp|filezilla", "Crypto/transfer tooling"),
        (r"7-zip|winrar", "Archive tooling — phishing/exploit delivery"),
        (r"adobe|acrobat|reader", "PDF reader — client exploit surface"),
    )

    def _collect_script(self) -> str:
        max_entries = int(self.max_entries or 60)
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$maxEntries = {max_entries}

function Get-InstalledProducts {{
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = @()
    foreach ($path in $paths) {{
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object {{ $_.DisplayName }} |
            ForEach-Object {{
                $items += [PSCustomObject]@{{
                    Name = $_.DisplayName
                    Version = $_.DisplayVersion
                    Publisher = $_.Publisher
                    InstallDate = $_.InstallDate
                    Source = $path
                }}
            }}
    }}
    return $items | Sort-Object Name -Unique | Select-Object -First $maxEntries
}}

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$report = [PSCustomObject]@{{
    Host = $env:COMPUTERNAME
    OsCaption = $os.Caption
    OsVersion = $os.Version
    OsBuild = $os.BuildNumber
    Products = Get-InstalledProducts
}}

$report | ConvertTo-Json -Depth 6 -Compress
"""

    def _highlight_products(self, products: list) -> list[dict]:
        highlights: list[dict] = []
        for product in products or []:
            name = (product.get("Name") or "").lower()
            version = product.get("Version") or "?"
            for pattern, hint in self._SENSITIVE_PATTERNS:
                if re.search(pattern, name, re.I):
                    highlights.append({
                        "name": product.get("Name", "?"),
                        "version": version,
                        "hint": hint,
                    })
                    break
        return highlights

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Installed software audit")

        raw = self.win_run_powershell(self._collect_script(), timeout=35)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse software audit output: {exc}")
            print_info(raw[:2000])
            return False

        print_info(f"OS: {data.get('OsCaption', '?')} build {data.get('OsBuild', '?')} ({data.get('OsVersion', '?')})")

        products = data.get("Products") or []
        print_info("-" * 60)
        print_info(f"Installed products sampled: {len(products)}")
        for product in products[:20]:
            print_info(
                f"  {product.get('Name', '?')} "
                f"{product.get('Version', '')} "
                f"[{product.get('Publisher', '')}]"
            )
        if len(products) > 20:
            print_info(f"  ... {len(products) - 20} more")

        highlights = self._highlight_products(products)
        print_info("-" * 60)
        if highlights:
            print_warning(f"Security-sensitive software: {len(highlights)}")
            for item in highlights:
                print_warning(f"  {item['name']} {item['version']}")
                print_info(f"    -> {item['hint']}")
        else:
            print_status("No security-sensitive product name matched heuristics")

        print_info("=" * 60)
        return True
