#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Kerberos Ticket Audit",
        "description": "Dump klist and logon session Kerberos context",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1550.003/",
            "https://attack.mitre.org/techniques/T1558/",
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

    include_tgt_details = OptBool(True, "Include detailed TGT/TGS listing via klist", False)

    def _collect_script(self) -> str:
        include_tgt = "true" if self.include_tgt_details else "false"
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$includeTgt = ${include_tgt}

$report = [PSCustomObject]@{{
    WhoAmI = (whoami /user 2>$null | Out-String).Trim()
    WhoAmIAll = (whoami /all 2>$null | Out-String).Trim()
    Domain = $null
    PartOfDomain = $false
    LogonServer = $env:LOGONSERVER
    UserDnsDomain = $env:USERDNSDOMAIN
    Klist = (klist 2>&1 | Out-String).Trim()
    KlistTgt = $null
    SessionTickets = @()
}}

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs) {{
    $report.Domain = $cs.Domain
    $report.PartOfDomain = [bool]$cs.PartOfDomain
}}

if ($includeTgt) {{
    $report.KlistTgt = (klist -tgt 2>&1 | Out-String).Trim()
}}

$klistLines = $report.Klist -split "`n"
foreach ($line in $klistLines) {{
    if ($line -match 'Server:\s*(\S+)@(\S+)') {{
        $report.SessionTickets += [PSCustomObject]@{{
            Server = $matches[1]
            Realm = $matches[2]
            Line = $line.Trim()
        }}
    }}
}}

$report | ConvertTo-Json -Depth 6 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False

        print_info("=" * 60)
        print_info("Kerberos ticket audit")

        raw = self.win_run_powershell(self._collect_script(), timeout=25)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse Kerberos audit output: {exc}")
            print_info(raw[:2500])
            return False

        print_info("-" * 60)
        print_info("Logon identity")
        for line in (data.get("WhoAmI") or "").splitlines()[:6]:
            if line.strip():
                print_info(f"  {line}")

        print_info("-" * 60)
        print_info(f"Domain: {data.get('Domain', '?')} (joined={data.get('PartOfDomain', False)})")
        if data.get("LogonServer"):
            print_info(f"  Logon server: {data['LogonServer']}")

        print_info("-" * 60)
        print_info("klist")
        klist = data.get("Klist", "")
        if klist:
            for line in klist.splitlines()[:25]:
                print_info(f"  {line}")
        else:
            print_status("  (no klist output)")

        if self.include_tgt_details and data.get("KlistTgt"):
            print_info("-" * 60)
            print_info("klist -tgt")
            for line in data["KlistTgt"].splitlines()[:20]:
                print_info(f"  {line}")

        print_info("=" * 60)
        return True
