#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Firewall Posture Audit",
        "description": "List firewall profiles and inbound allow rules",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562.004/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
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

    include_rules = OptBool(True, "Include enabled inbound allow rules", False)
    max_rules = OptInteger(25, "Maximum firewall rules to list", False)

    def _collect_script(self) -> str:
        include_rules = "true" if self.include_rules else "false"
        max_rules = int(self.max_rules or 25)
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$includeRules = ${include_rules}
$maxRules = {max_rules}

$report = [PSCustomObject]@{{
    Profiles = @()
    InboundAllowRules = @()
    NetshSummary = (netsh advfirewall show allprofiles 2>&1 | Out-String).Trim()
}}

try {{
    $report.Profiles = Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules
}} catch {{
    $report.ProfileError = $_.Exception.Message
}}

if ($includeRules) {{
    try {{
        $report.InboundAllowRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop |
            Select-Object -First $maxRules DisplayName, Profile, Direction, Action, Program, Service |
            ForEach-Object {{
                $port = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                [PSCustomObject]@{{
                    DisplayName = $_.DisplayName
                    Profile = $_.Profile
                    Program = $_.Program
                    Service = $_.Service
                    LocalPort = $port.LocalPort
                    RemotePort = $port.RemotePort
                    Protocol = $port.Protocol
                }}
            }}
    }} catch {{
        $report.RuleError = $_.Exception.Message
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
        print_info("Windows Firewall")

        raw = self.win_run_powershell(self._collect_script(), timeout=35)
        if not raw:
            # fallback netsh only
            out = self.win_execute("netsh advfirewall show allprofiles", timeout=12)
            print_info(out or "(no output)")
            return True

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse firewall audit output: {exc}")
            print_info(raw[:2000])
            return False

        profiles = data.get("Profiles") or []
        if profiles:
            print_info("Firewall profiles:")
            for profile in profiles:
                print_info(
                    f"  {profile.get('Name', '?')}: enabled={profile.get('Enabled', '?')} "
                    f"inbound={profile.get('DefaultInboundAction', '?')} "
                    f"outbound={profile.get('DefaultOutboundAction', '?')}"
                )
        elif data.get("NetshSummary"):
            print_info(data["NetshSummary"][:1500])

        if self.include_rules:
            rules = data.get("InboundAllowRules") or []
            print_info("-" * 60)
            print_info(f"Inbound allow rules sampled: {len(rules)}")
            for rule in rules[:12]:
                print_info(
                    f"  {rule.get('DisplayName', '?')} "
                    f"ports={rule.get('LocalPort', '?')} "
                    f"prog={rule.get('Program', '')}"
                )

        for err_key in ("ProfileError", "RuleError"):
            if data.get(err_key):
                print_warning(data[err_key])

        print_info("=" * 60)
        return True
