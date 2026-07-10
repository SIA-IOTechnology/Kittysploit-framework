#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather EDR & Defender Audit",
        "description": (
            "Audit Windows Defender status, RunAsPPL, Credential Guard / VBS, "
            "AMSI availability, and common EDR process indicators."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    check_processes = OptBool(True, "Enumerate common EDR/AV process names", False)

    _EDR_PROCESSES = (
        "MsMpEng", "MsSense", "SenseIR", "SenseCncProxy",
        "CSFalconService", "CSFalconContainer", "SentinelAgent",
        "SentinelHelperService", "elastic-agent", "elastic-endpoint",
        "cb", "RepMgr", "RepUtils", "CylanceSvc", "TaniumClient",
        "sysmon", "Sysmon64",
    )

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Windows Defender (Get-MpComputerStatus)")
        status = self.win_run_powershell(
            "try { Get-MpComputerStatus | Format-List * | Out-String -Width 4096 } "
            "catch { Write-Output $_.Exception.Message }",
            timeout=20,
        )
        print_info(status or "(Get-MpComputerStatus unavailable — Defender may be absent)")

        print_info("-" * 60)
        print_info("LSA RunAsPPL")
        print_info(
            self.win_execute(
                r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL',
                timeout=8,
            )
            or "(no data)"
        )

        print_info("-" * 60)
        print_info("Credential Guard / Device Guard")
        print_info(
            self.win_run_powershell(
                "Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue | "
                "Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus | "
                "Format-List | Out-String",
                timeout=15,
            )
            or "(no data)"
        )

        print_info("-" * 60)
        print_info("AMSI test string (should NOT be blocked in audit mode)")
        amsi_test = self.win_run_powershell("'amsiutils' + 'amsicontext'", timeout=10)
        if amsi_test:
            print_info(f"AMSI probe output: {amsi_test}")
        else:
            print_status("AMSI probe returned no output (may indicate blocking).")

        if self.check_processes:
            print_info("-" * 60)
            print_info("EDR / AV process scan")
            found = []
            for name in self._EDR_PROCESSES:
                out = self.win_execute(
                    f'tasklist /FI "IMAGENAME eq {name}.exe" /NH',
                    timeout=8,
                )
                if out and name.lower() in out.lower() and "no tasks" not in out.lower():
                    found.append(name)
            if found:
                print_warning(f"Detected: {', '.join(found)}")
            else:
                print_status("No known EDR process names matched tasklist filter.")

        if self.win_is_admin():
            print_success("Session has administrator privileges.")
        else:
            print_status("Session is not elevated — some evasion actions will fail.")

        print_info("=" * 60)
        return True
