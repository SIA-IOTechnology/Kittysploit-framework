#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "resource_guard"

    __info__ = {
        "name": "Resource Guard (PowerShell)",
        "description": "Exit early when memory or disk looks too constrained for the intended target",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "powershell"],
    }

    min_mem_mb = OptString("32", "Minimum physical memory in MB", False)
    min_disk_mb = OptString("10", "Minimum free disk in MB", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        try:
            min_mem = int(getattr(getattr(self, "min_mem_mb", None), "value", self.min_mem_mb) or 32)
        except (TypeError, ValueError):
            min_mem = 32
        try:
            min_disk = int(getattr(getattr(self, "min_disk_mb", None), "value", self.min_disk_mb) or 10)
        except (TypeError, ValueError):
            min_disk = 10
        return f"""
$ErrorActionPreference='SilentlyContinue'
$global:_kitty_resource_guard=@{{ ok=$true; mem_mb=0; disk_mb=0 }}
try {{ $global:_kitty_resource_guard.disk_mb=[int]((Get-PSDrive -Name C).Free/1MB) }} catch {{}}
try {{ $global:_kitty_resource_guard.mem_mb=[int]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1MB) }} catch {{}}
if($global:_kitty_resource_guard.mem_mb -gt 0 -and $global:_kitty_resource_guard.mem_mb -lt {min_mem}){{ try {{ _KittyTelemetryRecord 'resource_guard' 'low_memory' $global:_kitty_resource_guard.mem_mb }} catch {{}}; exit 0 }}
if($global:_kitty_resource_guard.disk_mb -gt 0 -and $global:_kitty_resource_guard.disk_mb -lt {min_disk}){{ try {{ _KittyTelemetryRecord 'resource_guard' 'low_disk' $global:_kitty_resource_guard.disk_mb }} catch {{}}; exit 0 }}
""".strip()
