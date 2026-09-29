#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "scope_guard"

    __info__ = {
        "name": "Scope Guard (PowerShell)",
        "description": "Exit when the callback host is outside the embedded lab scope",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "guard", "powershell"],
    }

    allowed_scope = OptString("", "Extra allowed hosts/CIDRs (comma-separated)", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").replace("'", "''")
        raw_scope = str(ctx.get("prestage_scope") or getattr(getattr(self, "allowed_scope", None), "value", "") or "").replace("'", "''")
        return f"""
$ErrorActionPreference='SilentlyContinue'
$c2Host='{c2_host}'
$allowed=@('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8')
if('{raw_scope}'){{ $allowed += '{raw_scope}'.Split(',') | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }} }}
function _KittyScopeAllowed($hostName){{
  if(-not $hostName){{ return $false }}
  try {{
    $ip=[System.Net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($hostName)[0].IPAddressToString)
    foreach($cidr in $allowed){{
      if($cidr -notmatch '/'){{ if($hostName -eq $cidr){{ return $true }}; continue }}
      $parts=$cidr.Split('/'); $net=$parts[0]; $bits=[int]$parts[1]
      $mask=[uint32]([math]::Pow(2,32)-[math]::Pow(2,(32-$bits)))
      $netIp=[System.Net.IPAddress]::Parse($net).GetAddressBytes(); [Array]::Reverse($netIp)
      $netNum=[BitConverter]::ToUInt32($netIp,0)
      $ipBytes=$ip.GetAddressBytes(); [Array]::Reverse($ipBytes)
      $ipNum=[BitConverter]::ToUInt32($ipBytes,0)
      if(($ipNum -band $mask) -eq ($netNum -band $mask)){{ return $true }}
    }}
  }} catch {{}}
  return $false
}}
if($c2Host -and -not (_KittyScopeAllowed $c2Host)){{ try {{ _KittyTelemetryRecord 'scope_guard' 'blocked' $c2Host }} catch {{}}; exit 0 }}
""".strip()
