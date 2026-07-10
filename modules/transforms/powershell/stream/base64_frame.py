#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.stream.base64_frame import Module as PythonBase64FrameObfuscator


class Module(PythonBase64FrameObfuscator):
    """PowerShell Base64 framed stream obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell Base64 Frame Obfuscator",
        "description": "Frames C2 chunks as length-prefixed Base64 lines and emits PowerShell client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        return (
            "$script:obfBuf=New-Object System.Collections.Generic.List[byte];\n"
            "function _obf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $len=[BitConverter]::GetBytes([UInt32]$d.Length);[Array]::Reverse($len)\n"
            " $raw=New-Object byte[] (4+$d.Length);[Array]::Copy($len,0,$raw,0,4);[Array]::Copy($d,0,$raw,4,$d.Length)\n"
            " $line='K64 '+[Convert]::ToBase64String($raw)+\"`n\"\n"
            " return [Text.Encoding]::ASCII.GetBytes($line)\n"
            "}\n"
            "function _obf_decode([byte[]]$d){\n"
            " if($null -ne $d -and $d.Length -gt 0){$script:obfBuf.AddRange($d)}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " while($true){\n"
            "  $idx=-1\n"
            "  for($i=0;$i -lt $script:obfBuf.Count;$i++){if($script:obfBuf[$i] -eq 10){$idx=$i;break}}\n"
            "  if($idx -lt 0){break}\n"
            "  $lineBytes=$script:obfBuf.GetRange(0,$idx).ToArray();$script:obfBuf.RemoveRange(0,$idx+1)\n"
            "  $line=[Text.Encoding]::ASCII.GetString($lineBytes).Trim()\n"
            "  if(-not $line.StartsWith('K64 ')){continue}\n"
            "  try{$raw=[Convert]::FromBase64String($line.Substring(4))}catch{continue}\n"
            "  if($raw.Length -lt 4){continue}\n"
            "  $lenBytes=New-Object byte[] 4;[Array]::Copy($raw,0,$lenBytes,0,4);[Array]::Reverse($lenBytes)\n"
            "  $ln=[BitConverter]::ToUInt32($lenBytes,0)\n"
            "  if($ln -gt 1048576 -or $ln -gt ($raw.Length-4)){continue}\n"
            "  $payload=New-Object byte[] $ln;[Array]::Copy($raw,4,$payload,0,$ln);$out.AddRange($payload)\n"
            " }\n"
            " return $out.ToArray()\n"
            "}\n"
        )
