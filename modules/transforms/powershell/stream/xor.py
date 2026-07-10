#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.stream.xor import Module as PythonXorTransform


class Module(Transform, PythonXorTransform):
    """PowerShell XOR stream transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell XOR Stream Transform",
        "description": "XORs the C2 stream with a repeating key and emits PowerShell client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "powershell":
            return None
        key_val = (str(self.key).strip() or "kittysploit").replace("\\", "\\\\").replace("'", "\\'")
        ps_key = key_val.replace("`", "``").replace('"', '`"').replace("$", "`$")
        return (
            f"$script:xfKey=[Text.Encoding]::UTF8.GetBytes(\"{ps_key}\");\n"
            "$script:xfDoff=0;$script:xfEoff=0;\n"
            "function _xf_decode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object byte[] $d.Length\n"
            " for($i=0;$i -lt $d.Length;$i++){$out[$i]=[byte]($d[$i] -bxor $script:xfKey[($script:xfDoff+$i)%$script:xfKey.Length])}\n"
            " $script:xfDoff += $d.Length\n"
            " return $out\n"
            "}\n"
            "function _xf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object byte[] $d.Length\n"
            " for($i=0;$i -lt $d.Length;$i++){$out[$i]=[byte]($d[$i] -bxor $script:xfKey[($script:xfEoff+$i)%$script:xfKey.Length])}\n"
            " $script:xfEoff += $d.Length\n"
            " return $out\n"
            "}\n"
        )
