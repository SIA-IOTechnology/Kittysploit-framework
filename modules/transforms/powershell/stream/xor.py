#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.stream.xor import Module as PythonXorObfuscator


class Module(PythonXorObfuscator):
    """PowerShell XOR stream obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["powershell"]

    __info__ = {
        "name": "PowerShell XOR Stream Obfuscator",
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
            f"$script:obfKey=[Text.Encoding]::UTF8.GetBytes(\"{ps_key}\");\n"
            "$script:obfDoff=0;$script:obfEoff=0;\n"
            "function _obf_decode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object byte[] $d.Length\n"
            " for($i=0;$i -lt $d.Length;$i++){$out[$i]=[byte]($d[$i] -bxor $script:obfKey[($script:obfDoff+$i)%$script:obfKey.Length])}\n"
            " $script:obfDoff += $d.Length\n"
            " return $out\n"
            "}\n"
            "function _obf_encode([byte[]]$d){\n"
            " if($null -eq $d -or $d.Length -eq 0){return [byte[]]@()}\n"
            " $out=New-Object byte[] $d.Length\n"
            " for($i=0;$i -lt $d.Length;$i++){$out[$i]=[byte]($d[$i] -bxor $script:obfKey[($script:obfEoff+$i)%$script:obfKey.Length])}\n"
            " $script:obfEoff += $d.Length\n"
            " return $out\n"
            "}\n"
        )
