#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.stream.xor import Module as PythonXorObfuscator


class Module(PythonXorObfuscator):
    """PHP XOR stream obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP XOR Stream Obfuscator",
        "description": "XORs the C2 stream with a repeating key and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        php_key = (str(self.key).strip() or "kittysploit").replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"$obf_key='{php_key}';$obf_doff=0;$obf_eoff=0;"
            "function _obf_xor($d,&$off){global $obf_key;$kl=strlen($obf_key);"
            "if($d===''||$kl<1){return $d;}$out='';$dl=strlen($d);"
            "for($i=0;$i<$dl;$i++){$out.=chr(ord($d[$i])^ord($obf_key[($off+$i)%$kl]));}"
            "$off+=$dl;return $out;}"
            "function _obf_decode($d){global $obf_doff;return _obf_xor($d,$obf_doff);}"
            "function _obf_encode($d){global $obf_eoff;return _obf_xor($d,$obf_eoff);}"
        )
