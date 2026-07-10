#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.stream.xor import Module as PythonXorTransform


class Module(Transform, PythonXorTransform):
    """PHP XOR stream transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP XOR Stream Transform",
        "description": "XORs the C2 stream with a repeating key and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        php_key = (str(self.key).strip() or "kittysploit").replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"$xf_key='{php_key}';$xf_doff=0;$xf_eoff=0;"
            "function _xf_xor($d,&$off){global $xf_key;$kl=strlen($xf_key);"
            "if($d===''||$kl<1){return $d;}$out='';$dl=strlen($d);"
            "for($i=0;$i<$dl;$i++){$out.=chr(ord($d[$i])^ord($xf_key[($off+$i)%$kl]));}"
            "$off+=$dl;return $out;}"
            "function _xf_decode($d){global $xf_doff;return _xf_xor($d,$xf_doff);}"
            "function _xf_encode($d){global $xf_eoff;return _xf_xor($d,$xf_eoff);}"
        )
