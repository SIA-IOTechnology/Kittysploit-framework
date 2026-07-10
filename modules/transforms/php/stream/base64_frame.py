#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.stream.base64_frame import Module as PythonBase64FrameObfuscator


class Module(PythonBase64FrameObfuscator):
    """PHP Base64 framed stream obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP Base64 Frame Obfuscator",
        "description": "Frames C2 chunks as length-prefixed Base64 lines and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$obf_buf='';"
            "function _obf_encode($d){if($d===''){return $d;}return 'K64 '.base64_encode(pack('N',strlen($d)).$d).\"\\n\";}"
            "function _obf_decode($d){global $obf_buf;$obf_buf.=$d;$out='';"
            "while(($p=strpos($obf_buf,\"\\n\"))!==false){"
            "$line=trim(substr($obf_buf,0,$p));$obf_buf=substr($obf_buf,$p+1);"
            "if(substr($line,0,4)!=='K64 '){continue;}"
            "$raw=base64_decode(substr($line,4),true);if($raw===false||strlen($raw)<4){continue;}"
            "$u=unpack('Nlen',substr($raw,0,4));$ln=$u['len'];"
            "if($ln<=1048576&&$ln<=strlen($raw)-4){$out.=substr($raw,4,$ln);}"
            "}return $out;}"
        )
