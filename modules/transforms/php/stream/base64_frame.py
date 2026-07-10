#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.stream.base64_frame import Module as PythonBase64FrameTransform


class Module(Transform, PythonBase64FrameTransform):
    """PHP Base64 framed stream transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP Base64 Frame Transform",
        "description": "Frames C2 chunks as length-prefixed Base64 lines and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$xf_buf='';"
            "function _xf_encode($d){if($d===''){return $d;}return 'K64 '.base64_encode(pack('N',strlen($d)).$d).\"\\n\";}"
            "function _xf_decode($d){global $xf_buf;$xf_buf.=$d;$out='';"
            "while(($p=strpos($xf_buf,\"\\n\"))!==false){"
            "$line=trim(substr($xf_buf,0,$p));$xf_buf=substr($xf_buf,$p+1);"
            "if(substr($line,0,4)!=='K64 '){continue;}"
            "$raw=base64_decode(substr($line,4),true);if($raw===false||strlen($raw)<4){continue;}"
            "$u=unpack('Nlen',substr($raw,0,4));$ln=$u['len'];"
            "if($ln<=1048576&&$ln<=strlen($raw)-4){$out.=substr($raw,4,$ln);}"
            "}return $out;}"
        )
