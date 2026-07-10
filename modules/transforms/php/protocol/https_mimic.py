#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.protocol.https_mimic import (
    CLIENT_HELLO_BYTES,
    Module as PythonHttpsObfuscator,
)


class Module(PythonHttpsObfuscator):
    """PHP HTTPS/TLS record mimic obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP HTTPS Mimic Obfuscator",
        "description": "Sends a fake TLS ClientHello then wraps C2 bytes in TLS Application Data records.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        hello_hex = CLIENT_HELLO_BYTES.hex()
        return (
            f"$obf_client_hello=hex2bin('{hello_hex}');$obf_buf='';$obf_first=true;"
            "function _obf_encode($d){global $obf_client_hello,$obf_first;if($d===''){return $d;}$out='';"
            "if($obf_first){$out.=$obf_client_hello;$obf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,16384);$i+=strlen($c);$n=strlen($c);$out.=chr(0x17).chr(0x03).chr(0x03).chr(($n>>8)&255).chr($n&255).$c;}return $out;}"
            "function _obf_decode($d){global $obf_buf;$obf_buf.=$d;$out='';"
            "while(strlen($obf_buf)>=5){$rt=ord($obf_buf[0]);$ln=(ord($obf_buf[3])<<8)|ord($obf_buf[4]);"
            "if($ln>16384){$obf_buf=substr($obf_buf,1);continue;}if(strlen($obf_buf)<5+$ln){break;}"
            "if($rt===0x17){$out.=substr($obf_buf,5,$ln);}$obf_buf=substr($obf_buf,5+$ln);}return $out;}"
        )
