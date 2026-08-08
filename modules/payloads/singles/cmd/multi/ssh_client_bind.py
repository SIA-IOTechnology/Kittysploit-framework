#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "SSH Client BIND",
        "description": "BIND payload for listeners/multi/ssh_client",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/multi/ssh_client",
        "handler": Handler.BIND,
        "session_type": SessionType.SSH,
    }

    rhost = OptString("127.0.0.1", "SSH target host", True)
    rport = OptPort(22, "SSH port", True)
    username = OptString("root", "SSH username", True)
    password = OptString("", "SSH password", True)

    def generate(self):
        return build_bind_session_hint(
            "SSH", str(self.rhost), int(self.rport or 22),
            username=str(self.username or "root"),
            probe=f"ssh {self.username}@{self.rhost} -p {int(self.rport or 22)}",
        )
