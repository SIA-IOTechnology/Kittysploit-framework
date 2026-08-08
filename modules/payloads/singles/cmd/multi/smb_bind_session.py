#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "SMB Client BIND Session",
        "description": "BIND payload for listeners/smb/client",
        "category": PayloadCategory.CMD,
        "platform": Platform.WINDOWS,
        "listener": "listeners/smb/client",
        "handler": Handler.BIND,
        "session_type": SessionType.SMB,
    }

    rhost = OptString("127.0.0.1", "SMB target host", True)
    rport = OptPort(445, "SMB port", True)
    username = OptString("", "SMB username", False)
    password = OptString("", "SMB password", False)
    domain = OptString("", "SMB domain", False)

    def generate(self):
        dom = f" domain={self.domain}" if str(self.domain or "").strip() else ""
        return build_bind_session_hint(
            "SMB", str(self.rhost), int(self.rport or 445),
            username=str(self.username or "(null/guest)"),
            extra=dom.strip(),
            probe=f"net view \\\\{self.rhost}",
        )
