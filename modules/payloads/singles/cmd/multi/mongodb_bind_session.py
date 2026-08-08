#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "MongoDB BIND Session",
        "description": "BIND payload for listeners/database/mongodb",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/mongodb",
        "handler": Handler.BIND,
        "session_type": SessionType.MONGODB,
    }

    rhost = OptString("127.0.0.1", "MongoDB host", True)
    rport = OptPort(27017, "MongoDB port", True)
    username = OptString("", "MongoDB username", False)
    password = OptString("", "MongoDB password", False)
    database = OptString("admin", "Auth database", False)

    def generate(self):
        return build_bind_session_hint(
            "MongoDB", str(self.rhost), int(self.rport or 27017),
            username=str(self.username or ""),
            extra=f"authdb={self.database or 'admin'}",
            probe="db.adminCommand({ping:1})",
        )
