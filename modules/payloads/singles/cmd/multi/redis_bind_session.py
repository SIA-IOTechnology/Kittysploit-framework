#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "Redis BIND Session",
        "description": "BIND payload for listeners/database/redis",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/redis",
        "handler": Handler.BIND,
        "session_type": SessionType.REDIS,
    }

    rhost = OptString("127.0.0.1", "Redis host", True)
    rport = OptPort(6379, "Redis port", True)
    password = OptString("", "Redis password", False)
    db = OptInteger(0, "Redis DB index", False)

    def generate(self):
        return build_bind_session_hint(
            "Redis", str(self.rhost), int(self.rport or 6379),
            extra=f"db={int(self.db or 0)}",
            probe="PING",
        )
