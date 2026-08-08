#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "MSSQL BIND Session",
        "description": "BIND payload for listeners/database/mssql",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/mssql",
        "handler": Handler.BIND,
        "session_type": SessionType.MSSQL,
    }

    rhost = OptString("127.0.0.1", "MSSQL host", True)
    rport = OptPort(1433, "MSSQL port", True)
    username = OptString("sa", "MSSQL username", True)
    password = OptString("", "MSSQL password", False)
    database = OptString("master", "Database name", False)

    def generate(self):
        return build_bind_session_hint(
            "MSSQL", str(self.rhost), int(self.rport or 1433),
            username=str(self.username or "sa"),
            extra=f"database={self.database or 'master'}",
            probe="SELECT @@version;",
        )
