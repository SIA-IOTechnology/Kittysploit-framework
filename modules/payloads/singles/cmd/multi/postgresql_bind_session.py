#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "PostgreSQL BIND Session",
        "description": "BIND payload for listeners/database/postgresql (direct psycopg2 session)",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/postgresql",
        "handler": Handler.BIND,
        "session_type": SessionType.POSTGRESQL,
    }

    rhost = OptString("127.0.0.1", "PostgreSQL host", True)
    rport = OptPort(5432, "PostgreSQL port", True)
    username = OptString("postgres", "PostgreSQL username", True)
    password = OptString("", "PostgreSQL password", False)
    database = OptString("postgres", "Database name", False)

    def generate(self):
        return build_bind_session_hint(
            "PostgreSQL", str(self.rhost), int(self.rport or 5432),
            username=str(self.username or "postgres"),
            extra=f"database={self.database or 'postgres'}",
            probe="SELECT version();",
        )
