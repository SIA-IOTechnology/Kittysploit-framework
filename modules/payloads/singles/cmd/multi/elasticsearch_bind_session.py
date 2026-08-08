#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "Elasticsearch BIND Session",
        "description": "BIND payload for listeners/database/elasticsearch",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/elasticsearch",
        "handler": Handler.BIND,
        "session_type": SessionType.ELASTICSEARCH,
    }

    rhost = OptString("127.0.0.1", "Elasticsearch host", True)
    rport = OptPort(9200, "Elasticsearch port", True)
    username = OptString("", "Username", False)
    password = OptString("", "Password", False)
    use_ssl = OptBool(False, "Use HTTPS", False)

    def generate(self):
        scheme = "https" if bool(self.use_ssl) else "http"
        return build_bind_session_hint(
            "Elasticsearch", str(self.rhost), int(self.rport or 9200),
            username=str(self.username or ""),
            probe=f"GET {scheme}://{self.rhost}:{int(self.rport or 9200)}/",
        )
