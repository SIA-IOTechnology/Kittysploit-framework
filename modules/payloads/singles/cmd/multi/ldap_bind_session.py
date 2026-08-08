#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.c2.database_bind import build_bind_session_hint


class Module(Payload):
    __info__ = {
        "name": "LDAP BIND Session",
        "description": "BIND payload for listeners/database/ldap",
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/database/ldap",
        "handler": Handler.BIND,
        "session_type": SessionType.LDAP,
    }

    rhost = OptString("127.0.0.1", "LDAP host", True)
    rport = OptPort(389, "LDAP port", True)
    username = OptString("", "Bind DN", False)
    password = OptString("", "Bind password", False)
    use_ssl = OptBool(False, "Use LDAPS", False)
    base_dn = OptString("", "Search base DN", False)

    def generate(self):
        scheme = "ldaps" if bool(self.use_ssl) else "ldap"
        return build_bind_session_hint(
            "LDAP", str(self.rhost), int(self.rport or 389),
            username=str(self.username or "(anonymous)"),
            extra=f"base_dn={self.base_dn or ''}",
            probe=f"# {scheme}://{self.rhost}:{int(self.rport or 389)}",
        )
