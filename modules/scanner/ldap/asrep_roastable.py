#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect AS-REP Roastable accounts (pre-auth disabled)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD AS-REP Roastable accounts",
        "description": "Detects accounts with Kerberos pre-authentication disabled (AS-REP roasting).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "kerberos", "asrep", "preauth"],
    }

    def run(self):
        # userAccountControl bit 4194304 = DONT_REQUIRE_PREAUTH
        asrep = self.search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "adminCount"],
        )
        if not asrep:
            return False
        names = [self.attr_str(u, "sAMAccountName") for u in asrep[:20]]
        adm = [n for u, n in zip(asrep, names) if self.attr_int(u, "adminCount") == 1]
        reason = f"{len(asrep)} account(s): {', '.join(names[:8])}"
        if adm:
            reason += f" (admin: {', '.join(adm[:5])})"
        self.set_info(severity="high", reason=reason)
        return True
