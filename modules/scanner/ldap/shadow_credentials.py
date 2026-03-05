#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect shadow credentials (msDS-KeyCredentialLink) on accounts."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD shadow credentials",
        "description": "Detects accounts with msDS-KeyCredentialLink set (PKINIT takeover possible).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "shadow credentials", "keycredential", "pkinit"],
    }

    def run(self):
        users = self.search(
            "(&(objectClass=user)(!(objectClass=computer))(msDS-KeyCredentialLink=*))",
            ["sAMAccountName", "adminCount"],
        )
        computers = self.search(
            "(&(objectClass=computer)(msDS-KeyCredentialLink=*))",
            ["sAMAccountName"],
        )
        if not users and not computers:
            return False
        admin_hits = [self.attr_str(u, "sAMAccountName") for u in users if self.attr_int(u, "adminCount") == 1]
        other = [self.attr_str(u, "sAMAccountName") for u in users if self.attr_int(u, "adminCount") != 1]
        comp_names = [self.attr_str(c, "sAMAccountName") for c in computers]
        parts = []
        if admin_hits:
            parts.append(f"admin(s): {', '.join(admin_hits[:8])}")
        if other or comp_names:
            parts.append(f"others: {', '.join((other + comp_names)[:8])}")
        self.set_info(severity="high", reason="; ".join(parts))
        return True
