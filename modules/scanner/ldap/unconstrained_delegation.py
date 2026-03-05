#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect unconstrained delegation (computers and users)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD unconstrained delegation",
        "description": "Detects computers and users trusted for unconstrained delegation.",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "delegation", "unconstrained"],
    }

    def run(self):
        # Computers (not DCs) with TRUSTED_FOR_DELEGATION (524288)
        unc_computers = self.search(
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            ["sAMAccountName", "dNSHostName"],
        )
        # Users with unconstrained delegation
        unc_users = self.search(
            "(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "adminCount"],
        )
        if not unc_computers and not unc_users:
            return False
        parts = []
        if unc_computers:
            names = [self.attr_str(c, "dNSHostName") or self.attr_str(c, "sAMAccountName") for c in unc_computers[:10]]
            parts.append(f"computers: {', '.join(names)}")
        if unc_users:
            names = [self.attr_str(u, "sAMAccountName") for u in unc_users[:10]]
            parts.append(f"users: {', '.join(names)}")
        self.set_info(severity="high", reason="; ".join(parts))
        return True
