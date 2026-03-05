#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Kerberoastable accounts (users with SPNs)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_helpers import UAC_DONT_EXPIRE_PASSWD

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD Kerberoastable accounts",
        "description": "Detects user accounts with SPNs (Kerberoast targets).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "kerberos", "kerberoast", "spn"],
    }

    def run(self):
        # Users (not computers) with SPNs, enabled
        kerb = self.search(
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "adminCount", "pwdLastSet", "userAccountControl"],
        )
        if not kerb:
            return False
        names = []
        admin_never_expire = []
        for u in kerb[:30]:
            n = self.attr_str(u, "sAMAccountName")
            names.append(n)
            if self.attr_int(u, "adminCount") == 1:
                uac = self.attr_int(u, "userAccountControl")
                if uac & UAC_DONT_EXPIRE_PASSWD:
                    admin_never_expire.append(n)
        reason = f"{len(kerb)} Kerberoastable account(s)"
        if admin_never_expire:
            reason += f" (admin+never expire: {', '.join(admin_never_expire[:5])})"
        else:
            reason += f": {', '.join(names[:8])}"
        self.set_info(severity="high", reason=reason)
        return True
