#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect accounts using DES-only Kerberos encryption."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD DES Kerberos encryption",
        "description": "Detects accounts restricted to DES Kerberos encryption (weak).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "kerberos", "des", "encryption"],
    }

    def run(self):
        # userAccountControl 2097152 = USE_DES_KEY_ONLY
        des = self.search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        if not des:
            return False
        names = [self.attr_str(u, "sAMAccountName") for u in des[:15]]
        self.set_info(severity="medium", reason=f"{len(des)} account(s): {', '.join(names)}")
        return True
