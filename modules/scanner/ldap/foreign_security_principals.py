#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Foreign Security Principals in privileged groups."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD foreign security principals in privileged groups",
        "description": "Detects FSPs from trusted domains in sensitive local groups.",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "fsp", "trust", "privileged"],
    }

    def run(self):
        base = self.base_dn
        if not base:
            return False
        sensitive = [
            f"CN=Domain Admins,CN=Users,{base}",
            f"CN=Enterprise Admins,CN=Users,{base}",
            f"CN=Schema Admins,CN=Users,{base}",
            f"CN=Administrators,CN=Builtin,{base}",
            f"CN=Account Operators,CN=Builtin,{base}",
            f"CN=Backup Operators,CN=Builtin,{base}",
            f"CN=Server Operators,CN=Builtin,{base}",
            f"CN=Group Policy Creator Owners,CN=Users,{base}",
        ]
        fsp_base = f"CN=ForeignSecurityPrincipals,{base}"
        fsps = self.search("(objectClass=foreignSecurityPrincipal)", ["cn", "memberOf"], base=fsp_base)
        hits = []
        for fsp in fsps:
            groups = self.attr_list(fsp, "memberOf")
            sid = self.attr_str(fsp, "cn")
            for gdn in groups:
                if any(gdn.upper() == s.upper() for s in sensitive):
                    res = self.resolve_sid(sid)
                    hits.append(f"{res} -> privileged group")
        if not hits:
            return False
        self.set_info(severity="high", reason=f"{len(hits)} FSP(s) in privileged groups: {'; '.join(hits[:6])}")
        return True
