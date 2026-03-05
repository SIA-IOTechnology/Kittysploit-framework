#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SID History abuse (privileged SIDs in sIDHistory)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_helpers import get_domain_sid, sid_is_privileged

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD SID History abuse",
        "description": "Detects accounts with privileged SIDs in sIDHistory (persistence/backdoor).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "sid history", "persistence"],
    }

    def run(self):
        domain_sid = get_domain_sid(self)
        users = self.search("(&(objectClass=user)(sIDHistory=*))", ["sAMAccountName", "sIDHistory"])
        computers = self.search("(&(objectClass=computer)(sIDHistory=*))", ["sAMAccountName", "sIDHistory"])
        priv_hits = []
        for u in users + computers:
            name = self.attr_str(u, "sAMAccountName")
            for sid in self.attr_list(u, "sIDHistory"):
                sid_str = str(sid)
                if sid_is_privileged(sid_str, domain_sid):
                    priv_hits.append(f"{name} -> {sid_str}")
        if not priv_hits:
            return False
        self.set_info(severity="high", reason=f"{len(priv_hits)} privileged SID(s) in history: {'; '.join(priv_hits[:6])}")
        return True
