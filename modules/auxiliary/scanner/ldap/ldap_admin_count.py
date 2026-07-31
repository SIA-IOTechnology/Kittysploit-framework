#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""List adminCount=1 accounts (NetExec: nxc ldap --admin-count)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_enum import enumerate_users


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP AdminCount Accounts",
        "description": (
            "Lists accounts with adminCount=1 (AdminSDHolder / protected groups) "
            "(NetExec: nxc ldap <dc> -u -p --admin-count)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "admincount", "enumeration", "auxiliary", "netexec"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        if not self.conn:
            print_error("LDAP bind failed")
            return {"error": "ldap_bind_failed"}
        rows = enumerate_users(self, admin_count_only=True)
        print_success(f"{len(rows)} adminCount=1 account(s)")
        for r in rows:
            print_info(f"  {r['sam']}")
        return {"domain": self.domain, "count": len(rows), "users": [r["sam"] for r in rows]}
