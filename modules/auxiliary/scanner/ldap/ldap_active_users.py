#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""List enabled/active domain users (NetExec: nxc ldap --active-users)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_enum import enumerate_users


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Active Users",
        "description": (
            "Lists enabled (not ACCOUNTDISABLE) domain users for spray targeting "
            "(NetExec: nxc ldap <dc> -u -p --active-users)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "users", "spray", "enumeration", "auxiliary", "netexec"],
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
        all_users = enumerate_users(self)
        active = enumerate_users(self, active_only=True)
        disabled = len(all_users) - len(active)
        print_success(
            f"{len(all_users)} total, {disabled} disabled → {len(active)} active user(s)"
        )
        for r in active:
            print_info(f"  {r['sam']}")
        return {
            "domain": self.domain,
            "total": len(all_users),
            "disabled": disabled,
            "active": len(active),
            "users": [r["sam"] for r in active],
        }
