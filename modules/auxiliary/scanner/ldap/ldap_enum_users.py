#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate domain users (NetExec: nxc ldap --users)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_enum import enumerate_users


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Enum Users",
        "description": (
            "Lists domain users with pwdLastSet and badPwdCount "
            "(NetExec: nxc ldap <dc> -u -p --users)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "users", "enumeration", "auxiliary", "netexec"],
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
        rows = enumerate_users(self)
        print_success(f"Enumerated {len(rows)} domain user(s): {self.domain or '?'}")
        print_info(f"{'Username':<20} {'Last PW Set':<20} {'BadPwd':>6} {'Admin':>5}")
        for r in rows:
            print_info(
                f"{str(r['sam'])[:20]:<20} {str(r['pwd_last_set'])[:20]:<20} "
                f"{int(r['bad_pwd_count']):>6} {('Y' if r['admin_count'] else ''):>5}"
            )
        return {"domain": self.domain, "count": len(rows), "users": rows}
