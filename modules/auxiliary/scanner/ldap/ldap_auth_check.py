#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate domain credentials over LDAP (NetExec: nxc ldap host -u -p)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Auth Check",
        "description": (
            "Validates domain credentials with an LDAP bind and reports domain / DC info "
            "(NetExec: nxc ldap <dc> -u <user> -p <pass>)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "auth", "auxiliary", "netexec"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "auth_attempt"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        user = str(self.username or "").strip()
        if not user:
            print_error("username is required")
            return {"error": "missing_username"}
        if not self.conn:
            print_error(f"LDAP bind failed for {user}")
            return {"error": "ldap_bind_failed", "user": user}
        print_success(f"LDAP bind OK: {self.domain or '?'}\\{user}")
        print_info(f"Base DN: {self.base_dn}")
        print_info(f"DC: {self.dc_ip or self.target}")
        return {
            "ok": True,
            "domain": self.domain,
            "base_dn": self.base_dn,
            "user": user,
            "dc": self.dc_ip or str(self.target or ""),
        }
