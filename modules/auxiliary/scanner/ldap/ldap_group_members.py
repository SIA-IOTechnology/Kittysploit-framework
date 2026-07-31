#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Group membership helpers (NetExec: --groups / groupmembership)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_enum import group_members, user_group_membership


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Group Members",
        "description": (
            "List members of a group, or groups for a user "
            "(NetExec: --groups 'Backup Operators' / -M groupmembership)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "groups", "enumeration", "auxiliary", "netexec"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    group = OptString(
        "",
        "Group name to list members of (e.g. Backup Operators)",
        False,
    )
    user = OptString(
        "",
        "User sAMAccountName to list group membership for",
        False,
    )

    def run(self):
        if not self.conn:
            print_error("LDAP bind failed")
            return {"error": "ldap_bind_failed"}
        group = str(self.group or "").strip()
        user = str(self.user or "").strip()
        if not group and not user:
            print_error("Set group and/or user")
            return {"error": "missing_group_or_user"}

        payload = {"domain": self.domain}
        if group:
            members = group_members(self, group)
            print_success(f"Group '{group}': {len(members)} member(s)")
            for m in members:
                print_info(f"  {m}")
            payload["group"] = group
            payload["members"] = members
        if user:
            groups = user_group_membership(self, user)
            print_success(f"User '{user}' is member of {len(groups)} group(s)")
            for g in groups:
                print_info(f"  {g}")
            payload["user"] = user
            payload["groups"] = groups
        return payload
