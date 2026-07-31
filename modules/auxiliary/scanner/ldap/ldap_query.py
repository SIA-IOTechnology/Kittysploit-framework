#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Raw LDAP query (NetExec: nxc ldap --query)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Query",
        "description": (
            "Runs a raw LDAP filter and dumps matching attributes "
            "(NetExec: nxc ldap <dc> -u -p --query '(sAMAccountName=user)' '')."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "query", "enumeration", "auxiliary", "netexec"],
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

    ldap_filter = OptString(
        "(objectClass=user)",
        "LDAP filter (e.g. (sAMAccountName=krishna))",
        True,
    )
    attributes = OptString(
        "",
        "Comma-separated attributes (empty = common set)",
        False,
    )
    size_limit = OptInteger(50, "Max entries to return", False, advanced=True)

    def run(self):
        if not self.conn:
            print_error("LDAP bind failed")
            return {"error": "ldap_bind_failed"}
        filt = str(self.ldap_filter or "").strip()
        if not filt:
            print_error("ldap_filter is required")
            return {"error": "missing_filter"}
        attrs_raw = str(self.attributes or "").strip()
        if attrs_raw:
            attrs = [a.strip() for a in attrs_raw.split(",") if a.strip()]
        else:
            attrs = [
                "sAMAccountName",
                "cn",
                "description",
                "distinguishedName",
                "memberOf",
                "userAccountControl",
                "adminCount",
                "objectSid",
                "pwdLastSet",
                "lastLogon",
                "servicePrincipalName",
            ]
        entries = self.search(filt, attrs, size_limit=int(self.size_limit or 50)) or []
        print_success(f"{len(entries)} object(s) for filter {filt}")
        results = []
        for entry in entries:
            dn = getattr(entry, "entry_dn", "") or self.attr_str(entry, "distinguishedName")
            print_info(f"Object: {dn}")
            row = {"dn": dn, "attributes": {}}
            for name in attrs:
                vals = self.attr_list(entry, name)
                if not vals:
                    continue
                display = ", ".join(str(v) for v in vals[:20])
                print_info(f"  {name}: {display[:200]}")
                row["attributes"][name] = [str(v) for v in vals]
            results.append(row)
        return {"filter": filt, "count": len(results), "objects": results}
