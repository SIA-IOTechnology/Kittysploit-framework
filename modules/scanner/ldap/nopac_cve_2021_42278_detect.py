#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect noPac (CVE-2021-42278/42287) prerequisite conditions."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client, LDAP3_AVAILABLE


class Module(Scanner, Ad_client):
    __info__ = {
        "name": "noPac CVE-2021-42278/42287 Detect",
        "description": (
            "Detects prerequisites for the noPac SamAccountName spoofing chain: "
            "authenticated LDAP access, ms-DS-MachineAccountQuota > 0, and at least "
            "one domain controller computer object. Does not verify patch level."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2021-42278", "CVE-2021-42287"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42278",
            "https://github.com/Ridter/noPac",
        ],
        "tags": ["ad", "ldap", "scanner", "nopac", "kerberos", "kev"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "chain": {
                "suggested_followups": [
                    "exploits/windows/ldap/nopac_cve_2021_42278_42287_escalate",
                ],
            },
        },
    }

    dc_name = OptString("", "Expected DC NetBIOS name (optional filter)", required=False)

    def run(self):
        if not LDAP3_AVAILABLE:
            print_error("ldap3 not installed")
            return False
        if not self.conn:
            print_error("LDAP bind failed")
            return False

        domain_obj = self.get_domain_object()
        maq = self.attr_int(domain_obj, "ms-DS-MachineAccountQuota", 0) if domain_obj else 0
        if maq <= 0:
            print_info("ms-DS-MachineAccountQuota is 0 — noPac not viable for this principal")
            return False

        name_filter = str(self.dc_name or "").strip().rstrip("$")
        dcs = self.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName", "dNSHostName"],
            base=self.base_dn,
        )
        if not dcs:
            print_info("No domain controller computer objects found")
            return False

        target = dcs[0]
        if name_filter:
            matched = [
                dc for dc in dcs
                if self.attr_str(dc, "sAMAccountName").rstrip("$").lower() == name_filter.lower()
            ]
            if not matched:
                print_info(f"No DC matching name {name_filter}")
                return False
            target = matched[0]

        sam = self.attr_str(target, "sAMAccountName")
        fqdn = self.attr_str(target, "dNSHostName") or sam
        self.set_info(
            severity="high",
            cve="CVE-2021-42278",
            reason=(
                f"noPac prerequisites met (MAQ={maq}, DC={sam}, fqdn={fqdn}). "
                "Patch KB5008380/KB5008602 status not verified."
            ),
        )
        print_warning(f"noPac may be viable — MAQ={maq}, target DC {sam}")
        return True
