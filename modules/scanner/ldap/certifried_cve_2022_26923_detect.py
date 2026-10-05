#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Certifried (CVE-2022-26923) prerequisite conditions."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client, LDAP3_AVAILABLE


class Module(Scanner, Ad_client):
    __info__ = {
        "name": "Certifried CVE-2022-26923 Detect",
        "description": (
            "Detects prerequisites for CVE-2022-26923 (Certifried): authenticated LDAP "
            "access, ms-DS-MachineAccountQuota > 0, AD CS enrollment service, and the "
            "Machine certificate template."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2022-26923"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-26923",
        ],
        "tags": ["ad", "ldap", "adcs", "scanner", "certifried", "kev"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/ldap/certifried_cve_2022_26923_escalate",
                    "scanner/ldap/adcs_misconfig_scanner",
                ],
            },
        },
    }

    def run(self):
        if not LDAP3_AVAILABLE:
            print_error("ldap3 not installed")
            return False
        if not self.conn:
            print_error("LDAP bind failed")
            return False
        if not self.config_dn:
            print_error("Could not determine configuration naming context")
            return False

        domain_obj = self.get_domain_object()
        maq = self.attr_int(domain_obj, "ms-DS-MachineAccountQuota", 0) if domain_obj else 0
        if maq <= 0:
            print_info("ms-DS-MachineAccountQuota is 0 — Certifried not viable for this principal")
            return False

        templates = self.search(
            "(&(objectClass=pKICertificateTemplate)(|(cn=Machine)(name=Machine)))",
            ["cn", "msPKI-Enrollment-Flag"],
            base=self.config_dn,
            size_limit=5,
        )
        services = self.search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName"],
            base=self.config_dn,
            size_limit=5,
        )
        if not templates:
            print_info("Machine certificate template not found")
            return False
        if not services:
            print_info("AD CS enrollment service not found")
            return False

        ca_host = self.attr_str(services[0], "dNSHostName") or self.attr_str(services[0], "cn")
        self.set_info(
            severity="high",
            cve="CVE-2022-26923",
            reason=(
                f"Certifried prerequisites met (MAQ={maq}, CA={ca_host}, "
                f"Machine template present). May be patched on DC (May 2022+)."
            ),
        )
        print_warning(f"Certifried may be viable — MAQ={maq}, CA {ca_host}")
        return True
