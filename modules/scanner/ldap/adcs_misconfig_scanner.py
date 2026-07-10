#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect vulnerable AD CS certificate templates and enrollment services."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client, LDAP3_AVAILABLE
from lib.protocols.ldap.adcs_helpers import analyze_certificate_template, analyze_enrollment_service


class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD CS Misconfiguration Scanner",
        "description": "Detects ESC-style AD CS template and enrollment service misconfigurations via LDAP.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["ad", "ldap", "adcs", "certificate", "esc", "scanner"],
        "references": [
            "https://github.com/ly4k/Certipy",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "chain": {
                "produces_capabilities": ["adcs_misconfig"],
                "suggested_followups": ["post/ldap/gather/adcs_templates"],
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

        findings = []
        templates = self.search(
            "(objectClass=pKICertificateTemplate)",
            [
                "cn",
                "name",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-RA-Signature",
            ],
            base=self.config_dn,
        )
        for template in templates:
            findings.extend(
                analyze_certificate_template(
                    template,
                    self.attr_int,
                    self.attr_list,
                    self.attr_str,
                )
            )

        services = self.search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "flags"],
            base=self.config_dn,
        )
        for service in services:
            findings.extend(
                analyze_enrollment_service(service, self.attr_int, self.attr_str)
            )

        if not findings:
            print_info("No AD CS misconfiguration hints found")
            return False

        high = [f for f in findings if f.get("severity") == "high"]
        reason = f"{len(findings)} AD CS finding(s)"
        if high:
            reason += f" — high: {', '.join(f['esc'] + ':' + f.get('template', f.get('service', '')) for f in high[:5])}"
        self.set_info(severity="high" if high else "medium", reason=reason, findings=findings[:30])
        for item in findings[:10]:
            print_warning(f"[{item.get('esc')}] {item.get('description')} ({item.get('template') or item.get('service')})")
        return True
