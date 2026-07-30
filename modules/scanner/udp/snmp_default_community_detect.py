#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SNMP agents accepting default community strings."""

from kittysploit import *


DEFAULT_COMMUNITIES = (
    "public",
    "private",
    "community",
    "snmp",
    "snmpd",
    "cisco",
    "admin",
    "manager",
)


class Module(Scanner):
    __info__ = {
        "name": "SNMP Default Community",
        "description": (
            "Probes SNMP v1/v2c agents for common default community strings "
            "(e.g. public/private) via sysDescr."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc1157",
        ],
        "tags": ["snmp", "udp", "network", "scanner", "default-login", "misconfig", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.4,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "unauth_read", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    target = OptString("", "Target hostname or IP", required=True)
    port = OptPort(161, "SNMP UDP port", required=True)
    timeout = OptPort(3, "SNMP timeout in seconds", required=False, advanced=True)

    def run(self):
        host = str(self.target or "").strip()
        if not host:
            return False

        try:
            from lib.protocols.snmp.snmp_client import SNMPClient
        except Exception:
            return False

        accepted = []
        sysdescr = ""
        for community in DEFAULT_COMMUNITIES:
            try:
                client = SNMPClient(
                    host=host,
                    port=int(self.port or 161),
                    community=community,
                    version=SNMPClient.V2C,
                    timeout=int(self.timeout or 3),
                    retries=0,
                )
                description = client.get(SNMPClient.OIDS["system_description"])
            except Exception:
                continue
            if not description:
                continue
            accepted.append(community)
            if not sysdescr:
                sysdescr = str(description)[:240]
            # Keep scanning a couple more for evidence richness, but stop early
            if len(accepted) >= 2:
                break

        if not accepted:
            return False

        severity = "critical" if "private" in accepted else "high"
        self.report_finding(
            "SNMP default community accepted",
            severity=severity,
            evidence={
                "host": host,
                "port": int(self.port or 161),
                "communities": accepted,
                "sysdescr": sysdescr,
            },
            impact={
                "summary": "SNMP communities allow remote inventory and often configuration disclosure.",
                "business_risk": "Network reconnaissance / potential device reconfiguration",
            },
            remediation={
                "summary": "Disable SNMPv1/v2c or replace default communities with strong credentials.",
                "actions": [
                    "Remove public/private default communities",
                    "Prefer SNMPv3 with authPriv",
                    "Restrict SNMP to management networks / ACLs",
                ],
            },
        )
        return True
