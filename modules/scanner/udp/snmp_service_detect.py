#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SNMP service via public community sysDescr."""

from kittysploit import *


class Module(Scanner):
    __info__ = {
        "name": "SNMP Service Detection",
        "description": "Detects SNMP agents responding to the public community sysDescr OID.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "snmp", "vendor": "ietf"},
        "tags": ["snmp", "udp", "network", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "Target hostname or IP", required=True)
    port = OptPort(161, "SNMP UDP port", required=True)
    community = OptString("public", "SNMP community to probe", required=False)
    timeout = OptPort(5, "SNMP timeout in seconds", required=False, advanced=True)

    def run(self):
        host = str(self.target or "").strip()
        if not host:
            print_error("Target is required")
            return False

        try:
            from lib.protocols.snmp.snmp_client import SNMPClient
        except Exception as exc:
            print_info(f"SNMP dependencies unavailable: {exc}")
            return False

        try:
            client = SNMPClient(
                host=host,
                port=int(self.port or 161),
                community=str(self.community or "public"),
                version=SNMPClient.V2C,
                timeout=int(self.timeout or 5),
            )
            description = client.get(SNMPClient.OIDS["system_description"])
        except Exception as exc:
            print_info(f"SNMP probe failed: {exc}")
            return False

        if not description:
            return False

        self.set_info(
            severity="info",
            reason="SNMP agent responded to sysDescr",
            sysdescr=str(description)[:200],
            community=str(self.community or "public"),
        )
        return True
