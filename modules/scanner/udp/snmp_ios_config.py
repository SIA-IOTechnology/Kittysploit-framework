#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco IOS SNMP config/info (NSE snmp-ios-config inspired, read-only)."""

from kittysploit import *
from lib.scanner.snmp.detectors import probe_snmp_ios_config


class Module(Scanner):
    __info__ = {
        "name": "SNMP Cisco IOS Config Hints",
        "description": (
            "Fingerprints Cisco IOS via SNMP and checks for config-copy MIB / image strings "
            "(read-only subset of NSE snmp-ios-config; does not push config to TFTP)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/snmp-ios-config.html"],
        "tags": ["snmp", "cisco", "ios", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "Target hostname or IP", True)
    port = OptPort(161, "SNMP UDP port", True)
    community = OptString("public", "SNMP community", False)
    timeout = OptPort(5, "Timeout seconds", False, advanced=True)

    def run(self):
        host = str(self.target or "").strip()
        if not host:
            return False
        info = probe_snmp_ios_config(
            host=host,
            community=str(self.community or "public"),
            port=int(self.port or 161),
            timeout=float(self.timeout or 5),
        )
        if not info.get("detected") or not info.get("cisco"):
            return False
        severity = "medium" if info.get("config_copy_mib") else "info"
        self.set_info(
            severity=severity,
            reason="Cisco IOS SNMP identity collected",
            sysdescr=str(info.get("sysdescr") or "")[:200],
            sysname=str(info.get("sysname") or ""),
            ios_image=str(info.get("ios_image") or ""),
            config_copy_mib=bool(info.get("config_copy_mib")),
            running_last_changed=str(info.get("running_last_changed") or ""),
        )
        return True
