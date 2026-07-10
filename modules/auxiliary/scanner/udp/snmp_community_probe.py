#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe SNMP communities and enumerate basic system information."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.snmp.snmp_client import SNMPClient


DEFAULT_COMMUNITIES = [
    "public",
    "private",
    "community",
    "manager",
    "cisco",
    "admin",
    "default",
]


class Module(Auxiliary):
    __info__ = {
        "name": "SNMP Community Probe",
        "description": "Tests common SNMP v1/v2c communities and collects basic system information.",
        "author": ["KittySploit Team"],
        "tags": ["auxiliary", "scanner", "udp", "snmp", "enum", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "Target hostname or IP", required=True)
    port = OptPort(161, "SNMP UDP port", required=True)
    communities = OptString(
        "public,private,community,manager,cisco,admin,default",
        "Comma-separated community strings to test",
        required=False,
    )
    version = OptChoice("2", "SNMP version", required=True, choices=["1", "2"])
    timeout = OptPort(5, "SNMP timeout in seconds", required=False, advanced=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _community_list(self):
        raw = str(self.communities or "").strip()
        if not raw:
            return list(DEFAULT_COMMUNITIES)
        values = [item.strip() for item in raw.split(",") if item.strip()]
        return values or list(DEFAULT_COMMUNITIES)

    def _snmp_version(self):
        return SNMPClient.V1 if str(self.version) == "1" else SNMPClient.V2C

    def run(self):
        host = str(self.target or "").strip()
        if not host:
            print_error("Target is required")
            return {"error": "missing_target"}

        port = int(self.port or 161)
        communities = self._community_list()
        print_info(f"Probing SNMP communities on {host}:{port}")

        client = SNMPClient(
            host=host,
            port=port,
            community="public",
            version=self._snmp_version(),
            timeout=int(self.timeout or 5),
        )
        valid = client.enumerate_communities(communities)
        data = {
            "target": host,
            "port": port,
            "valid_communities": valid,
            "systems": [],
        }

        if not valid:
            print_info("No valid SNMP community found")
            if self.output_file:
                self._save_output(data)
            return data

        print_warning(f"Valid SNMP communities: {', '.join(valid)}")
        for community in valid[:3]:
            client.community = community
            system = client.get_system_info()
            entry = {"community": community, "system": system}
            data["systems"].append(entry)
            name = system.get("system_name") or system.get("system_description") or "unknown"
            print_success(f"[{community}] {name}")

        if self.output_file:
            self._save_output(data)
        return data

    def _save_output(self, data):
        try:
            with open(str(self.output_file), "w") as fp:
                json.dump(data, fp, indent=2)
            print_success(f"Results saved to {self.output_file}")
        except Exception as exc:
            print_error(f"Failed to save output: {exc}")
