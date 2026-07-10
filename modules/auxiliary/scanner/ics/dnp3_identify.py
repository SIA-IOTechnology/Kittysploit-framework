#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import identify_dnp3
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 outstation identify",
        "description": (
            "Identifies a DNP3 outstation on TCP/20000 via link-layer status and "
            "device attributes (group 60) read."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "identify", "outstation"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "dnp3_access", "from_detail": "protocol"},
                    {"capability": "dnp3_dest", "from_detail": "dest_address"},
                ],
                "suggested_followups": [
                    "post/ics/gather/dnp3_read_points",
                    "auxiliary/scanner/ics/dnp3_integrity_poll",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    src_address = OptInteger(1024, "DNP3 master source link address", False, advanced=True)
    dest_address = OptInteger(1, "DNP3 outstation destination link address", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_status(f"Identifying DNP3 outstation {host}:{self._port()}...")
        result = identify_dnp3(
            host,
            self._port(),
            self._timeout(),
            int(self.src_address or 1024),
            int(self.dest_address or 1),
        )

        if not result.connected:
            print_error(result.error or "Connection failed")
            return False

        print_success(f"DNP3 TCP reachable on {host}:{self._port()}")
        print_info(f"  Link alive: {result.link_alive}")
        print_info(f"  Device attributes: {result.device_attributes}")

        for label in result.strings[:8]:
            print_info(f"  Attribute: {label}")

        self.sync_workspace_ics(
            port=self._port(),
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="auxiliary/scanner/ics/dnp3_identify",
        )
        self.vulnerability_info = {
            "protocol": "dnp3",
            "host": host,
            "port": self._port(),
            "dest_address": str(int(self.dest_address or 1)),
        }
        return bool(result.link_alive or result.device_attributes)
