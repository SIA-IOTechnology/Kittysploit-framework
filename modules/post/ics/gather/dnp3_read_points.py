#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNP3 read points — analog/binary input enumeration.

Solidifies the DNP3 client read_points path for post-recon data collection
on identified outstations (group 1 binary input, group 30 analog input).
"""

from __future__ import annotations

from typing import Any, Dict, List

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import Dnp3Client, GRP_ANALOG_INPUT, GRP_BINARY_INPUT
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 read points (legacy path)",
        "description": (
            "Read binary and analog input points from a DNP3 outstation using "
            "group 1 and group 30 object reads. Requires prior dnp3_identify."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "read", "gather", "ot"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints"],
            "chain": {
                "consumes_capabilities": ["dnp3_access"],
                "produces_capabilities": ["file_read"],
                "option_bindings": {
                    "dest_address": "dnp3_dest",
                },
                "suggested_followups": [
                    "scanner/ics/dnp3_write_enabled",
                    "auxiliary/scanner/ics/dnp3_integrity_poll",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    src_address = OptInteger(1024, "DNP3 master source link address", False, advanced=True)
    dest_address = OptInteger(1, "DNP3 outstation destination link address", False, advanced=True)
    binary_start = OptInteger(0, "Binary input start index", False)
    binary_stop = OptInteger(15, "Binary input stop index", False)
    analog_start = OptInteger(0, "Analog input start index", False)
    analog_stop = OptInteger(7, "Analog input stop index", False)

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        port = self._port()
        src = int(self.src_address or 1024)
        dest = int(self.dest_address or 1)
        timeout = self._timeout()

        print_status(f"DNP3 read_points on {host}:{port} dest={dest}")
        client = Dnp3Client(host, port, timeout, src=src, dest=dest)

        readings: List[Dict[str, Any]] = []
        for label, group, variation, start, stop in (
            ("binary_input", GRP_BINARY_INPUT, 1, int(self.binary_start), int(self.binary_stop)),
            ("analog_input", GRP_ANALOG_INPUT, 1, int(self.analog_start), int(self.analog_stop)),
        ):
            result = client.read_points(group, variation, start, stop)
            ok = bool(result.success)
            print_info(f"  {label} [{start}-{stop}]: {'OK' if ok else 'FAIL'} len={result.response_len}")
            if result.strings:
                for s in result.strings[:6]:
                    print_info(f"    {s}")
            readings.append({
                "group": label,
                "success": ok,
                "response_len": result.response_len,
                "strings": result.strings[:12],
                "raw_hex": (result.raw_hex or "")[:256],
            })

        any_ok = any(r.get("success") for r in readings)
        if not any_ok:
            print_warning("No DNP3 point reads succeeded")
            return False

        print_success(f"DNP3 read_points completed on {host}:{port}")
        self.sync_workspace_ics(
            port=port,
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="post/ics/gather/dnp3_read_points",
        )
        self.vulnerability_info = {
            "host": host,
            "port": port,
            "protocol": "dnp3",
            "dnp3_dest": str(dest),
            "readings": readings,
        }
        return True
