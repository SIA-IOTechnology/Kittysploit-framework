#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect IEC 61850 MMS servers on ISO-on-TCP port 102."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec61850_client import probe_iec61850_mms


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "IEC 61850 MMS Identify",
        "description": (
            "Probe TCP/102 for IEC 61850 MMS (COTP + initiate) and distinguish "
            "from Siemens S7comm on the same port."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ics", "iec61850", "mms", "substation", "scada", "enumeration"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "ISO-on-TCP port (default 102)", True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return {"error": "missing_target"}
        if not self.is_tcp_open():
            print_error(f"TCP {self._port()} closed")
            return {"error": "port_closed"}

        result = probe_iec61850_mms(host, self._port(), timeout=self._timeout())
        data = result.to_dict()

        if result.s7_conflict:
            print_info(result.error)
            return data
        if result.detected:
            print_warning(f"IEC 61850 MMS candidate on {host}:{self._port()}")
            if result.mms_initiate_ok:
                print_success("MMS initiate response observed")
            elif result.cotp_accepted:
                print_info("MMS COTP accepted; initiate response inconclusive")
        else:
            print_info(result.error or "No IEC 61850 MMS signal detected")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
