#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import integrity_poll_dnp3
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import Dnp3SessionMixin


class Module(Post, Ics_scanner_client, Dnp3SessionMixin):
    __info__ = {
        "name": "DNP3 integrity dump",
        "description": "Integrity poll (class 0–3) plus binary/analog sample counts (session preferred)",
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "gather"],
        "session_type": [SessionType.DNP3, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.1,
            "requires": {"capabilities_any": ["ot_assets", "dnp3_access"]},
            "chain": {
                "produces_capabilities": [
                    {"capability": "dnp3_access", "from_detail": ""},
                    {"capability": "ot_assets", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/ics/dnp3/gather/read_points",
                    "post/ics/dnp3/manage/operate_crob",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    src_address = OptInteger(1024, "Master source link address", False, advanced=True)
    dest_address = OptInteger(1, "Outstation destination link address", False, advanced=True)
    binary_count = OptInteger(8, "Binary input sample count", False)
    analog_count = OptInteger(8, "Analog input sample count", False)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        try:
            client = self.open_dnp3()
            info = self.get_dnp3_connection_info()
            if int(self.dest_address or 0):
                client.dest = int(self.dest_address)
            if int(self.src_address or 0):
                client.src = int(self.src_address)
            result = client.integrity_poll(
                binary_count=int(self.binary_count or 8),
                analog_count=int(self.analog_count or 8),
            )
            host = info.get("host") or client.host
        except Exception:
            host = self._host()
            if not host:
                print_error("DNP3 session or target is required")
                return False
            result = integrity_poll_dnp3(
                host,
                self._port(),
                self._timeout(),
                int(self.src_address or 1024),
                int(self.dest_address or 1),
                int(self.binary_count or 8),
                int(self.analog_count or 8),
            )

        if result.error and not result.connected:
            print_error(result.error)
            return False
        classes = result.class_results or {}
        points = result.points or {}
        print_success(f"Integrity poll on {host}:{result.port}")
        print_info(f"  classes={classes}")
        print_info(f"  points={points}")
        if result.error:
            print_warning(result.error)
        self.sync_workspace_ics(
            port=result.port,
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="post/ics/dnp3/gather/integrity_dump",
        )
        return True
