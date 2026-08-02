#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import GRP_ANALOG_INPUT, GRP_BINARY_INPUT, read_dnp3_points
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import Dnp3SessionMixin


class Module(Post, Ics_scanner_client, Dnp3SessionMixin):
    __info__ = {
        "name": "DNP3 read points",
        "description": (
            "Reads DNP3 binary or analog input points via application-layer READ requests "
            "and prints any ASCII metadata found in responses (session preferred)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "gather", "read"],
        "session_type": [SessionType.DNP3, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {"capabilities_any": ["ot_assets", "dnp3_access"]},
            "chain": {
                "produces_capabilities": [
                    {"capability": "dnp3_access", "from_detail": ""},
                    {"capability": "ot_assets", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/ics/dnp3/gather/integrity_dump",
                    "post/ics/dnp3/manage/operate_crob",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    object_type = OptChoice(
        "binary_input",
        "DNP3 object type to read",
        True,
        choices=["binary_input", "analog_input", "device_attributes"],
    )
    start_index = OptInteger(0, "First point index", False)
    count = OptInteger(10, "Number of points to read", False)
    src_address = OptInteger(1024, "DNP3 master source link address", False, advanced=True)
    dest_address = OptInteger(1, "DNP3 outstation destination link address", False, advanced=True)

    def _object_spec(self) -> tuple[int, int]:
        choice = str(self.object_type or "binary_input").strip().lower()
        if choice == "analog_input":
            return GRP_ANALOG_INPUT, 0x01
        if choice == "device_attributes":
            return 0x3C, 0x01
        return GRP_BINARY_INPUT, 0x01

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        group, variation = self._object_spec()
        start = int(self.start_index or 0)
        stop = start + max(0, int(self.count or 10) - 1)

        try:
            client = self.open_dnp3()
            if int(self.dest_address or 0):
                client.dest = int(self.dest_address)
            if int(self.src_address or 0):
                client.src = int(self.src_address)
            print_status(
                f"Reading DNP3 group {group} var {variation} "
                f"index {start}-{stop} on {client.host}:{client.port}..."
            )
            result = client.read_points(group, variation, start, stop)
            host = client.host
            port = client.port
        except Exception:
            host = self._host()
            if not host:
                print_error("DNP3 session or target is required")
                return False
            print_status(
                f"Reading DNP3 group {group} var {variation} "
                f"index {start}-{stop} on {host}:{self._port()}..."
            )
            result = read_dnp3_points(
                host,
                self._port(),
                self._timeout(),
                group,
                variation,
                start,
                stop,
                int(self.src_address or 1024),
                int(self.dest_address or 1),
            )
            port = self._port()

        if not result.success:
            print_error(result.error or "DNP3 read failed")
            return False

        print_success(f"DNP3 read succeeded ({result.response_len} bytes)")
        for label in result.strings[:12]:
            print_info(f"  {label}")

        self.sync_workspace_ics(
            port=port,
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="post/ics/dnp3/gather/read_points",
        )
        return True
