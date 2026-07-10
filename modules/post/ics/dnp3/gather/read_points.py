#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import GRP_ANALOG_INPUT, GRP_BINARY_INPUT, read_dnp3_points
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "DNP3 read points",
        "description": (
            "Reads DNP3 binary or analog input points via application-layer READ requests "
            "and prints any ASCII metadata found in responses."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "gather", "read"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
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

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False

        group, variation = self._object_spec()
        start = int(self.start_index or 0)
        stop = start + max(0, int(self.count or 10) - 1)

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

        if not result.success:
            print_error(result.error or "DNP3 read failed")
            return False

        print_success(f"DNP3 read succeeded ({result.response_len} bytes)")
        for label in result.strings[:12]:
            print_info(f"  {label}")

        self.sync_workspace_ics(
            port=self._port(),
            protocol="dnp3",
            device_type="RTU/IED",
            purdue_level=1,
            source="post/ics/dnp3/gather/read_points",
        )
        return True
