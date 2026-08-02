#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import read_property
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import BacnetSessionMixin


class Module(Post, Ics_scanner_client, BacnetSessionMixin):
    __info__ = {
        "name": "BACnet read property",
        "description": "ReadProperty against a BACnet object (session preferred)",
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "gather", "read"],
        "session_type": [SessionType.BACNET, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {"capabilities_any": ["ot_assets", "bacnet"]},
            "chain": {
                "produces_capabilities": [
                    {"capability": "bacnet", "from_detail": ""},
                    {"capability": "ot_assets", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/ics/bacnet/gather/object_inventory",
                    "post/ics/bacnet/manage/write_property",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(0, "Device instance (0 = session default)", False)
    object_type = OptInteger(2, "Object type (2=AV, 0=AI, 1=AO, 3=BI, 4=BO)", True)
    object_instance = OptInteger(1, "Object instance", True)
    property_id = OptInteger(85, "Property id (85=present-value)", True)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        try:
            client = self.open_bacnet()
            did = int(self.device_id or 0) or int(client.device_id or 0)
            if did <= 0:
                print_error("device_id required (set option or discover via Who-Is)")
                return False
            raw = client.read_prop(
                int(self.object_type),
                int(self.object_instance),
                int(self.property_id),
                device_id=did,
            )
            host = client.host
        except Exception:
            host = self._host()
            if not host:
                print_error("BACnet session or target is required")
                return False
            did = int(self.device_id or 0)
            if did <= 0:
                print_error("device_id is required without a session")
                return False
            raw = read_property(
                host,
                did,
                int(self.object_type),
                int(self.object_instance),
                int(self.property_id),
                self._port(),
                self._timeout(),
            )

        if not raw:
            print_error("No ReadProperty response")
            return False
        print_success(
            f"ReadProperty ok host={host} dev={did} "
            f"obj={self.object_type}:{self.object_instance} prop={self.property_id}"
        )
        print_info(f"  {len(raw)} bytes: {raw.hex()}")
        return True
