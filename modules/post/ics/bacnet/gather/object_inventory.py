#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import object_inventory, who_is
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import BacnetSessionMixin


class Module(Post, Ics_scanner_client, BacnetSessionMixin):
    __info__ = {
        "name": "BACnet object inventory",
        "description": "Discovers BACnet devices and requests object inventory via ReadProperty (session or direct)",
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "gather"],
        "session_type": [SessionType.BACNET, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "capabilities_any": ["ot_assets", "bacnet"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ot_assets", "from_detail": ""},
                    {"capability": "bacnet", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "suggested_followups": [
                    "post/ics/bacnet/gather/read_property",
                    "post/ics/bacnet/manage/write_property",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(0, "BACnet device instance (0 = auto from Who-Is / session)", False)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        # Prefer live BACnet session when available
        try:
            client = self.open_bacnet()
            device_id = int(self.device_id or 0) or int(client.device_id or 0)
            if device_id <= 0:
                devices = client.who_is()
                if not devices:
                    print_warning("No BACnet I-Am responses")
                    return False
                device_id = int(devices[0].device_id or 0)
            inventory = client.inventory(device_id)
            host = client.host
        except Exception:
            host = self._host()
            if not host:
                print_error("BACnet session or target is required")
                return False
            device_id = int(self.device_id or 0)
            if device_id <= 0:
                devices = who_is(host, self._port(), self._timeout())
                if not devices:
                    print_warning("No BACnet I-Am responses")
                    return False
                device_id = int(devices[0].device_id or 0)
                print_info(f"Using discovered device_id={device_id}")
            inventory = object_inventory(host, device_id, self._port(), self._timeout())

        if not inventory:
            print_warning("Object inventory request returned no parsed data")
            return False
        for item in inventory:
            print_success(
                f"Device {item.get('device_id')} on {item.get('host') or host} — "
                f"raw response {len(item.get('raw_hex', '')) // 2} bytes"
            )
        return True
