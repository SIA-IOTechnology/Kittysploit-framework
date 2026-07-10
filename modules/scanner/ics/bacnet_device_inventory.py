#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only BACnet device inventory via Who-Is and ReadProperty."""

from kittysploit import *
from lib.protocols.ics.bacnet_client import object_inventory, who_is
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "BACnet Device Inventory",
        "description": (
            "Discover BACnet/IP devices and perform read-only object inventory "
            "requests via ReadProperty."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["ics", "bacnet", "bms", "scanner", "inventory"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(0, "BACnet device instance (0 = auto-discover)", required=False)
    max_devices = OptInteger(5, "Maximum discovered devices to inventory", required=False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False

        device_id = int(self.device_id or 0)
        targets = []
        if device_id > 0:
            targets.append((host, device_id))
        else:
            devices = who_is(host, self._port(), self._timeout())
            if not devices:
                print_warning("No BACnet I-Am responses received")
                return False
            for device in devices[: int(self.max_devices or 5)]:
                if device.device_id is not None:
                    targets.append((device.host, int(device.device_id)))
                    print_info(
                        f"Discovered device_id={device.device_id} vendor_id={device.vendor_id} "
                        f"on {device.host}:{device.port}"
                    )

        inventoried = 0
        for target_host, dev_id in targets:
            inventory = object_inventory(target_host, dev_id, self._port(), self._timeout())
            if not inventory:
                print_warning(f"No inventory parsed for device {dev_id} on {target_host}")
                continue
            for item in inventory:
                print_success(
                    f"Inventory device {item.get('device_id')} on {item.get('host')} — "
                    f"response {len(item.get('raw_hex', '')) // 2} bytes"
                )
                inventoried += 1

        if inventoried == 0:
            return False
        self.set_info(
            severity="medium",
            reason=f"BACnet inventory collected for {inventoried} device(s)",
        )
        return True
