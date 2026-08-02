#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BACnet/IP bind listener — opens a BACnet session for interactive device access."""

from kittysploit import *
from lib.protocols.ics.bacnet_client import BacnetClient
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS


class Module(Listener):
    __info__ = {
        "name": "BACnet/IP Client",
        "description": "Discovers a BACnet/IP device (Who-Is) and creates an interactive BACnet shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.BACNET,
        "protocol": "bacnet",
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["ot_assets", "bacnet"],
                "suggested_followups": [
                    "post/ics/bacnet/gather/object_inventory",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target BACnet/IP host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["bacnet"], "BACnet/IP UDP port", True)
    device_id = OptInteger(0, "BACnet device instance (0 = auto from Who-Is)", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport)
        device_id = int(self.device_id or 0)
        timeout = float(self.timeout or 5)

        print_status(f"Discovering BACnet/IP on {host}:{port}...")
        client = BacnetClient(host, port, timeout, device_id)
        if not client.connect():
            print_error(f"No BACnet I-Am responses from {host}:{port}")
            return False

        print_success(
            f"BACnet session ready — device_id={client.device_id} "
            f"({len(client.devices)} I-Am response(s))"
        )
        for device in client.devices[:8]:
            print_info(
                f"  device_id={device.device_id} vendor={device.vendor_id} "
                f"from {device.host}:{device.port}"
            )

        additional_data = {
            "host": host,
            "port": port,
            "device_id": client.device_id,
            "devices": [
                {
                    "host": d.host,
                    "port": d.port,
                    "device_id": d.device_id,
                    "vendor_id": d.vendor_id,
                }
                for d in client.devices
            ],
            "protocol": "bacnet",
            "platform": "ics",
            "timeout": timeout,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
