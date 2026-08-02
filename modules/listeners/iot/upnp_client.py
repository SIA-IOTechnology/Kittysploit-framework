#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""UPnP bind listener — SSDP discover + device description session."""

from kittysploit import *
from lib.protocols.upnp.client import SSDP_PORT, UpnpClient


class Module(Listener):
    __info__ = {
        "name": "UPnP / SSDP Client",
        "description": (
            "Discovers a UPnP device via SSDP M-SEARCH, fetches the device "
            "description, and opens an interactive UPnP shell (IGD actions)."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.UPNP,
        "protocol": "upnp",
        "tags": ["iot", "upnp", "ssdp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["upnp_access", "ot_assets"],
                "suggested_followups": [
                    "post/upnp/gather/device_inventory",
                    "post/upnp/gather/igd_portmap",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Target host for unicast SSDP", True)
    rport = OptPort(SSDP_PORT, "SSDP UDP port", True)
    location = OptString("", "Optional device description URL (skip SSDP)", False)

    def run(self):
        host = str(self.rhost).strip()
        port = int(self.rport or SSDP_PORT)
        timeout = float(self.timeout or 5)
        location = str(self.location or "").strip()

        print_status(f"UPnP discover on {host}:{port}...")
        client = UpnpClient(host, port, timeout, location=location)
        if not client.connect(location=location):
            print_error(client.last_error or "UPnP discovery/description failed")
            return False

        device = client.root_device
        print_success(f"LOCATION: {client.location}")
        if device:
            print_info(
                f"  {device.friendly_name or '?'} | {device.manufacturer or '?'} "
                f"{device.model_name or '?'} ({device.device_type or '?'})"
            )
            print_info(f"  services: {len(client.list_services())}")
            wan = client.find_wan_service()
            if wan:
                print_success(f"WAN service: {wan.service_type}")

        additional_data = {
            "host": host,
            "port": port,
            "location": client.location,
            "server": client.server,
            "st": client.st,
            "usn": client.usn,
            "protocol": "upnp",
            "platform": "iot",
            "timeout": timeout,
            "device": device.to_dict() if device else {},
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
