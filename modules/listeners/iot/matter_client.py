#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter bind listener — DNS-SD discovery session for Matter / CHIP nodes."""

from kittysploit import *
from lib.protocols.matter.client import MATTER_UDP_PORT, MatterClient


class Module(Listener):
    __info__ = {
        "name": "Matter Client",
        "description": (
            "Discovers Matter/CHIP nodes via mDNS (_matterc._udp / _matter._tcp), "
            "parses commissionable/operational TXT, optionally probes UDP/5540, "
            "and opens an interactive Matter shell session."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.MATTER,
        "protocol": "matter",
        "tags": ["iot", "matter", "chip", "thread", "mdns", "smart-home"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["matter_access", "ot_assets"],
                "suggested_followups": [
                    "post/matter/gather/discover",
                    "post/matter/gather/device_inventory",
                ],
            },
        },
    }

    rhost = OptString("", "Target host (empty + multicast for LAN browse)", False)
    rport = OptPort(MATTER_UDP_PORT, "Matter UDP port for reachability probe", True)
    multicast = OptBool(True, "Browse multicast mDNS 224.0.0.251", False)
    probe_udp = OptBool(True, "Probe UDP/5540 on discovered addresses", False)

    def run(self):
        host = str(self.rhost or "").strip()
        port = int(self.rport or MATTER_UDP_PORT)
        timeout = float(self.timeout or 3)
        multicast = bool(self.multicast) or not host

        print_status(
            f"Matter discovery host={host or '*'} multicast={multicast} "
            f"udp_probe={bool(self.probe_udp)}..."
        )
        client = MatterClient(host=host, port=port, timeout=timeout, multicast=multicast)
        result = client.discover(probe_udp=bool(self.probe_udp))
        client.devices = list(result.devices)
        client.last_result = result
        client.connected = bool(result.devices)

        if not result.devices:
            # Soft-fail to host UDP probe when mDNS quiet
            if host and bool(self.probe_udp):
                if client.connect():
                    print_warning("No mDNS Matter records; UDP/5540 probe bound session")
                else:
                    print_error(client.last_error or "No Matter nodes discovered")
                    return False
            else:
                print_error(result.error or "No Matter nodes discovered")
                return False

        print_success(f"Discovered {len(client.devices)} Matter node(s)")
        for device in client.devices[:12]:
            kind = "commissionable" if device.commissionable else "operational"
            label = device.device_name or device.instance or device.host
            print_info(
                f"  [{kind}] {label} "
                f"vid={device.vendor_id or '-'} "
                f"type={device.device_type_name or device.device_type or '-'} "
                f"cm={device.commissioning_mode_name or device.commissioning_mode or '-'}"
            )

        additional_data = {
            "host": host,
            "port": port,
            "protocol": "matter",
            "platform": "iot",
            "multicast": multicast,
            "timeout": timeout,
            "device_count": len(client.devices),
            "devices": [d.to_dict() for d in client.devices],
        }
        return (client, host or "multicast", port, additional_data)

    def shutdown(self):
        return True
