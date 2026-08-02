#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter device inventory dump (JSON) via session or target."""

from kittysploit import *
from lib.protocols.matter.client import MATTER_UDP_PORT, MatterClient, discover_matter
from lib.protocols.matter.session import MatterSessionMixin
import json
import os
import time


class Module(Post, MatterSessionMixin):
    __info__ = {
        "name": "Matter device inventory",
        "description": (
            "Full Matter node inventory from DNS-SD TXT (vendor/product, device type, "
            "commissioning window, discriminator) with optional JSON export."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.MATTER, SessionType.SHELL],
        "tags": ["iot", "matter", "chip", "mdns", "gather", "inventory"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["matter_access", "ot_assets"],
                "suggested_followups": [
                    "post/matter/gather/discover",
                    "listeners/iot/matter_client",
                ],
            },
            "requires": {"capabilities_any": ["matter_access", "ot_assets"]},
        },
    }

    session_id = OptString("", "Matter session ID", False)
    rhost = OptString("", "Target host when not using a session", False)
    rport = OptPort(MATTER_UDP_PORT, "Matter UDP port", False)
    multicast = OptBool(False, "Multicast mDNS browse", False)
    probe_udp = OptBool(True, "Probe UDP/5540 on addresses", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip() or bool(self.multicast):
            return True
        print_error("Matter session_id, rhost, or multicast=true is required")
        return False

    def run(self):
        if not self.check():
            return False

        inventory = None
        try:
            client = self.open_matter(connect=True)
            if bool(self.probe_udp) and client.devices:
                client.discover(probe_udp=True)
            inventory = client.inventory()
        except Exception:
            host = str(self.rhost or self._opt_value("target") or "").strip()
            if not host and not bool(self.multicast):
                print_error("Matter session or target is required")
                return False
            result = discover_matter(
                host=host,
                timeout=float(self.timeout or 3),
                multicast=bool(self.multicast) or not host,
                probe_udp=bool(self.probe_udp),
            )
            client = MatterClient(
                host=host,
                port=int(self.rport or MATTER_UDP_PORT),
                timeout=float(self.timeout or 3),
                multicast=bool(self.multicast) or not host,
            )
            client.devices = list(result.devices)
            client.last_result = result
            inventory = client.inventory()

        devices = inventory.get("devices") or []
        if not devices:
            print_error(inventory.get("error") or "Empty Matter inventory")
            return False

        open_cm = [
            d
            for d in devices
            if d.get("commissioning_mode") in (1, 2)
        ]
        print_success(
            f"Matter inventory — {len(devices)} node(s), "
            f"open_commissioning={len(open_cm)}"
        )
        for device in devices:
            print_info(
                f"  {device.get('device_name') or device.get('instance')} | "
                f"vid={device.get('vendor_id')} ({device.get('vendor_name') or '-'}) | "
                f"type={device.get('device_type_name') or device.get('device_type')} | "
                f"cm={device.get('commissioning_mode_name') or '-'} | "
                f"disc={device.get('discriminator')} | "
                f"udp={device.get('udp_reachable')}"
            )
            if device.get("pairing_instruction"):
                print_info(f"    PI: {device.get('pairing_instruction')}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"matter_inventory_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(inventory, fh, indent=2)
            print_success(f"Saved {path}")

        return True
