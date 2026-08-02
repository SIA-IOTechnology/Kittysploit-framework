#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter mDNS discovery via session or target."""

from kittysploit import *
from lib.protocols.matter.client import MATTER_UDP_PORT, discover_matter
from lib.protocols.matter.session import MatterSessionMixin


class Module(Post, MatterSessionMixin):
    __info__ = {
        "name": "Matter discover",
        "description": (
            "Browse Matter commissionable/operational DNS-SD records and summarize "
            "vendor, device type, and commissioning mode (session preferred)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.MATTER, SessionType.SHELL],
        "tags": ["iot", "matter", "chip", "mdns", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["matter_access", "ot_assets"],
                "suggested_followups": [
                    "post/matter/gather/device_inventory",
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
    probe_udp = OptBool(False, "Also probe UDP/5540", False)

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
        try:
            client = self.open_matter(connect=False)
            result = client.discover(probe_udp=bool(self.probe_udp))
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

        if not result.devices:
            print_error(result.error or "No Matter devices discovered")
            return False

        print_success(f"Matter discover — {len(result.devices)} node(s) mode={result.mode}")
        for device in result.devices:
            kind = "commissionable" if device.commissionable else "operational"
            print_info(
                f"  [{kind}] {device.device_name or device.instance or device.host} "
                f"vid={device.vendor_id or '-'} pid={device.product_id or '-'} "
                f"type={device.device_type_name or device.device_type or '-'} "
                f"cm={device.commissioning_mode_name or device.commissioning_mode or '-'}"
            )
        return True
