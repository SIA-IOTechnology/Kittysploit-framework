#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Matter / CHIP nodes via mDNS and optional UDP/5540 probe."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.matter.client import MATTER_UDP_PORT, discover_matter, probe_matter_udp
from lib.protocols.matter.session import MatterSessionMixin


class Module(Scanner, Ics_scanner_client, MatterSessionMixin):
    __info__ = {
        "name": "Matter / CHIP Detection",
        "description": (
            "Discovers Matter commissionable (_matterc._udp) and operational "
            "(_matter._tcp) nodes via mDNS, parses TXT (VP/DT/DN/CM), and can "
            "probe UDP/5540 reachability."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["matter", "chip", "thread", "mdns", "iot", "udp", "scanner", "smart-home"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "produces_capabilities": ["matter_access", "ot_assets"],
                "suggested_followups": [
                    "listeners/iot/matter_client",
                    "post/matter/gather/discover",
                    "post/matter/gather/device_inventory",
                    "scanner/udp/mdns_enum",
                ],
            },
        },
    }

    port = OptPort(MATTER_UDP_PORT, "Matter UDP port for reachability probe", True)
    multicast = OptBool(False, "Browse multicast mDNS (or when target empty)", False)
    probe_udp = OptBool(True, "Probe UDP/5540 on target / discovered addresses", False)

    def run(self):
        host = self._host()
        multicast = bool(self.multicast) or not host
        if not host and not multicast:
            return False

        result = discover_matter(
            host=host or "",
            timeout=self._timeout(),
            multicast=multicast,
            probe_udp=bool(self.probe_udp),
        )

        # Host-only UDP fallback
        if not result.devices and host and bool(self.probe_udp):
            udp = probe_matter_udp(host, self._port(), min(self._timeout(), 2.0))
            if udp.get("reachable"):
                self.set_info(
                    severity="info",
                    reason="Matter UDP/5540 reply (no mDNS TXT)",
                    host=host,
                    port=self._port(),
                )
                print_warning(f"UDP/5540 reachable on {host} without mDNS Matter records")
                return True

        if not result.devices:
            return False

        commissionable = [d for d in result.devices if d.commissionable]
        open_cm = [
            d
            for d in commissionable
            if d.commissioning_mode in (1, 2)
        ]
        self.set_info(
            severity="warning" if open_cm else "info",
            reason=(
                f"Matter nodes={len(result.devices)} "
                f"commissionable={len(commissionable)} "
                f"open_commissioning={len(open_cm)}"
            ),
            devices=[d.to_dict() for d in result.devices[:16]],
            suggested_modules=[
                "listeners/iot/matter_client",
                "post/matter/gather/device_inventory",
            ],
        )
        print_success(
            f"Matter: {len(result.devices)} node(s) "
            f"(commissionable={len(commissionable)}, open_cm={len(open_cm)})"
        )
        for device in result.devices[:12]:
            kind = "C" if device.commissionable else "O"
            print_info(
                f"  [{kind}] {device.device_name or device.instance or device.host} "
                f"vid={device.vendor_id or '-'} "
                f"{device.vendor_name or ''} "
                f"type={device.device_type_name or device.device_type or '-'} "
                f"cm={device.commissioning_mode_name or '-'}"
            )
        return True
