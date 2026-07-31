#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DHCP broadcast discover (NSE broadcast-dhcp-discover)."""

from kittysploit import *
from lib.scanner.broadcast.detectors import probe_broadcast_dhcp


class Module(Scanner):
    __info__ = {
        "name": "Broadcast DHCP Discover",
        "description": (
            "Sends a DHCP DISCOVER and reports offers (NSE broadcast-dhcp-discover). "
            "Requires scapy and typically elevated privileges."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html"],
        "tags": ["dhcp", "broadcast", "scanner", "discovery", "lan"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    timeout = OptPort(5, "Listen timeout seconds", False)
    iface = OptString("", "Scapy interface (optional)", False, advanced=True)

    def run(self):
        info = probe_broadcast_dhcp(
            timeout=float(self.timeout or 5),
            iface=str(self.iface or ""),
        )
        if info.get("error", "").startswith("scapy_required"):
            print_info("Scapy required for DHCP broadcast discover")
            return False
        if not info.get("detected"):
            return False
        offers = info.get("offers") or []
        self.set_info(
            severity="info",
            reason=f"DHCP offer(s) received ({len(offers)})",
            offers=offers[:10],
        )
        return True
