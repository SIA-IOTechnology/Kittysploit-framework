#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WS-Discovery multicast probe (NSE broadcast-wsdd-discover)."""

from kittysploit import *
from lib.scanner.broadcast.detectors import probe_broadcast_wsdd


class Module(Scanner):
    __info__ = {
        "name": "Broadcast WS-Discovery",
        "description": (
            "Sends a WS-Discovery Probe to 239.255.255.250:3702 and collects ProbeMatches "
            "(NSE broadcast-wsdd-discover)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/broadcast-wsdd-discover.html"],
        "tags": ["wsdd", "ws-discovery", "broadcast", "scanner", "discovery", "lan"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    timeout = OptPort(3, "Listen timeout seconds", False)

    def run(self):
        info = probe_broadcast_wsdd(timeout=float(self.timeout or 3))
        if not info.get("detected"):
            return False
        endpoints = info.get("endpoints") or []
        self.set_info(
            severity="info",
            reason=f"WS-Discovery responses ({len(endpoints)})",
            endpoints=list(endpoints)[:20],
        )
        return True
