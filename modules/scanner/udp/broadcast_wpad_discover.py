#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPAD discovery (NSE broadcast-wpad-discover inspired)."""

from kittysploit import *
from lib.scanner.broadcast.detectors import probe_broadcast_wpad


class Module(Scanner):
    __info__ = {
        "name": "WPAD Discover",
        "description": (
            "Resolves WPAD hosts and fetches wpad.dat PAC files "
            "(NSE broadcast-wpad-discover inspired; DNS+HTTP methods)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/broadcast-wpad-discover.html"],
        "tags": ["wpad", "proxy", "scanner", "discovery", "lan"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    domain = OptString("", "Optional local DNS domain for wpad.<domain>", False)
    timeout = OptPort(5, "HTTP timeout seconds", False)

    def run(self):
        info = probe_broadcast_wpad(
            domain=str(self.domain or ""),
            timeout=float(self.timeout or 5),
        )
        if not info.get("detected"):
            return False
        pac_urls = info.get("pac_urls") or []
        severity = "medium" if pac_urls else "info"
        self.set_info(
            severity=severity,
            reason="WPAD endpoint(s) discovered",
            wpad_hosts=list(info.get("wpad_hosts") or [])[:10],
            pac_urls=list(pac_urls)[:5],
            pac_preview=str(info.get("pac_preview") or "")[:200],
        )
        return True
