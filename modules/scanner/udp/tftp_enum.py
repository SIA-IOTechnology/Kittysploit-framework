#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TFTP common-file enum (NSE tftp-enum)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.tftp.detectors import probe_tftp_enum


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "TFTP Enum",
        "description": (
            "Attempts TFTP RRQ for common config/boot filenames "
            "(NSE tftp-enum)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/tftp-enum.html"],
        "tags": ["tftp", "udp", "scanner", "enum", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 15,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(69, "TFTP UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_tftp_enum(host=host, port=self._port(), timeout=self._timeout())
        existing = info.get("existing") or []
        if not existing:
            # Service may still be up with only "file not found"
            if info.get("detected"):
                self.set_info(
                    severity="info",
                    reason="TFTP service responded (no common files found)",
                    existing=[],
                )
                return True
            return False
        self.set_info(
            severity="medium",
            reason=f"TFTP files readable ({len(existing)})",
            existing=list(existing)[:30],
        )
        return True
