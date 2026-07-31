#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMB2 security mode / dialect (NSE smb2-security-mode / smb-protocols)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB Security Mode",
        "description": (
            "Negotiates SMB2/3 and reports signing mode and selected dialect "
            "(NSE smb2-security-mode / smb-protocols)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://nmap.org/nsedoc/scripts/smb2-security-mode.html",
            "https://nmap.org/nsedoc/scripts/smb-protocols.html",
        ],
        "tags": ["smb", "smb2", "signing", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        if not self._host():
            return False
        status, dialect, code = self.smb2_info()
        if status in ("unreachable", "error", "smb2_disabled") and not dialect:
            return False
        severity = "info"
        if status == "disabled":
            severity = "medium"
        elif status == "enabled_not_required":
            severity = "low"
        self.set_info(
            severity=severity,
            reason=f"SMB signing={status}" + (f" dialect={dialect}" if dialect else ""),
            signing=status,
            dialect=dialect or "",
            dialect_code=hex(code) if code is not None else "",
        )
        return True
