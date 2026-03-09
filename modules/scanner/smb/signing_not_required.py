#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection SMB signing désactivé ou non requis (relais NTLM)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB signing not required",
        "description": "Detects SMB signing disabled or not required (NTLM relay possible).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["smb", "scanner", "signing", "relay", "ntlm"],
    }

    def run(self):
        if not self._host():
            return False
        status, ver = self.smb_signing_status()
        if status == "unreachable" or status == "error":
            return False
        if status == "disabled":
            ver_str = ver or "SMB2/3"
            self.set_info(severity="high", reason=f"Signing disabled ({ver_str})")
            return True
        if status == "enabled_not_required":
            ver_str = ver or "SMB2/3"
            self.set_info(severity="medium", reason=f"Signing enabled but not required ({ver_str})")
            return True
        if status == "smb2_disabled" and self.smb1_enabled():
            self.set_info(severity="high", reason="SMBv1 only — SMB2/3 signing not applicable")
            return True
        return False
