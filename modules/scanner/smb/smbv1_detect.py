#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection SMBv1 activé (EternalBlue, relais, etc.)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMBv1 detection",
        "description": "Detects if SMBv1 is enabled (EternalBlue, relay, deprecated).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["smb", "scanner", "smbv1", "eternalblue", "legacy"],
    }

    def run(self):
        if not self._host():
            return False
        if self.smb1_enabled():
            self.set_info(severity="high", reason="SMBv1 negotiate accepted (disable SMBv1)")
            return True
        return False
