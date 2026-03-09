#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection null session (accès SMB anonyme)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB null session",
        "description": "Detects if anonymous (null) SMB session is accepted.",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["smb", "scanner", "null session", "anonymous", "enumeration"],
    }

    def run(self):
        if not self._host():
            return False
        if self.null_session_accepted():
            self.set_info(severity="high", reason="Null session accepted (unauthenticated access)")
            return True
        return False
