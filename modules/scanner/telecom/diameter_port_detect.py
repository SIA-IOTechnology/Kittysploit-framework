#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection port Diameter (3GPP LTE/5G - authentification, abonnés)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "Diameter port detection",
        "description": "Detects open Diameter port (3868) - 3GPP LTE/5G S6a/S6d, authentication.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "lte", "diameter", "3gpp", "mobile"],
    }

    def run(self):
        if not self._host():
            return False
        if self.is_tcp_open():
            self.set_info(severity="medium", reason="Diameter port 3868 open (3GPP control plane)")
            return True
        return False
