#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MongoDB instances and unauthenticated access."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mongodb.detectors import PYMONGO_AVAILABLE, probe_mongodb


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MongoDB Unauthenticated Access Detection",
        "description": "Detects exposed MongoDB and whether databases are readable without authentication.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["mongodb", "database", "scanner", "misconfig", "unauth"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(27017, "Target MongoDB port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            print_error("Target is required")
            return False
        if not PYMONGO_AVAILABLE:
            print_error("pymongo not installed")
            return False
        if not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_mongodb(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        version = str(info.get("version") or "")
        if info.get("unauthenticated"):
            dbs = info.get("databases") or []
            self.set_info(
                severity="high",
                reason=f"MongoDB {version} allows unauthenticated access",
                databases=dbs[:10],
            )
            print_warning(f"MongoDB unauthenticated — databases: {', '.join(dbs[:8])}")
            return True

        if info.get("auth_required"):
            self.set_info(
                severity="info",
                reason=f"MongoDB {version} detected — authentication required",
                version=version,
            )
            print_info(f"MongoDB detected ({version}), authentication required")
            return True
        return False
