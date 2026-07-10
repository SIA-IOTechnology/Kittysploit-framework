#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Zookeeper four-letter-word admin commands without authentication."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.zookeeper.detectors import probe_zookeeper_unauth_info


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Zookeeper Unauthenticated Enumeration",
        "description": "Collects Zookeeper srvr/stat/conf output via unauthenticated four-letter commands.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["zookeeper", "tcp", "scanner", "unauth", "verify", "enumeration"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["unauth_read", "misconfig_surface"]},
        },
    }

    port = OptPort(2181, "Zookeeper port", True)

    def run(self):
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=self._port()):
            return False
        info = probe_zookeeper_unauth_info(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        conf = str(info.get("conf") or "")
        severity = "high" if "dataDir" in conf or "clientPort" in conf else "medium"
        self.set_info(
            severity=severity,
            reason="Zookeeper admin commands respond without authentication",
            version=str(info.get("version") or ""),
            conf_exposed=bool(conf),
            confidence="high",
        )
        return True
