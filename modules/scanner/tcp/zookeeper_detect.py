#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Zookeeper service on TCP 2181."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.zookeeper.detectors import probe_zookeeper


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Zookeeper Detection",
        "description": "Detects Zookeeper via four-letter srvr command.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "zookeeper", "vendor": "apache"},
        "tags": ["zookeeper", "tcp", "scanner", "discovery", "coordination"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(2181, "Zookeeper port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_zookeeper(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="Zookeeper service detected",
            version=str(info.get("version") or ""),
        )
        return True
