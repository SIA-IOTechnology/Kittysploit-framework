#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Kafka brokers via ApiVersions on TCP 9092."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.kafka.detectors import probe_kafka_broker


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Apache Kafka Broker Detection",
        "description": "Detects Kafka brokers by sending an ApiVersions request on TCP 9092.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["kafka", "messaging", "scanner", "discovery", "tcp", "broker"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(9092, "Kafka broker port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_kafka_broker(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="Kafka broker ApiVersions response received",
            api_count=int(info.get("api_count") or 0),
            error_code=info.get("error_code"),
        )
        return True
