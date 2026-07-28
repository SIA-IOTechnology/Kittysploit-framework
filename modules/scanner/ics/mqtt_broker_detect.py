#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MQTT brokers on plaintext TCP 1883."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mqtt.detectors import probe_mqtt_broker


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "MQTT Broker Detection",
        "description": "Detects MQTT brokers on TCP 1883 and tests anonymous subscribe access.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["ics", "iot", "mqtt", "scanner", "discovery", "messaging"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1883, "MQTT port", True)

    def run(self):
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=self._port()):
            return False

        result = probe_mqtt_broker(host, self._port(), timeout=self._timeout())
        if not result.detected:
            return False

        severity = "high" if result.anonymous else "medium" if result.auth_required else "info"
        self.set_info(
            severity=severity,
            reason="MQTT broker detected",
            anonymous=bool(result.anonymous),
            auth_required=bool(result.auth_required),
            broker_version=str(result.broker_version or ""),
            error=str(result.error or ""),
        )
        return True
