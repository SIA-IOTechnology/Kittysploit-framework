#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identify exposed MQTT brokers and anonymous access."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mqtt.detectors import probe_mqtt_broker


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "MQTT Broker Identify",
        "description": "Detect MQTT brokers and test anonymous subscribe access on TCP 1883.",
        "author": ["KittySploit Team"],
        "tags": ["ics", "iot", "mqtt", "broker", "scanner"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1883, "MQTT TCP port", True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return {"error": "missing_target"}

        result = probe_mqtt_broker(host, self._port(), timeout=self._timeout())
        data = result.to_dict()

        if not result.detected:
            print_error(result.error or "MQTT broker not detected")
            return data

        if result.anonymous:
            print_warning(f"MQTT broker allows anonymous access on {host}:{self._port()}")
            if result.broker_version:
                print_info(f"Broker version: {result.broker_version}")
            if result.topics_seen:
                print_info(f"Topics seen: {', '.join(result.topics_seen[:8])}")
        elif result.auth_required:
            print_info(f"MQTT broker detected on {host}:{self._port()} — authentication required")
        else:
            print_info(result.error or "MQTT broker detected with unknown auth state")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
