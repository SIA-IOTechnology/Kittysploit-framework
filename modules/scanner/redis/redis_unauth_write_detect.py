#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Redis instances allowing unauthenticated writes."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.redis.detectors import probe_redis_unauth_write


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Redis Unauthenticated Write Detection",
        "description": "Tests whether Redis accepts unauthenticated SET/DEL commands.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "metadata": {"max-request": 2, "product": "redis", "vendor": "redis"},
        "tags": ["redis", "network", "scanner", "misconfig", "unauth"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(6379, "Target Redis port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_redis_unauth_write(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if not info.get("detected"):
            return False

        if info.get("writable"):
            self.set_info(
                severity="high",
                reason="Redis allows unauthenticated write operations",
            )
            print_warning("Redis unauthenticated write access confirmed")
            return True

        self.set_info(severity="info", reason="Redis detected — write requires authentication")
        return True
