#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Redis + récupération d'informations via INFO."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.redis.detectors import get_server_info, extract_server_details


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "Redis Info - Detect",
        "description": "Retrieves information such as version number, architecture, role, and resource usage from a Redis server.",
        "author": "DhiyaneshDK / KittySploit Team",
        "severity": "info",
        "references": [
            "https://nmap.org/nsedoc/scripts/redis-info.html",
        ],
        "metadata": {
            "max-request": 1,
            "product": "redis",
            "vendor": "redis",
        },
        "tags": ["redis", "network", "enum", "discovery"],
    }

    port = OptPort(6379, "Target Redis port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        response = get_server_info(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if not response:
            return False

        if response.startswith("-NOAUTH") or "authentication required" in response.lower():
            self.set_info(severity="info", reason="Redis detected but INFO requires authentication")
            return True

        if "redis_version:" not in response and not response.startswith("$"):
            return False

        extracted = extract_server_details(response)
        if not extracted:
            self.set_info(severity="info", reason="Redis responded to INFO")
            return True

        self.set_info(**extracted)
        return True
