#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection MySQL + récupération d'informations via handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mysql.detectors import fingerprint_mysql


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "MySQL Info - Enumeration",
        "description": "Connects to a MySQL server and prints information such as protocol, version, TLS support, and transport.",
        "author": "pussycat0x / KittySploit Team",
        "severity": "info",
        "references": [
            "https://nmap.org/nsedoc/scripts/mysql-info.html",
        ],
        "metadata": {
            "max-request": 1,
            "shodan-query": "port:3306",
            "product": "mysql",
            "vendor": "oracle",
        },
        "tags": ["mysql", "network", "enum", "discovery"],
    }

    port = OptPort(3306, "Target MySQL port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = fingerprint_mysql(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if not info.get("success"):
            return False

        self.set_info(
            version=info.get("Version", ""),
            protocol=info.get("Protocol", ""),
            tls=info.get("TLS", ""),
            transport=info.get("Transport", "tcp"),
        )
        return True
