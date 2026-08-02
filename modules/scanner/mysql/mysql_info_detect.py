#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection MySQL + récupération d'informations via handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mysql.detectors import fingerprint_mysql


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "MySQL Info - Enumeration",
        "description": (
            "Connects to a MySQL server and prints information such as "
            "protocol, version, TLS support, and transport."
        ),
        "author": ["KittySploit Team"],
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
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    "service_identified",
                    "db_surface",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/mysql/mysql_tls_detect",
                    "scanner/mysql/mysql_empty_password_detect",
                    "auxiliary/scanner/mysql/mysql_login_bruteforce",
                ],
            },
        },
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

        version = str(info.get("Version") or "")
        protocol = str(info.get("Protocol") or "")
        tls = str(info.get("TLS") or "")
        transport = str(info.get("Transport") or "tcp")
        parts = []
        if version:
            parts.append(f"version={version}")
        if protocol:
            parts.append(f"protocol={protocol}")
        if tls:
            parts.append(f"tls={tls}")
        if transport:
            parts.append(f"transport={transport}")
        reason = "MySQL service detected"
        if parts:
            reason = f"{reason} | {' | '.join(parts)}"
        self.set_info(
            severity="info",
            reason=reason,
            version=version,
            protocol=protocol,
            tls=tls,
            transport=transport,
        )
        return True
