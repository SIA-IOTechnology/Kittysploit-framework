#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report MySQL/MariaDB TLS capability from the server handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mysql.detectors import fingerprint_mysql


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MySQL TLS Capability",
        "description": (
            "Reports whether the MySQL/MariaDB handshake advertises SSL/TLS "
            "(CLIENT_SSL). Flags servers that do not support TLS."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/mysql-info.html"],
        "tags": ["mysql", "mariadb", "tls", "ssl", "scanner", "enum"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["service_identified"],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
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
        tls = str(info.get("TLS") or "unknown")
        tls_supported = tls.lower() == "supported"
        severity = "info" if tls_supported else "low"
        if tls_supported:
            reason = f"MySQL TLS supported | version={version}" if version else "MySQL TLS supported"
        else:
            reason = (
                f"MySQL TLS not supported in handshake | version={version}"
                if version
                else "MySQL TLS not supported in handshake"
            )
        self.set_info(
            severity=severity,
            reason=reason,
            version=version,
            tls=tls,
            protocol=str(info.get("Protocol") or ""),
            transport=str(info.get("Transport") or "tcp"),
        )
        return True
