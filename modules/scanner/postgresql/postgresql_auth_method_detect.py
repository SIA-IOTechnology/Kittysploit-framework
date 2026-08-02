#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PostgreSQL authentication method from startup handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.postgresql.detectors import probe_postgresql


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "PostgreSQL Auth Method",
        "description": (
            "Identifies the PostgreSQL AuthenticationRequest type "
            "(trust, cleartext, md5, scram/sasl, …) for a username."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["postgresql", "database", "auth", "scanner", "enum"],
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
                    "pgsql_auth_surface",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/postgresql/postgresql_empty_password_detect",
                    "auxiliary/scanner/postgresql/postgresql_login_bruteforce",
                ],
            },
        },
    }

    port = OptPort(5432, "Target PostgreSQL port", True)
    username = OptString("postgres", "Username used for startup probe", False)
    database = OptString("postgres", "Database name used for startup probe", False)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        user = str(self.username or "postgres")
        database = str(self.database or "postgres")
        info = probe_postgresql(
            host=host,
            port=port,
            timeout=self._timeout(),
            user=user,
            database=database,
        )
        if not info.get("detected"):
            return False
        method = str(info.get("auth_method") or "").strip()
        if not method:
            method = "unknown"
        severity = "info"
        if method == "trust":
            severity = "high"
        elif method == "cleartext":
            severity = "medium"
        reason = f"PostgreSQL auth method for {user}@{database}: {method}"
        self.set_info(
            severity=severity,
            reason=reason,
            auth_method=method,
            auth_required=bool(info.get("auth_required")),
            username=user,
            database=database,
        )
        return True
