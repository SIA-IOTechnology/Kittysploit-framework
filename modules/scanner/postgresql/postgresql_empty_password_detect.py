#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PostgreSQL trust / empty-password access."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.postgresql.detectors import probe_postgresql

try:
    import psycopg2
except ImportError:  # pragma: no cover
    psycopg2 = None


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "PostgreSQL Empty Password",
        "description": (
            "Tests common PostgreSQL usernames for trust or empty-password "
            "login via psycopg2. Authorized targets only."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["postgresql", "database", "credentials", "misconfig", "scanner", "vuln"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": "username"},
                    "authenticated_session",
                ],
                "consumes_capabilities": ["service_identified", "pgsql_auth_surface"],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/postgresql/postgresql_login_bruteforce",
                ],
            },
        },
    }

    port = OptPort(5432, "Target PostgreSQL port", True)
    database = OptString("postgres", "Database name for login attempts", False)
    usernames = OptString(
        "postgres,admin,root,test,user",
        "Comma-separated usernames to test with an empty password",
        False,
    )

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        if psycopg2 is None:
            print_info("psycopg2 required for PostgreSQL empty-password probe")
            return False

        database = str(self.database or "postgres")
        users = [
            u.strip()
            for u in str(self.usernames or "postgres,admin").split(",")
            if u.strip()
        ]
        timeout = max(float(self._timeout()), 3.0)

        # Prefer trust signal from handshake when present
        for username in users:
            probe = probe_postgresql(
                host=host,
                port=port,
                timeout=min(timeout, 5.0),
                user=username,
                database=database,
            )
            if probe.get("auth_method") == "trust":
                reason = f"PostgreSQL trust auth for {username}@{database}"
                self.report_finding(
                    "PostgreSQL trust authentication",
                    severity="high",
                    evidence={
                        "host": host,
                        "port": port,
                        "username": username,
                        "database": database,
                        "auth_method": "trust",
                    },
                    impact={
                        "summary": "Server accepts connections without a password (trust).",
                        "business_risk": "Unauthenticated database access",
                    },
                    remediation={
                        "summary": "Replace trust with scram-sha-256/md5 and restrict pg_hba.conf.",
                        "actions": [
                            "Update pg_hba.conf to require password auth",
                            "Use scram-sha-256",
                            "Restrict listen addresses",
                        ],
                    },
                )
                self.set_info(
                    severity="high",
                    reason=reason,
                    username=username,
                    password="",
                    database=database,
                    auth_method="trust",
                )
                return True

            try:
                conn = psycopg2.connect(
                    host=host,
                    port=int(port),
                    user=username,
                    password="",
                    dbname=database,
                    connect_timeout=int(timeout),
                )
                conn.close()
            except Exception:
                continue

            reason = f"PostgreSQL empty password accepted for {username}@{database}"
            self.report_finding(
                "PostgreSQL empty password accepted",
                severity="high",
                evidence={
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": "(empty)",
                    "database": database,
                },
                impact={
                    "summary": "Database accessible without a password.",
                    "business_risk": "Data exposure / lateral movement",
                },
                remediation={
                    "summary": "Set strong passwords and harden pg_hba.conf.",
                    "actions": [
                        "ALTER ROLE … PASSWORD",
                        "Require scram-sha-256",
                        "Restrict listen addresses",
                    ],
                },
            )
            self.set_info(
                severity="high",
                reason=reason,
                username=username,
                password="",
                database=database,
            )
            return True
        return False
