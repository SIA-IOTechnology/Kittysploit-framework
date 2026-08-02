#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MySQL/MariaDB accounts with an empty password."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mysql.detectors import fingerprint_mysql

try:
    import pymysql
except ImportError:  # pragma: no cover
    pymysql = None


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MySQL Empty Password",
        "description": (
            "Tests common MySQL/MariaDB usernames for empty-password login. "
            "Requires pymysql. Authorized targets only."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["mysql", "mariadb", "credentials", "misconfig", "scanner", "vuln"],
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
                "consumes_capabilities": ["service_identified"],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/mysql/mysql_login_bruteforce",
                    "post/mysql/gather/enum_databases",
                ],
            },
        },
    }

    port = OptPort(3306, "Target MySQL port", True)
    usernames = OptString(
        "root,admin,mysql,test,user",
        "Comma-separated usernames to test with an empty password",
        False,
    )

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        if pymysql is None:
            print_info("pymysql required for MySQL empty-password probe")
            return False

        fp = fingerprint_mysql(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        version = str(fp.get("Version") or "") if fp.get("success") else ""

        users = [
            u.strip()
            for u in str(self.usernames or "root,admin").split(",")
            if u.strip()
        ]
        timeout = max(int(float(self._timeout())), 3)
        for username in users:
            try:
                conn = pymysql.connect(
                    host=host,
                    port=int(port),
                    user=username,
                    password="",
                    connect_timeout=timeout,
                    read_timeout=timeout,
                    write_timeout=timeout,
                )
                conn.ping(reconnect=False)
                conn.close()
            except Exception:
                continue

            reason = f"MySQL empty password accepted for {username}"
            if version:
                reason = f"{reason} | version={version}"
            self.report_finding(
                "MySQL empty password accepted",
                severity="high",
                evidence={
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": "(empty)",
                    "version": version,
                },
                impact={
                    "summary": "Database accessible without a password.",
                    "business_risk": "Data exposure / lateral movement",
                },
                remediation={
                    "summary": "Set strong passwords and restrict remote root login.",
                    "actions": [
                        "SET PASSWORD for empty-password accounts",
                        "Bind MySQL to trusted interfaces only",
                        "Require TLS for remote clients when possible",
                    ],
                },
            )
            self.set_info(
                severity="high",
                reason=reason,
                username=username,
                password="",
                version=version,
            )
            return True
        return False
