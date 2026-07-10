#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated ClickHouse SQL queries over HTTP."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.clickhouse.detectors import probe_clickhouse_query


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "ClickHouse Unauthenticated Query Verification",
        "description": "Confirms anonymous ClickHouse HTTP queries via SELECT version() and SELECT 1.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["clickhouse", "database", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["db_access", "unauth_read"],
                "consumes_capabilities": ["devops_panel"],
            },
        },
    }

    port = OptPort(8123, "ClickHouse HTTP port", True)

    def run(self):
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=self._port()):
            return False
        for query in ("SELECT 1", "SELECT version()"):
            info = probe_clickhouse_query(host=host, port=self._port(), query=query, timeout=self._timeout())
            if info.get("detected"):
                rows = info.get("rows") or []
                self.set_info(
                    severity="high",
                    reason="ClickHouse accepts unauthenticated SQL queries",
                    query=query,
                    proof=str(rows[0] if rows else ""),
                    confidence="high",
                )
                return True
        return False
