#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated InfluxDB database listing."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.influxdb.detectors import probe_influxdb_query


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "InfluxDB Unauthenticated Read Verification",
        "description": "Confirms anonymous InfluxDB HTTP queries via SHOW DATABASES.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["influxdb", "database", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["db_access", "unauth_read"]},
        },
    }

    port = OptPort(8086, "InfluxDB HTTP port", True)

    def run(self):
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=self._port()):
            return False
        info = probe_influxdb_query(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        dbs = info.get("databases") or []
        self.set_info(
            severity="high",
            reason="InfluxDB allows unauthenticated SHOW DATABASES",
            database_count=len(dbs),
            databases=",".join(str(x) for x in dbs[:8]),
            confidence="high",
        )
        return True
