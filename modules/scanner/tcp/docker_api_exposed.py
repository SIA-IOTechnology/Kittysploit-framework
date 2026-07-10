#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Docker Engine API on TCP 2375."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.docker.detectors import probe_docker_api


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Docker API Exposure Verification",
        "description": "Confirms unauthenticated Docker Engine /version and /containers/json on TCP 2375.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["docker", "container", "scanner", "unauth", "verify", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["container_admin", "unauth_read"]},
        },
    }

    port = OptPort(2375, "Docker API port", True)

    def run(self):
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=self._port()):
            return False
        info = probe_docker_api(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        containers = info.get("containers") or []
        self.set_info(
            severity="critical",
            reason="Docker Engine API exposed without authentication",
            version=str(info.get("version") or ""),
            container_count=len(containers),
            confidence="high",
        )
        return True
