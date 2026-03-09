#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection PFCP (UDP 8805) - 5G N4 interface (SMF-UPF)."""

import socket
from kittysploit import *
from core.framework.option import OptPort
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


def _pfcp_probe_udp(host: str, port: int, timeout: float = 2.0) -> bool:
    """Send minimal PFCP Heartbeat Request; return True if response received."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # PFCP header: version 1, S=0, message type 60 (Heartbeat Request), length 4
        probe = bytes([0x20, 0x3C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
        s.sendto(probe, (host, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return len(data) >= 8
    except (socket.timeout, OSError):
        return False


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "PFCP UDP detection",
        "description": "Detects PFCP port 8805 (5G N4 - SMF/UPF control plane).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "pfcp", "3gpp", "n4", "upf", "smf"],
    }

    port = OptPort(8805, "PFCP port (8805)", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = self._port()
        if port in (80, 443, 3868, 2152):
            port = 8805
        if _pfcp_probe_udp(host, port, self._timeout()):
            self.set_info(severity="medium", reason="PFCP port 8805 responsive (5G N4)")
            return True
        return False
