#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection GTP-U / GTP-C (UDP 2152 / 2123) - 3GPP 4G/5G user/control plane."""

import socket
from kittysploit import *
from core.framework.option import OptPort
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


# Minimal GTPv2-C Echo Request (message type 1) or GTPv1-U G-PDU (0xff) - 8 bytes min
def _gtp_probe_udp(host: str, port: int, timeout: float = 2.0) -> bool:
    """Send minimal GTP-like UDP probe; return True if any response received."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # GTPv1-U: flags 0x30, type 0xff (G-PDU), length 0, TEID 0
        probe = bytes([0x30, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        s.sendto(probe, (host, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return len(data) >= 4
    except (socket.timeout, OSError):
        return False


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "GTP-U/GTP-C UDP detection",
        "description": "Detects GTP-U (2152) or GTP-C (2123) - 3GPP 4G/5G data/control plane.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "lte", "gtp", "3gpp", "mobile", "ran"],
    }

    port = OptPort(2152, "GTP port (2152=GTP-U, 2123=GTP-C)", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = self._port()
        timeout = self._timeout()
        if port in (80, 443, 3868):
            port = 2152
        if _gtp_probe_udp(host, port, timeout):
            label = "GTP-U" if port == 2152 else "GTP-C" if port == 2123 else "GTP"
            self.set_info(severity="medium", reason=f"{label} port {port} responsive (UDP)")
            return True
        return False
