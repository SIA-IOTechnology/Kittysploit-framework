#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SSH service and fingerprint OpenSSH/Dropbear banners."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_ssh_banner


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "OpenSSH Banner Detection",
        "description": "Detects SSH services and extracts OpenSSH or Dropbear version banners.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/ssh-hostkey.html"],
        "metadata": {"max-request": 1, "product": "openssh", "vendor": "openbsd"},
        "tags": ["ssh", "network", "scanner", "enum", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(22, "Target SSH port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_ssh_banner(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        product = str(info.get("product") or "ssh")
        version = str(info.get("version") or "")
        self.set_info(
            severity="info",
            reason=f"SSH service detected ({product} {version})".strip(),
            banner=info.get("banner", ""),
            product=product,
            version=version,
        )
        return True
