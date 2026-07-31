#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFS showmount / export list (NSE nfs-showmount)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.nfs.detectors import probe_nfs_showmount


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "NFS Showmount",
        "description": (
            "Queries the MOUNT daemon (via portmap) for NFS export lists "
            "(NSE nfs-showmount)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/nfs-showmount.html"],
        "tags": ["nfs", "rpc", "showmount", "scanner", "discovery", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(111, "Portmap / rpcbind port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_nfs_showmount(
            host=host, portmap_port=self._port(), timeout=self._timeout()
        )
        if not info.get("detected"):
            return False
        exports = info.get("exports") or []
        severity = "medium" if exports else "info"
        self.set_info(
            severity=severity,
            reason=f"NFS mount service detected ({len(exports)} exports)",
            mount_port=int(info.get("mount_port") or 0),
            exports=exports[:30],
        )
        return True
