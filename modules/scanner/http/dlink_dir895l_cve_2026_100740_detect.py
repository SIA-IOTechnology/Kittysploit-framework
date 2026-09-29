#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-100740 — D-Link DIR-895L L2TP Host Name AVP OOB write detection."""

from __future__ import annotations

import re
import socket
from typing import Any, Optional
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    L2TP_UDP_PORT = 1701
    POCBIT_PAGE = "https://pocbit.org/pocs/cve-2026-100740"
    VULN_FW_MARKERS = ("A1_102b07", "102b07")
    MODEL_MARKERS = ("dir-895l", "dir_895l", "DIR-895L")
    HTTP_PATHS = (
        "/",
        "/Login.html",
        "/login.html",
        "/index.asp",
        "/info/Login.html",
    )

    __info__ = {
        "name": "D-Link DIR-895L CVE-2026-100740 L2TP OOB Write Detection",
        "description": (
            "Detects D-Link DIR-895L firmware A1_102b07 and an exposed L2TP UDP/1701 service "
            "associated with CVE-2026-100740 (Host Name AVP out-of-bounds write)."
        ),
        "author": ["PoCbit", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-100740"],
        "references": [
            POCBIT_PAGE,
            "https://nvd.nist.gov/vuln/detail/CVE-2026-100740",
        ],
        "tags": [
            "web",
            "scanner",
            "udp",
            "l2tp",
            "dlink",
            "dir-895l",
            "router",
            "iot",
            "memory-corruption",
            "cve-2026-100740",
        ],
        "modules": [
            "exploits/linux/udp/dlink_dir895l_cve_2026_100740_l2tp",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "requires": {
                "tech_hints_any": ["dlink", "router"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "risk_signal", "from_detail": "dir895l_l2tp_oob"},
                ],
                "suggested_followups": [
                    "exploits/linux/udp/dlink_dir895l_cve_2026_100740_l2tp",
                ],
            },
        },
    }

    l2tp_port = OptPort(L2TP_UDP_PORT, "L2TP UDP port to probe", required=False, advanced=True)
    udp_timeout = OptInteger(4, "UDP probe timeout in seconds", required=False, advanced=True)

    def _host(self) -> str:
        target = str(getattr(self, "target", "") or "").strip()
        if "://" in target:
            parsed = urlparse(target)
            return str(parsed.hostname or parsed.netloc or target).split(":")[0]
        return target.split("/")[0].split(":")[0]

    @classmethod
    def _parse_firmware(cls, text: str) -> Optional[str]:
        if not text:
            return None
        match = re.search(r"A1[_-]?(\d+[a-z]\d+)", text, re.I)
        if match:
            return "A1_" + match.group(1).lower()
        match = re.search(r"(\d{3}b\d{2})", text, re.I)
        if match:
            return "A1_" + match.group(1).lower()
        return None

    @classmethod
    def _firmware_vulnerable(cls, fw_str: Optional[str]) -> bool:
        if not fw_str:
            return False
        low = fw_str.lower()
        return "102b07" in low or low == "a1_102b07"

    def _detect_router(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "device": False,
            "model": None,
            "firmware": None,
            "http_hits": [],
        }
        bodies: list[str] = []
        for path in self.HTTP_PATHS:
            response = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=int(self.timeout or 12),
            )
            if not response or int(response.status_code or 0) >= 500:
                continue
            body = response.text or ""
            low = body.lower()
            if any(marker.lower() in low for marker in self.MODEL_MARKERS) or "d-link" in low:
                row["http_hits"].append(path)
                bodies.append(body)
                if any(marker in body for marker in self.MODEL_MARKERS):
                    row["model"] = "DIR-895L"
                row["device"] = True
        for body in bodies:
            firmware = self._parse_firmware(body)
            if firmware:
                row["firmware"] = firmware
                break
        if row["device"] and row["firmware"] is None:
            for marker in self.VULN_FW_MARKERS:
                if any(marker.lower() in (entry or "").lower() for entry in bodies):
                    row["firmware"] = "A1_102b07 (hint)"
                    break
        return row

    def _udp_open(self) -> bool:
        host = self._host()
        if not host:
            return False
        port = int(self.l2tp_port or self.L2TP_UDP_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(float(self.udp_timeout or 4))
        try:
            sock.sendto(b"\x00", (host, port))
            try:
                sock.recvfrom(512)
            except socket.timeout:
                pass
            except OSError:
                pass
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def run(self):
        det = self._detect_router()
        if not det.get("device"):
            return False

        firmware = det.get("firmware")
        l2tp_open = self._udp_open()
        fw_vuln = self._firmware_vulnerable(firmware) or (
            isinstance(firmware, str) and "102b07" in firmware.lower()
        )
        l2tp_port = int(self.l2tp_port or self.L2TP_UDP_PORT)

        if fw_vuln and l2tp_open:
            severity = "critical"
            reason = (
                f"D-Link DIR-895L firmware {firmware} with L2TP UDP/{l2tp_port} open "
                f"(CVE-2026-100740)"
            )
        elif det.get("model") == "DIR-895L" and l2tp_open:
            severity = "high"
            reason = (
                "DIR-895L with exposed L2TP UDP/1701 — verify firmware A1_102b07 for CVE-2026-100740"
            )
        elif det.get("device") and l2tp_open:
            severity = "medium"
            reason = "D-Link router with L2TP UDP/1701 open — possible CVE-2026-100740 exposure"
        else:
            severity = "info"
            reason = "D-Link router detected; L2TP UDP/1701 not reachable from scanner"

        self.set_info(
            severity=severity,
            reason=reason,
            path=det.get("http_hits", ["/"])[0],
            model=det.get("model"),
            firmware=firmware,
            l2tp_open=l2tp_open,
        )
        return severity in ("critical", "high", "medium")
