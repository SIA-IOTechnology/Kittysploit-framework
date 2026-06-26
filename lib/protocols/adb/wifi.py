#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ADB Wi-Fi shell output parser and collector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

CmdExecutor = Callable[[str], str]


class AdbWifiError(Exception):
    """Raised when ADB Wi-Fi helpers are used without a shell executor."""


@dataclass
class AdbWifiNetwork:
    """Saved or observed Wi-Fi network entry."""

    ssid: str
    security: str = "unknown"
    network_id: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "id": self.network_id,
            "ssid": self.ssid,
            "security": self.security,
        }


class AdbWifi:
    """Parse and collect Wi-Fi information from Android shell commands over ADB."""

    _LIST_NETWORKS_ROW = re.compile(r"^(\d+)\s+\"?([^\"]+?)\"?\s{2,}(.+)$")
    _SSID_QUOTED = re.compile(r'SSID:\s*"([^"]+)"', re.IGNORECASE)
    _SSID_PLAIN = re.compile(r"SSID:\s*([^\n,]+)", re.IGNORECASE)
    _KEY_MGMT = re.compile(r"allowedKeyManagement.*?\[(.*?)\]", re.IGNORECASE | re.DOTALL)
    _SECURITY_TYPE = re.compile(r"Security type:\s*([^\n]+)", re.IGNORECASE)
    _STATUS_FIELDS = {
        "ssid": re.compile(r"ssid[:=]\s*\"?([^\"\n,]+)\"?", re.IGNORECASE),
        "bssid": re.compile(r"bssid[:=]\s*([0-9a-f:]{17})", re.IGNORECASE),
        "ip": re.compile(r"ip address[:=]\s*([0-9.]+)", re.IGNORECASE),
        "frequency": re.compile(r"frequency[:=]\s*(\d+)", re.IGNORECASE),
        "security": re.compile(r"security type[:=]\s*([^\n,]+)", re.IGNORECASE),
        "rssi": re.compile(r"rssi[:=]\s*(-?\d+)", re.IGNORECASE),
    }

    def __init__(self, cmd_execute: Optional[CmdExecutor] = None):
        self._cmd_execute = cmd_execute

    def shell(self, command: str) -> str:
        if not self._cmd_execute:
            raise AdbWifiError("ADB shell executor is not configured")
        return (self._cmd_execute(command) or "").strip()

    def parse_list_networks(self, raw: str) -> List[AdbWifiNetwork]:
        """Parse ``cmd wifi list-networks`` tabular output."""
        networks: List[AdbWifiNetwork] = []
        if not raw:
            return networks

        for line in raw.splitlines():
            text = line.strip()
            if not text or text.lower().startswith("network id") or text.startswith("-"):
                continue

            match = self._LIST_NETWORKS_ROW.match(text)
            if match:
                networks.append(
                    AdbWifiNetwork(
                        network_id=match.group(1).strip(),
                        ssid=match.group(2).strip().strip('"'),
                        security=match.group(3).strip(),
                    )
                )
                continue

            parts = re.split(r"\s{2,}", text)
            if len(parts) >= 3 and parts[0].isdigit():
                networks.append(
                    AdbWifiNetwork(
                        network_id=parts[0].strip(),
                        ssid=parts[1].strip().strip('"'),
                        security=parts[2].strip(),
                    )
                )
        return networks

    def parse_dumpsys_saved_networks(self, raw: str) -> List[AdbWifiNetwork]:
        """Best-effort extraction of saved networks from ``dumpsys wifi``."""
        networks: List[AdbWifiNetwork] = []
        if not raw:
            return networks

        seen = set()
        for block in re.split(r"\n\s*\n", raw):
            ssid = ""
            for pattern in (self._SSID_QUOTED, self._SSID_PLAIN):
                match = pattern.search(block)
                if match:
                    ssid = match.group(1).strip().strip('"')
                    break
            if not ssid or ssid in seen:
                continue

            security = "unknown"
            for pattern in (self._SECURITY_TYPE, self._KEY_MGMT):
                match = pattern.search(block)
                if match:
                    security = match.group(1).strip()
                    break
            if security == "unknown":
                security = self._infer_security_from_block(block)

            seen.add(ssid)
            networks.append(AdbWifiNetwork(ssid=ssid, security=security))
        return networks

    def parse_status(self, raw: str) -> Dict[str, str]:
        """Extract common fields from ``cmd wifi status`` or ``dumpsys wifi`` snippets."""
        info: Dict[str, str] = {}
        if not raw:
            return info

        for key, pattern in self._STATUS_FIELDS.items():
            match = pattern.search(raw)
            if match:
                info[key] = match.group(1).strip()
        return info

    def classify_security(self, security: str) -> str:
        value = (security or "").strip().lower()
        if not value or value in {"open", "none", "nopass", "[nopass]"}:
            return "open"
        if "wpa3" in value:
            return "wpa3"
        if "wpa2" in value or "psk" in value or "sae" in value:
            return "wpa2"
        if "wpa" in value or "eap" in value or "enterprise" in value:
            return "wpa_enterprise"
        if "owe" in value:
            return "owe"
        return "other"

    def collect_saved_networks(self) -> Tuple[List[AdbWifiNetwork], str]:
        """Enumerate saved networks via ``cmd wifi`` then ``dumpsys wifi`` fallbacks."""
        list_out = self.shell("cmd wifi list-networks")
        networks = self.parse_list_networks(list_out)
        if networks:
            return networks, "cmd wifi list-networks"

        dumpsys = self.shell("dumpsys wifi")
        networks = self.parse_dumpsys_saved_networks(dumpsys)
        if networks:
            return networks, "dumpsys wifi"

        legacy = self.shell("dumpsys wifi | grep -E 'SSID:|ConfigKey:|Security type:'")
        networks = self.parse_dumpsys_saved_networks(legacy)
        if networks:
            return networks, "dumpsys wifi (filtered)"
        return [], ""

    def fetch_wifi_status(self) -> str:
        """Return current Wi-Fi status text from the device."""
        status = self.shell("cmd wifi status")
        if status:
            return status
        return self.shell("dumpsys wifi | head -120")

    @staticmethod
    def _infer_security_from_block(block: str) -> str:
        low = block.lower()
        if "nopass" in low or "open" in low:
            return "open"
        if "wpa3" in low:
            return "wpa3"
        if "wpa2" in low:
            return "wpa2"
        if "wpa" in low:
            return "wpa"
        if "owe" in low:
            return "owe"
        return "unknown"
