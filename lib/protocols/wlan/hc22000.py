#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Hashcat mode 22000 hash-line parsing and emission (WPA-PSK / PMKID)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lib.protocols.wlan.mac import str_to_mac


@dataclass(frozen=True)
class Hc22000Line:
    kind: str
    pmkid_or_mic: str
    mac_ap: str
    mac_sta: str
    essid: str
    anonce: str = ""
    eapol: str = ""
    message_pair: str = "00"

    @property
    def is_pmkid(self) -> bool:
        return self.kind in ("01", "03")

    @property
    def ssid(self) -> str:
        try:
            return bytes.fromhex(self.essid).decode("utf-8", errors="replace")
        except ValueError:
            return ""

    def serialize(self) -> str:
        base = (
            f"WPA*{self.kind}*{self.pmkid_or_mic}*{self.mac_ap}*{self.mac_sta}*{self.essid}"
        )
        if self.is_pmkid:
            return f"{base}***{self.message_pair}"
        return f"{base}*{self.anonce}*{self.eapol}*{self.message_pair}"


def mac_compact(mac: str) -> str:
    return str(mac or "").replace(":", "").lower()


def ssid_hex(ssid: str) -> str:
    return ssid.encode("utf-8", errors="surrogateescape").hex()


def eapol_hashline(
    ssid: str,
    bssid: str,
    station: str,
    anonce: bytes,
    eapol: bytes,
    mic: bytes,
    message_pair: str = "00",
) -> Hc22000Line:
    zeroed = eapol[:81] + b"\x00" * 16 + eapol[97:] if len(eapol) > 97 else eapol
    return Hc22000Line(
        kind="02",
        pmkid_or_mic=mic.hex(),
        mac_ap=mac_compact(bssid),
        mac_sta=mac_compact(station),
        essid=ssid_hex(ssid),
        anonce=anonce.hex(),
        eapol=zeroed.hex(),
        message_pair=message_pair,
    )


def pmkid_hashline(ssid: str, bssid: str, station: str, pmkid: bytes) -> Hc22000Line:
    return Hc22000Line(
        kind="01",
        pmkid_or_mic=pmkid.hex(),
        mac_ap=mac_compact(bssid),
        mac_sta=mac_compact(station),
        essid=ssid_hex(ssid),
    )


def parse_hc22000_line(line: str) -> Hc22000Line | None:
    line = line.strip()
    if not line.startswith("WPA*"):
        return None
    parts = line.split("*")
    if len(parts) < 6:
        return None
    kind = parts[1]
    return Hc22000Line(
        kind=kind,
        pmkid_or_mic=parts[2],
        mac_ap=parts[3],
        mac_sta=parts[4],
        essid=parts[5],
        anonce=parts[6] if len(parts) > 6 else "",
        eapol=parts[7] if len(parts) > 7 else "",
        message_pair=parts[8] if len(parts) > 8 else "",
    )


def write_hc22000_file(path: str | Path, lines: list[Hc22000Line]) -> Path:
    out = Path(path)
    out.write_text("\n".join(line.serialize() for line in lines) + "\n", encoding="utf-8")
    return out