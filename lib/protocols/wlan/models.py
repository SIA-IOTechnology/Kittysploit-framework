#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class AccessPointRecord:
    bssid: str
    ssid: str = ""
    channel: int | None = None
    rssi: int | None = None
    encryption: str = "unknown"
    clients: Set[str] = field(default_factory=set)
    pmf: bool = False
    wps: bool = False
    hidden: bool = False
    vendor: str = ""
    beacons: int = 0

    def merge(self, other: "AccessPointRecord") -> None:
        if other.ssid and (not self.ssid or self.hidden):
            self.ssid = other.ssid
            self.hidden = False
        if other.channel is not None:
            self.channel = other.channel
        if other.rssi is not None:
            self.rssi = other.rssi
        if other.encryption != "unknown":
            self.encryption = other.encryption
        self.clients |= other.clients
        self.pmf = self.pmf or other.pmf
        self.wps = self.wps or other.wps
        self.vendor = other.vendor or self.vendor
        self.beacons += other.beacons


@dataclass
class ClientRecord:
    mac: str
    probed_ssids: Set[str] = field(default_factory=set)
    associated_bssid: str = ""
    last_rssi: int | None = None


@dataclass
class HandshakeCapture:
    bssid: str
    station: str
    ssid: str
    eapol_m2: bytes = b""
    anonce: bytes = b""
    snonce: bytes = b""
    mic: bytes = b""
    pmkid: bytes = b""
    packets: list[bytes] = field(default_factory=list)


class WlanScanState:
    """In-memory AP / client tables for live WLAN surveys."""

    def __init__(self) -> None:
        self.aps: Dict[str, AccessPointRecord] = {}
        self.clients: Dict[str, ClientRecord] = {}
        self.handshakes: Dict[tuple[str, str], HandshakeCapture] = {}

    def upsert_ap(self, rec: AccessPointRecord) -> AccessPointRecord:
        cur = self.aps.get(rec.bssid)
        if cur is None:
            self.aps[rec.bssid] = rec
            return rec
        cur.merge(rec)
        return cur

    def note_client(self, mac: str, bssid: str = "", ssid_probe: str = "", rssi: int | None = None) -> None:
        cli = self.clients.setdefault(mac, ClientRecord(mac=mac))
        if bssid:
            cli.associated_bssid = bssid
        if ssid_probe:
            cli.probed_ssids.add(ssid_probe)
        if rssi is not None:
            cli.last_rssi = rssi