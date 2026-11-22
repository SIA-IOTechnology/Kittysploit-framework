#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pure-Python 802.11 MPDU parser for monitor-mode captures."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from lib.protocols.wlan.eapol_const import EAPOL_TYPE_KEY, LLC_SNAP_EAPOL, MIC_LEN, NONCE_LEN
from lib.protocols.wlan.ie import parse_ds_channel, parse_ssid
from lib.protocols.wlan.mac import BROADCAST_MAC, mac_to_str
from lib.protocols.wlan.radiotap import strip_monitor_header
from lib.protocols.wlan.rsn import parse_beacon_security

_ZERO_NONCE = b"\x00" * NONCE_LEN
_RSN_PMKID_OUI = bytes.fromhex("000fac04")


@dataclass
class ParsedBeacon:
    bssid: str
    ssid: str
    channel: int | None
    rssi: int | None
    security: Any
    raw: bytes
    ies: bytes = b""


@dataclass
class ParsedProbeRequest:
    client: str
    target_bssid: str
    ssid: str
    wildcard: bool


@dataclass
class ParsedClientActivity:
    bssid: str
    client: str
    frame_type: str


@dataclass
class ParsedEapol:
    bssid: str
    station: str
    eapol: bytes
    eapol_key: bytes
    anonce: bytes
    snonce: bytes
    mic: bytes
    key_info: int
    to_ds: bool
    key_message: int
    pmkid: bytes = b""


@dataclass
class ParsedDeauth:
    bssid: str
    source: str
    dest: str
    reason: int
    disassoc: bool


class WlanFrameParser:
    TYPE_MGMT = 0
    TYPE_DATA = 2
    SUBTYPE_ASSOC_REQ = 0
    SUBTYPE_ASSOC_RESP = 1
    SUBTYPE_REASSOC_REQ = 2
    SUBTYPE_PROBE_REQ = 4
    SUBTYPE_PROBE_RESP = 5
    SUBTYPE_BEACON = 8
    SUBTYPE_DISASSOC = 10
    SUBTYPE_AUTH = 11
    SUBTYPE_DEAUTH = 12

    @classmethod
    def peel(cls, blob: bytes) -> bytes:
        return strip_monitor_header(blob)

    @classmethod
    def _fc(cls, frame: bytes) -> tuple[int, int, int, int]:
        fc0, fc1 = frame[0], frame[1]
        ftype = (fc0 & 0x0C) >> 2
        subtype = (fc0 & 0xF0) >> 4
        return ftype, subtype, fc0, fc1

    @classmethod
    def _addresses(cls, fc1: int, frame: bytes) -> tuple[str, str, str]:
        to_ds = bool(fc1 & 0x01)
        from_ds = bool(fc1 & 0x02)
        a1 = mac_to_str(frame[4:10])
        a2 = mac_to_str(frame[10:16])
        a3 = mac_to_str(frame[16:22])
        if not to_ds and not from_ds:
            return a1, a2, a3
        if not to_ds and from_ds:
            return a1, a3, a2
        if to_ds and not from_ds:
            return a2, a1, a3
        return a1, a2, a3

    @classmethod
    def _invalid_client_mac(cls, mac: str) -> bool:
        low = (mac or "").lower()
        return low in (mac_to_str(BROADCAST_MAC), "00:00:00:00:00:00", "")

    @classmethod
    def parse_beacon(cls, frame: bytes, rssi: int | None = None) -> ParsedBeacon | None:
        frame = cls.peel(frame)
        if len(frame) < 36:
            return None
        ftype, subtype, _, fc1 = cls._fc(frame)
        if ftype != cls.TYPE_MGMT or subtype != cls.SUBTYPE_BEACON:
            return None
        _, _, bssid = cls._addresses(fc1, frame)
        body_start = 24 + 8
        if body_start >= len(frame):
            return None
        ies = frame[body_start:]
        ssid = parse_ssid(ies)
        channel = parse_ds_channel(ies)
        security = parse_beacon_security(ies, ssid)
        security.channel = channel
        return ParsedBeacon(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            rssi=rssi,
            security=security,
            raw=frame,
            ies=ies,
        )

    @classmethod
    def parse_probe_request(cls, frame: bytes) -> ParsedProbeRequest | None:
        frame = cls.peel(frame)
        if len(frame) < 24:
            return None
        ftype, subtype, _, fc1 = cls._fc(frame)
        if ftype != cls.TYPE_MGMT or subtype != cls.SUBTYPE_PROBE_REQ:
            return None
        dest, client, _ = cls._addresses(fc1, frame)
        ssid = parse_ssid(frame[24:])
        wildcard = ssid == ""
        return ParsedProbeRequest(
            client=client,
            target_bssid=dest,
            ssid=ssid,
            wildcard=wildcard,
        )

    @classmethod
    def parse_client_activity(cls, frame: bytes) -> ParsedClientActivity | None:
        frame = cls.peel(frame)
        if len(frame) < 24:
            return None
        ftype, subtype, _, fc1 = cls._fc(frame)
        if ftype == cls.TYPE_MGMT:
            dest, source, bssid = cls._addresses(fc1, frame)
            if subtype == cls.SUBTYPE_PROBE_REQ:
                if dest.lower() == mac_to_str(BROADCAST_MAC):
                    return None
                return ParsedClientActivity(bssid=dest, client=source, frame_type="probe")
            if subtype in (cls.SUBTYPE_ASSOC_REQ, cls.SUBTYPE_REASSOC_REQ):
                return ParsedClientActivity(bssid=dest, client=source, frame_type="association")
            if subtype == cls.SUBTYPE_AUTH:
                return ParsedClientActivity(bssid=dest, client=source, frame_type="authentication")
            return None
        if ftype == cls.TYPE_DATA:
            to_ds = bool(fc1 & 0x01)
            from_ds = bool(fc1 & 0x02)
            if to_ds and not from_ds:
                bssid, client = mac_to_str(frame[4:10]), mac_to_str(frame[10:16])
                if not cls._invalid_client_mac(client):
                    return ParsedClientActivity(bssid=bssid, client=client, frame_type="data")
            elif from_ds and not to_ds:
                bssid, client = mac_to_str(frame[10:16]), mac_to_str(frame[4:10])
                if not cls._invalid_client_mac(client):
                    return ParsedClientActivity(bssid=bssid, client=client, frame_type="data")
        return None

    @classmethod
    def parse_deauth(cls, frame: bytes) -> ParsedDeauth | None:
        frame = cls.peel(frame)
        if len(frame) < 26:
            return None
        ftype, subtype, _, fc1 = cls._fc(frame)
        if ftype != cls.TYPE_MGMT:
            return None
        if subtype not in (cls.SUBTYPE_DEAUTH, cls.SUBTYPE_DISASSOC):
            return None
        dest, source, bssid = cls._addresses(fc1, frame)
        reason = struct.unpack("<H", frame[24:26])[0]
        return ParsedDeauth(
            bssid=bssid,
            source=source,
            dest=dest,
            reason=reason,
            disassoc=subtype == cls.SUBTYPE_DISASSOC,
        )

    @classmethod
    def _pmkid_from_key_data(cls, body: bytes) -> bytes:
        if len(body) < 99:
            return b""
        kd_len = struct.unpack(">H", body[97:99])[0]
        if kd_len < 22:
            return b""
        kd = body[99 : 99 + kd_len]
        idx = kd.find(_RSN_PMKID_OUI)
        while idx >= 0:
            start = idx + len(_RSN_PMKID_OUI)
            if start + 16 <= len(kd):
                pmkid = kd[start : start + 16]
                if pmkid != b"\x00" * 16:
                    return pmkid
            idx = kd.find(_RSN_PMKID_OUI, idx + 1)
        return b""

    @classmethod
    def _key_message_num(cls, key_info: int, to_ds: bool, has_mic: bool) -> int:
        secure = bool(key_info & 0x0200)
        if not has_mic:
            return 1
        if has_mic and to_ds and not secure:
            return 2
        if has_mic and not to_ds and secure:
            return 3
        if has_mic and to_ds and secure:
            return 4
        return 0

    @classmethod
    def parse_eapol(cls, frame: bytes) -> ParsedEapol | None:
        frame = cls.peel(frame)
        if len(frame) < 24:
            return None
        ftype, _, _, fc1 = cls._fc(frame)
        if ftype != cls.TYPE_DATA:
            return None
        to_ds = bool(fc1 & 0x01)
        from_ds = bool(fc1 & 0x02)
        if to_ds and not from_ds:
            bssid, station = mac_to_str(frame[4:10]), mac_to_str(frame[10:16])
        elif from_ds and not to_ds:
            bssid, station = mac_to_str(frame[10:16]), mac_to_str(frame[4:10])
        else:
            return None
        offset = 24
        idx = frame.find(LLC_SNAP_EAPOL, offset)
        if idx < 0:
            return None
        payload = frame[idx + len(LLC_SNAP_EAPOL) :]
        if len(payload) < 99 or payload[1] != EAPOL_TYPE_KEY:
            return None
        body = payload[4:]
        if len(body) < 99:
            return None
        key_info = struct.unpack(">H", body[1:3])[0]
        has_mic = bool(key_info & 0x0100)
        nonce = body[17 : 17 + NONCE_LEN]
        mic = body[81 : 81 + MIC_LEN]
        if to_ds:
            snonce, anonce = nonce, _ZERO_NONCE
        else:
            anonce, snonce = nonce, _ZERO_NONCE
        pmkid = cls._pmkid_from_key_data(body)
        return ParsedEapol(
            bssid=bssid,
            station=station,
            eapol=payload,
            eapol_key=body,
            anonce=anonce,
            snonce=snonce,
            mic=mic,
            key_info=key_info,
            to_ds=to_ds,
            key_message=cls._key_message_num(key_info, to_ds, has_mic),
            pmkid=pmkid,
        )