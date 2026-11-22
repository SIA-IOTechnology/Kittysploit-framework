#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP IV capture parsing from 802.11 data frames."""

from __future__ import annotations

from dataclasses import dataclass, field

from lib.protocols.wlan.mac import mac_to_str
from lib.protocols.wlan.radiotap import strip_monitor_header

_TYPE_DATA = 2


@dataclass
class WepSample:
    bssid: str
    station: str
    iv: bytes
    key_id: int
    ciphertext: bytes


@dataclass
class WepIvStore:
    samples: list[WepSample] = field(default_factory=list)
    _keys: set[str] = field(default_factory=set)

    def add(self, sample: WepSample) -> bool:
        token = sample.iv.hex() + sample.ciphertext[:8].hex()
        if token in self._keys:
            return False
        self._keys.add(token)
        self.samples.append(sample)
        return True

    @property
    def count(self) -> int:
        return len(self.samples)


def parse_wep_data(frame: bytes) -> WepSample | None:
    frame = strip_monitor_header(frame)
    if len(frame) < 24:
        return None
    ftype = (frame[0] & 0x0C) >> 2
    if ftype != _TYPE_DATA:
        return None
    protected = bool(frame[1] & 0x40)
    if not protected:
        return None
    fc1 = frame[1]
    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    a1 = frame[4:10]
    a2 = frame[10:16]
    a3 = frame[16:22]
    hdr_len = 24
    if to_ds or from_ds:
        hdr_len = 30
    if len(frame) < hdr_len + 8:
        return None
    body = frame[hdr_len:]
    iv = body[:3]
    key_id = body[3] & 0x03
    cipher = body[4:]
    if from_ds and not to_ds:
        bssid = a2
        sta = a1
    elif to_ds and not from_ds:
        bssid = a1
        sta = a2
    else:
        bssid = a3
        sta = a2
    return WepSample(
        bssid=mac_to_str(bssid),
        station=mac_to_str(sta),
        iv=iv,
        key_id=key_id,
        ciphertext=cipher,
    )