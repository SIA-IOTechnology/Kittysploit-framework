#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Track EAPOL 4-way exchanges and export crackable hash lines."""

from __future__ import annotations

from dataclasses import dataclass, field

from lib.protocols.wlan.eapol_const import MIC_LEN, NONCE_LEN
from lib.protocols.wlan.eapol_export import select_eapol_export
from lib.protocols.wlan.ft import eapol_is_fast_transition
from lib.protocols.wlan.hc22000 import Hc22000Line, eapol_hashline, pmkid_hashline

_ZERO_NONCE = b"\x00" * NONCE_LEN
_FULL_EAPOL_KEY = MIC_LEN + 81


@dataclass
class EapolKeyMessage:
    bssid: str
    station: str
    anonce: bytes
    snonce: bytes
    eapol: bytes
    eapol_key: bytes
    mic: bytes
    to_ds: bool
    key_info: int
    key_message: int = 0
    pmkid: bytes = b""


@dataclass
class HandshakeState:
    bssid: str
    station: str
    messages: dict[int, EapolKeyMessage] = field(default_factory=dict)

    def message_mask(self) -> int:
        mask = 0
        for n in self.messages:
            if 1 <= n <= 4:
                mask |= 1 << (n - 1)
        return mask

    def label(self) -> str:
        parts = [f"M{n}" for n in sorted(self.messages) if 1 <= n <= 4]
        return "+".join(parts) if parts else "none"


class HandshakeTracker:
    def __init__(self) -> None:
        self._states: dict[tuple[str, str], HandshakeState] = {}
        self._pmkid: dict[tuple[str, str], bytes] = {}
        self.pmkids: list[tuple[str, str, str, bytes]] = []

    def _state(self, bssid: str, station: str) -> HandshakeState:
        key = (bssid, station)
        if key not in self._states:
            self._states[key] = HandshakeState(bssid=bssid, station=station)
        return self._states[key]

    def ingest(self, msg: EapolKeyMessage, ssid_by_bssid: dict[str, str]) -> None:
        key = (msg.bssid, msg.station)
        km = msg.key_message or self._infer_key_message(msg)

        if km in (1, 2, 3, 4):
            st = self._state(msg.bssid, msg.station)
            if km == 2 and not self._valid_mic_frame(msg):
                pass
            else:
                st.messages[km] = msg
        elif km == 0 and self._valid_mic_frame(msg) and msg.to_ds:
            st = self._state(msg.bssid, msg.station)
            if any(msg.snonce):
                st.messages.setdefault(2, msg)

        if km == 1 and any(msg.anonce):
            self._pmkid.setdefault(key, b"")
            if msg.pmkid:
                self._pmkid[key] = msg.pmkid

        ssid = ssid_by_bssid.get(msg.bssid, "")
        pmkid = msg.pmkid or self._pmkid.get(key, b"")
        if pmkid and ssid and len(pmkid) == 16:
            entry = (ssid, msg.bssid, msg.station, pmkid)
            if entry not in self.pmkids:
                self.pmkids.append(entry)

    @staticmethod
    def _valid_mic_frame(msg: EapolKeyMessage) -> bool:
        return len(msg.eapol_key) >= _FULL_EAPOL_KEY and msg.mic != b"\x00" * MIC_LEN

    @staticmethod
    def _infer_key_message(msg: EapolKeyMessage) -> int:
        has_mic = bool(msg.key_info & 0x0100)
        secure = bool(msg.key_info & 0x0200)
        if not has_mic:
            return 1
        if has_mic and msg.to_ds and not secure:
            return 2
        if has_mic and not msg.to_ds and secure:
            return 3
        if has_mic and msg.to_ds and secure:
            return 4
        return 0

    def summaries(self) -> list[dict]:
        rows: list[dict] = []
        for (bssid, station), st in self._states.items():
            export = select_eapol_export(st.messages)
            ft = any(eapol_is_fast_transition(m.key_info) for m in st.messages.values())
            rows.append(
                {
                    "bssid": bssid,
                    "station": station,
                    "messages": st.label(),
                    "mask": st.message_mask(),
                    "exportable": export is not None,
                    "message_pair": export.message_pair if export else "",
                    "export_label": export.label if export else "",
                    "fast_transition": ft,
                }
            )
        return rows

    def export_hc22000(self, ssid_by_bssid: dict[str, str]) -> list[Hc22000Line]:
        out: list[Hc22000Line] = []
        seen_pairs: set[tuple[str, str]] = set()
        for (bssid, station), st in self._states.items():
            ssid = ssid_by_bssid.get(bssid, "")
            if not ssid:
                continue
            if (bssid, station) in seen_pairs:
                continue
            chosen = select_eapol_export(st.messages)
            if not chosen:
                continue
            out.append(
                eapol_hashline(
                    ssid,
                    bssid,
                    station,
                    chosen.anonce,
                    chosen.eapol_key,
                    chosen.mic,
                    message_pair=chosen.message_pair,
                )
            )
            seen_pairs.add((bssid, station))
        for ssid, bssid, station, pmkid in self.pmkids:
            out.append(pmkid_hashline(ssid, bssid, station, pmkid))
        return out