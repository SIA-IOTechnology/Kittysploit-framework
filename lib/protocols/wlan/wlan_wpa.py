#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPA/WPA2-PSK cracking and hash export — inherit ``Wlan_wpa`` in modules."""

from __future__ import annotations
from pathlib import Path
from typing import Callable, Iterable, Iterator
from core.framework.base_module import BaseModule
from lib.protocols.wlan.crack import WpaCpuCracker, try_password_against_line
from lib.protocols.wlan.handshake_tracker import EapolKeyMessage, HandshakeTracker
from lib.protocols.wlan.parser import ParsedEapol
from lib.protocols.wlan.hc22000 import Hc22000Line, eapol_hashline, parse_hc22000_line, pmkid_hashline, write_hc22000_file
from lib.protocols.wlan.wordlist import merge_wordlists, ssid_variants
from lib.protocols.wlan.wpa_crypto import (
    derive_pmk,
    derive_ptk,
    is_valid_psk,
    pmkid_from_psk,
    verify_eapol_mic,
)


class Wlan_wpa(BaseModule):
    """WPA mixin — offline crack and handshake aggregation (no live capture required)."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self._wlan_handshake_tracker: HandshakeTracker | None = None

    def wlan_handshake_tracker(self) -> HandshakeTracker:
        if self._wlan_handshake_tracker is None:
            self._wlan_handshake_tracker = HandshakeTracker()
        return self._wlan_handshake_tracker

    def wlan_reset_handshake_tracker(self) -> HandshakeTracker:
        self._wlan_handshake_tracker = HandshakeTracker()
        return self._wlan_handshake_tracker

    def wlan_track_eapol(
        self,
        msg: EapolKeyMessage,
        ssid_by_bssid: dict[str, str],
    ) -> None:
        self.wlan_handshake_tracker().ingest(msg, ssid_by_bssid)

    def wlan_track_parsed_eapol(self, eap: ParsedEapol, ssid_by_bssid: dict[str, str]) -> None:
        """Feed a :class:`ParsedEapol` from :meth:`Wlan_dot11.wlan_parse_eapol` into the tracker."""
        self.wlan_track_eapol(
            EapolKeyMessage(
                bssid=eap.bssid,
                station=eap.station,
                anonce=eap.anonce,
                snonce=eap.snonce,
                eapol=eap.eapol,
                eapol_key=eap.eapol_key,
                mic=eap.mic,
                to_ds=eap.to_ds,
                key_info=eap.key_info,
                key_message=eap.key_message,
                pmkid=eap.pmkid,
            ),
            ssid_by_bssid,
        )

    def wlan_export_hc22000(self, ssid_by_bssid: dict[str, str]) -> list[Hc22000Line]:
        return self.wlan_handshake_tracker().export_hc22000(ssid_by_bssid)

    def wlan_handshake_summaries(self) -> list[dict]:
        return self.wlan_handshake_tracker().summaries()

    def wlan_write_hc22000(self, path: str | Path, lines: list[Hc22000Line]) -> Path:
        return write_hc22000_file(path, lines)

    @staticmethod
    def wlan_parse_hc22000_line(line: str) -> Hc22000Line | None:
        return parse_hc22000_line(line)

    @staticmethod
    def wlan_eapol_hashline(
        ssid: str,
        bssid: str,
        station: str,
        anonce: bytes,
        eapol: bytes,
        mic: bytes,
        message_pair: str = "00",
    ) -> Hc22000Line:
        return eapol_hashline(ssid, bssid, station, anonce, eapol, mic, message_pair)

    @staticmethod
    def wlan_pmkid_hashline(ssid: str, bssid: str, station: str, pmkid: bytes) -> Hc22000Line:
        return pmkid_hashline(ssid, bssid, station, pmkid)

    def wlan_open_cracker(self, hash_path: str | Path) -> WpaCpuCracker:
        return WpaCpuCracker.from_file(hash_path)

    def wlan_crack_hashes(
        self,
        hash_path: str | Path,
        passwords: Iterable[str],
        *,
        on_progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, str]:
        return self.wlan_open_cracker(hash_path).crack(passwords, on_progress=on_progress)

    @staticmethod
    def wlan_try_password(password: str, line: Hc22000Line) -> bool:
        return try_password_against_line(password, line)

    @staticmethod
    def wlan_iter_wordlist(path: str | Path) -> Iterator[str]:
        return WpaCpuCracker.iter_wordlist(path)

    @staticmethod
    def wlan_ssid_wordlist_variants(ssid: str) -> list[str]:
        return ssid_variants(ssid)

    @staticmethod
    def wlan_merge_wordlists(*sources: Iterable[str]) -> list[str]:
        return merge_wordlists(*sources)

    @staticmethod
    def wlan_derive_pmk(psk: str, ssid: bytes) -> bytes:
        return derive_pmk(psk, ssid)

    @staticmethod
    def wlan_is_valid_psk(psk: str) -> bool:
        return is_valid_psk(psk)