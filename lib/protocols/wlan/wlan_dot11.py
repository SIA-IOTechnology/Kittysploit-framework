#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 frame parsing and injection primitives — inherit ``Wlan_dot11`` in modules."""

from __future__ import annotations
from typing import Iterable
from core.framework.base_module import BaseModule
from lib.protocols.wlan.deauth import (
    build_client_deauth,
    build_deauth,
    deauth_nav_bytes,
    deauth_reason_label,
)
from lib.protocols.wlan.mgmt import build_beacon
from lib.protocols.wlan.ie import parse_ds_channel, parse_ssid
from lib.protocols.wlan.mac import BROADCAST_MAC, mac_to_str, random_client_mac, str_to_mac
from lib.protocols.wlan.parser import (
    ParsedBeacon,
    ParsedClientActivity,
    ParsedDeauth,
    ParsedEapol,
    ParsedProbeRequest,
    WlanFrameParser,
)
from lib.protocols.wlan.wps import WpsAccessPointInfo, wps_from_ies
from lib.protocols.wlan.radiotap import strip_monitor_header
from lib.protocols.wlan.rsn import SecurityInfo, parse_beacon_security


class Wlan_dot11(BaseModule):
    """
    Dot11 mixin — combine with :class:`Wlan_capture` or :class:`Wlan_client`.

    Example::

        class Module(Auxiliary, Wlan_client, Wlan_dot11):
            ...
    """

    def __init__(self, framework=None):
        super().__init__(framework)
        self._wlan_parser: WlanFrameParser | None = None

    def wlan_frame_parser(self) -> WlanFrameParser:
        if self._wlan_parser is None:
            self._wlan_parser = WlanFrameParser()
        return self._wlan_parser

    def wlan_strip_radiotap(self, frame: bytes) -> bytes:
        return strip_monitor_header(frame)

    def wlan_dot11_bssid(self, frame: bytes) -> str | None:
        if len(frame) < 10:
            return None
        try:
            _, _, bssid = WlanFrameParser._addresses(frame[1], frame)
            return bssid or None
        except Exception:
            return None

    def wlan_parse_beacon(self, raw: bytes, rssi: int | None = None) -> ParsedBeacon | None:
        return self.wlan_frame_parser().parse_beacon(raw, rssi=rssi)

    def wlan_parse_eapol(self, raw: bytes) -> ParsedEapol | None:
        return self.wlan_frame_parser().parse_eapol(raw)

    def wlan_parse_deauth(self, raw: bytes) -> ParsedDeauth | None:
        return self.wlan_frame_parser().parse_deauth(raw)

    def wlan_parse_probe_request(self, raw: bytes) -> ParsedProbeRequest | None:
        return self.wlan_frame_parser().parse_probe_request(raw)

    def wlan_parse_client_activity(self, raw: bytes) -> ParsedClientActivity | None:
        return self.wlan_frame_parser().parse_client_activity(raw)

    def wlan_deauth_reason(self, code: int) -> str:
        return deauth_reason_label(code)

    def wlan_parse_wps(self, ies: bytes, bssid: str, ssid: str = "") -> WpsAccessPointInfo | None:
        return wps_from_ies(ies, bssid, ssid)

    def wlan_wps_from_beacon(self, beacon: ParsedBeacon) -> WpsAccessPointInfo | None:
        return wps_from_ies(beacon.ies, beacon.bssid, beacon.ssid)

    def wlan_build_open_auth(self, bssid: str, sta: str) -> bytes:
        from lib.protocols.wlan.mgmt import build_open_auth_request

        return build_open_auth_request(bssid, sta)

    def wlan_build_assoc_request(
        self, bssid: str, sta: str, ssid: str, rsn_ie: bytes = b""
    ) -> bytes:
        from lib.protocols.wlan.ie import GENERIC_RSN_PSK_IE
        from lib.protocols.wlan.mgmt import build_association_request

        return build_association_request(bssid, sta, ssid, extra_ies=rsn_ie or GENERIC_RSN_PSK_IE)

    def wlan_parse_ssid(self, ies: bytes) -> str:
        return parse_ssid(ies)

    def wlan_parse_ds_channel(self, ies: bytes) -> int | None:
        return parse_ds_channel(ies)

    def wlan_parse_beacon_security(self, ies: bytes, ssid: str) -> SecurityInfo:
        return parse_beacon_security(ies, ssid)

    @staticmethod
    def wlan_mac_to_str(mac: bytes) -> str:
        return mac_to_str(mac)

    @staticmethod
    def wlan_str_to_mac(value: str | bytes) -> bytes:
        return str_to_mac(value)

    @staticmethod
    def wlan_random_sta_mac() -> bytes:
        return random_client_mac()

    def wlan_build_deauth_frame(
        self,
        a1: bytes,
        a2: bytes,
        a3: bytes,
        reason: int = 7,
        *,
        disassoc: bool = False,
    ) -> bytes:
        return build_deauth(a1, a2, a3, reason, disassoc=disassoc)

    def wlan_build_client_deauth(
        self,
        bssid: str,
        client: str,
        *,
        broadcast: bool = False,
        reason: int = 7,
    ) -> list[bytes]:
        return build_client_deauth(bssid, client, broadcast=broadcast, reason=reason)

    @staticmethod
    def wlan_deauth_nav(dest_mac: str | bytes) -> bytes:
        return deauth_nav_bytes(dest_mac)

    @staticmethod
    def wlan_broadcast_mac() -> bytes:
        return BROADCAST_MAC

    def wlan_build_beacon_frame(
        self,
        bssid: str,
        ssid: str,
        channel: int,
        *,
        open_network: bool = True,
        rsn_ie: bytes = b"",
    ) -> bytes:
        return build_beacon(bssid, ssid, channel, open_network=open_network, rsn_ie=rsn_ie)

    def wlan_flood_beacons(
        self,
        bssid: str,
        ssid: str,
        channel: int,
        *,
        duration: float = 30.0,
        interval: float = 0.1,
        open_network: bool = True,
        rsn_ie: bytes = b"",
        iface: str | None = None,
    ) -> int:
        """Inject beacon frames for ``duration`` seconds."""
        import time

        frame = self.wlan_build_beacon_frame(
            bssid, ssid, channel, open_network=open_network, rsn_ie=rsn_ie
        )
        sent = 0
        deadline = time.time() + max(1.0, float(duration))
        while time.time() < deadline:
            sent += self.wlan_inject_raw([frame], count=1, iface=iface)
            time.sleep(max(0.02, float(interval)))
        return sent