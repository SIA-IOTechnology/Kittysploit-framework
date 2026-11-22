#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Recon aggregation (AP tables, channels, vendors) — inherit ``Wlan_survey``."""

from __future__ import annotations
from core.framework.base_module import BaseModule
from lib.protocols.wlan.channels import channel_to_freq_mhz, default_channels, scan_hop_order
from lib.protocols.wlan.models import AccessPointRecord, ClientRecord, HandshakeCapture, WlanScanState
from lib.protocols.wlan.parser import ParsedBeacon
from lib.protocols.wlan.vendor import vendor_for_mac


class Wlan_survey(BaseModule):
    """Scanner state and channel-plan helpers."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self._wlan_scan_state: WlanScanState | None = None

    def wlan_scan_state(self) -> WlanScanState:
        if self._wlan_scan_state is None:
            self._wlan_scan_state = WlanScanState()
        return self._wlan_scan_state

    def wlan_reset_scan_state(self) -> WlanScanState:
        self._wlan_scan_state = WlanScanState()
        return self._wlan_scan_state

    @staticmethod
    def wlan_vendor(mac: str) -> str:
        return vendor_for_mac(mac)

    @staticmethod
    def wlan_default_channels(five_ghz: bool = True) -> list[int]:
        return default_channels(five_ghz)

    @staticmethod
    def wlan_scan_hop_order(channels: list[int]) -> list[int]:
        return scan_hop_order(channels)

    @staticmethod
    def wlan_channel_freq_mhz(channel: int) -> int:
        return channel_to_freq_mhz(channel)

    def wlan_ap_from_beacon(self, beacon: ParsedBeacon) -> AccessPointRecord:
        """Build an :class:`AccessPointRecord` from a parsed beacon (internal model)."""
        sec = beacon.security
        return AccessPointRecord(
            bssid=beacon.bssid,
            ssid=beacon.ssid or "<hidden>",
            channel=beacon.channel,
            rssi=beacon.rssi,
            encryption=sec.encryption,
            pmf=sec.pmf_required,
            wps=sec.wps,
            hidden=not beacon.ssid,
            vendor=self.wlan_vendor(beacon.bssid),
            beacons=1,
        )

    def wlan_register_beacon(self, beacon: ParsedBeacon) -> AccessPointRecord:
        """Upsert a beacon into :meth:`wlan_scan_state` and return the merged AP row."""
        return self.wlan_scan_state().upsert_ap(self.wlan_ap_from_beacon(beacon))

    def wlan_note_beacon_ssid(self, beacon: ParsedBeacon, ssid_by_bssid: dict[str, str]) -> None:
        """Track BSSID→SSID for handshake export when SSID is visible in beacons."""
        if beacon.ssid:
            ssid_by_bssid[beacon.bssid] = beacon.ssid

    def wlan_register_client(
        self,
        bssid: str,
        client: str,
        *,
        frame_type: str = "",
        ssid_probe: str = "",
        rssi: int | None = None,
    ) -> None:
        """Record client MAC activity in :meth:`wlan_scan_state`."""
        self.wlan_scan_state().note_client(client, bssid=bssid, ssid_probe=ssid_probe, rssi=rssi)
        ap = self.wlan_scan_state().aps.get(bssid)
        if ap is not None:
            ap.clients.add(client)