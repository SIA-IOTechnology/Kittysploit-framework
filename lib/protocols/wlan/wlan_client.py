#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Primary WLAN mixin — capture, dot11, survey, WPA, PCAP (combine in modules as needed).

Typical usage::

    class Module(Auxiliary, Wlan_client):
        ...

For offline-only workflows::

    class Module(Auxiliary, Wlan_dot11, Wlan_wpa, Wlan_pcap):
        ...
"""

from __future__ import annotations
import platform
from typing import Callable, Iterable
from core.framework.option import OptString
from core.output_handler import print_error, print_warning
from lib.protocols.wlan.capture import WlanCapture, resolve_scapy_iface, scapy_available
from lib.protocols.wlan.channel_ctl import set_interface_channel
from lib.protocols.wlan.wlan_dot11 import Wlan_dot11
from lib.protocols.wlan.wlan_pcap import Wlan_pcap
from lib.protocols.wlan.wlan_survey import Wlan_survey
from lib.protocols.wlan.wlan_wpa import Wlan_wpa
from lib.protocols.wlan.wlan_pmkid import Wlan_pmkid
from lib.protocols.wlan.wlan_vault import Wlan_vault
from lib.protocols.wlan.wlan_wep import Wlan_wep
from lib.protocols.wlan.wlan_wsc import Wlan_wsc


class Wlan_capture(Wlan_dot11):
    """Monitor interface I/O mixin — inherits dot11 helpers."""

    iface = OptString("wlan0mon", "Monitor-mode wireless interface", required=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._wlan_live: WlanCapture | None = None

    def wlan_scapy_available(self) -> bool:
        return scapy_available()

    def wlan_check_iface(self) -> bool:
        if not scapy_available():
            print_error("scapy is not installed (required for WLAN I/O).")
            return False
        requested = str(self.iface or "").strip()
        iface = resolve_scapy_iface(requested)
        if not iface:
            print_error("Interface name is required")
            return False
        if iface != requested:
            self.iface = iface
        try:
            from scapy.all import get_if_list

            if iface not in get_if_list():
                label = requested if requested != iface else iface
                print_warning(f"Interface {label} not in scapy interface list")
        except Exception:
            pass
        return True

    def wlan_open_capture(self, iface: str | None = None) -> WlanCapture:
        name = resolve_scapy_iface(str(iface or self.iface or "wlan0mon").strip())
        self._wlan_live = WlanCapture(name)
        return self._wlan_live

    def wlan_capture_client(self) -> WlanCapture:
        if self._wlan_live is None:
            return self.wlan_open_capture()
        return self._wlan_live

    def wlan_sniff(
        self,
        callback: Callable[[bytes, int | None], None],
        *,
        timeout: float = 30.0,
        stop_when: Callable[[], bool] | None = None,
        iface: str | None = None,
    ) -> None:
        self.wlan_open_capture(iface).sniff(callback, timeout=timeout, stop_when=stop_when)

    def wlan_inject_raw(self, frames: Iterable[bytes], count: int = 1, iface: str | None = None) -> int:
        return self.wlan_open_capture(iface).inject_raw(frames, count=count)

    def wlan_set_channel(self, channel: int, iface: str | None = None) -> bool:
        if platform.system() != "Linux":
            return False
        name = str(iface or self.iface or "wlan0mon").strip()
        ok = set_interface_channel(name, int(channel))
        if not ok:
            print_warning(
                f"Could not set channel {channel} on {name} "
                "(Linux wireless-extensions only; continue on current channel)"
            )
        return ok

    def wlan_sniff_channels(
        self,
        callback: Callable[[bytes, int | None], None],
        channels: list[int],
        *,
        dwell: float = 3.0,
        hop: bool = True,
        iface: str | None = None,
    ) -> None:
        """Sniff each channel for ``dwell`` seconds; optionally ioctl-hop (Linux)."""
        hop = bool(hop) and platform.system() == "Linux"
        for ch in channels:
            if hop:
                self.wlan_set_channel(ch, iface=iface)
            self.wlan_sniff(callback, timeout=float(dwell), iface=iface)


class Wlan_client(Wlan_capture, Wlan_survey, Wlan_wpa, Wlan_pcap, Wlan_pmkid, Wlan_wsc, Wlan_vault, Wlan_wep):
    """Full-stack WLAN mixin (live capture + recon + WPA + PCAP + PMKID + WPS + vault + WEP)."""