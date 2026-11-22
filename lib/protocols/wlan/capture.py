#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live monitor-mode capture and frame injection (scapy backend)."""

from __future__ import annotations

import time
from typing import Callable, Iterable

from lib.protocols.wlan.radiotap import strip_monitor_header


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401

        return True
    except ImportError:
        return False


def resolve_scapy_iface(requested: str) -> str:
    """Map a friendly OS adapter name to the scapy/Npcap device id when possible."""
    raw = str(requested or "").strip()
    if not raw or not scapy_available():
        return raw
    if raw.startswith("\\Device\\NPF") or (raw.startswith("{") and "}" in raw):
        return raw
    try:
        from scapy.all import conf, get_if_list

        names = list(get_if_list() or [])
        if raw in names:
            return raw
        needle = raw.lower()
        best = ""
        best_score = -1
        for name in names:
            row = conf.ifaces.get(name)
            desc = str(getattr(row, "description", "") or getattr(row, "network_name", "") or "")
            ip_desc = str(getattr(row, "ips", "") or "")
            hay = f"{name} {desc} {ip_desc}".lower()
            score = 0
            if needle == desc.lower() or needle == name.lower():
                score = 100
            elif needle in desc.lower():
                score = 80
            elif desc.lower() in needle:
                score = 70
            elif needle in hay:
                score = 50
            token = needle.split()[0] if needle.split() else ""
            if token and token in desc.lower() and "npf" in name.lower():
                score = max(score, 60)
            if score > best_score:
                best_score = score
                best = name
        return best or raw
    except Exception:
        return raw


class WlanCapture:
    """Standalone capture/inject client (same role as ``MqttTlsClient`` / ``CoapClient``)."""

    def __init__(self, iface: str) -> None:
        self.iface = str(iface or "").strip()

    def sniff(
        self,
        callback: Callable[[bytes, int | None], None],
        *,
        timeout: float = 30.0,
        stop_when: Callable[[], bool] | None = None,
    ) -> None:
        if not scapy_available():
            raise RuntimeError("scapy is required for live WLAN capture (pip install scapy)")
        from scapy.all import sniff

        end = time.time() + max(0.1, float(timeout))

        def handler(pkt) -> None:
            if stop_when and stop_when():
                return
            raw = bytes(pkt)
            if pkt.haslayer("RadioTap"):
                try:
                    raw = bytes(pkt["RadioTap"].payload)
                except Exception:
                    raw = strip_monitor_header(raw)
            elif pkt.haslayer("Dot11"):
                raw = bytes(pkt["Dot11"])
            else:
                raw = strip_monitor_header(raw)
            rssi = None
            if pkt.haslayer("RadioTap"):
                try:
                    rssi = int(pkt["RadioTap"].dBm_AntSignal)
                except Exception:
                    rssi = None
            callback(raw, rssi)

        sniff(
            iface=self.iface,
            prn=handler,
            timeout=max(0.0, end - time.time()),
            store=False,
            stop_filter=lambda _: bool(stop_when and stop_when()),
        )

    def inject_raw(self, frames: Iterable[bytes], count: int = 1) -> int:
        if not scapy_available():
            raise RuntimeError("scapy is required for frame injection")
        from scapy.all import RadioTap, Raw, sendp

        sent = 0
        for _ in range(max(1, count)):
            for frame in frames:
                pkt = RadioTap() / Raw(load=frame)
                sendp(pkt, iface=self.iface, verbose=False)
                sent += 1
        return sent