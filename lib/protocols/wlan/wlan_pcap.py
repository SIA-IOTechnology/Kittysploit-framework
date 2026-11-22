#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PCAP / PCAPNG helpers — inherit ``Wlan_pcap`` in modules."""

from __future__ import annotations
from pathlib import Path
from typing import Iterator
from core.framework.base_module import BaseModule
from lib.protocols.wlan.pcap_io import iter_pcap_packets, write_pcap


class Wlan_pcap(BaseModule):
    """Offline capture file I/O mixin."""

    @staticmethod
    def wlan_iter_pcap(path: str | Path) -> Iterator[bytes]:
        return iter_pcap_packets(path)

    @staticmethod
    def wlan_write_pcap(path: str | Path, packets: list[bytes]) -> Path:
        return write_pcap(path, packets)