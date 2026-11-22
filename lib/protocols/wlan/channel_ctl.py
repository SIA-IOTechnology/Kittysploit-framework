#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Set monitor-interface channel via Linux wireless extensions (no iw/aircrack)."""

from __future__ import annotations

import platform
import socket
import struct
from typing import Optional

from lib.protocols.wlan.channels import channel_to_freq_mhz

# linux/wireless.h (ioctl numbers vary slightly; these match glibc x86_64 Linux)
SIOCSIWFREQ = 0x8B04
SIOCGIWFREQ = 0x8B05


def _linux_ioctl_freq(iface: str, freq_mhz: int) -> bool:
    """Set center frequency through SIOCSIWFREQ (wireless extensions)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # iw_freq: value = m * 10^e  (drivers commonly use m=freq MHz, e=6)
        ifreq = struct.pack(
            "16sHHII",
            iface.encode("utf-8")[:15],
            freq_mhz,
            6,
            0,
            0,
        )
        import fcntl

        fcntl.ioctl(sock.fileno(), SIOCSIWFREQ, ifreq)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def set_interface_channel(iface: str, channel: int) -> bool:
    """Best-effort channel change; Linux wireless-extensions only."""
    if platform.system() != "Linux":
        return False
    name = str(iface or "").strip()
    if not name or channel <= 0:
        return False
    mhz = channel_to_freq_mhz(channel)
    if mhz <= 0:
        return False
    return _linux_ioctl_freq(name, mhz)


def current_interface_channel(iface: str) -> Optional[int]:
    """Read approximate channel from frequency (Linux only)."""
    if platform.system() != "Linux":
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        import fcntl

        ifreq = bytearray(32)
        struct.pack_into("16s", ifreq, 0, iface.encode("utf-8")[:15])
        fcntl.ioctl(sock.fileno(), SIOCGIWFREQ, ifreq)
        freq_mhz, _exp, _, _ = struct.unpack_from("HHII", ifreq, 16)
        return freq_mhz if freq_mhz < 1000 else freq_mhz // 1000
    except OSError:
        return None
    finally:
        sock.close()