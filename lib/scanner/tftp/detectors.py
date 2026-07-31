#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TFTP file existence enum (NSE tftp-enum)."""

from __future__ import annotations

import socket
import struct
from typing import Dict, List


DEFAULT_TFTP_FILES = (
    "startup-config",
    "running-config",
    "cisco.cfg",
    "router.cfg",
    "switch.cfg",
    "config",
    "config.bin",
    "config.txt",
    "backup.cfg",
    "passwd",
    "passwd.bak",
    "pxelinux.0",
    "boot.ini",
    "winnt/system32/drivers/etc/hosts",
)


def probe_tftp_enum(
    host: str,
    port: int = 69,
    timeout: float = 3.0,
    files: List[str] | None = None,
) -> Dict[str, object]:
    """
    Send TFTP RRQ for common filenames. DATA/OACK => exists; ERROR code 1 => missing.
    """
    result: Dict[str, object] = {
        "detected": False,
        "existing": [],
        "errors": [],
        "error": "",
    }
    existing: List[str] = []
    for name in files or list(DEFAULT_TFTP_FILES):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            # RRQ: opcode 1 + filename + 0 + mode + 0
            pkt = struct.pack("!H", 1) + name.encode("ascii", errors="ignore") + b"\x00octet\x00"
            sock.sendto(pkt, (host, int(port)))
            data, _ = sock.recvfrom(516)
            if len(data) < 2:
                continue
            opcode = struct.unpack("!H", data[:2])[0]
            result["detected"] = True
            if opcode in (3, 6):  # DATA or OACK
                existing.append(name)
            elif opcode == 5 and len(data) >= 4:
                err = struct.unpack("!H", data[2:4])[0]
                # 1 = file not found — service up
                if err != 1:
                    result["errors"].append({"file": name, "code": err})
        except socket.timeout:
            continue
        except Exception as exc:
            result["error"] = str(exc)[:120]
        finally:
            sock.close()
    result["existing"] = existing
    return result
