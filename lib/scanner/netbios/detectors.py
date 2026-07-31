#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetBIOS node status probe (NSE nbstat)."""

from __future__ import annotations

import socket
import struct
from typing import Dict, List


_SUFFIX_MAP = {
    0x00: "Workstation",
    0x03: "Messenger",
    0x20: "File Server",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Service Elections",
}


def _encode_netbios_name(name: str = "*", suffix: int = 0x00) -> bytes:
    """First-level NetBIOS encoding (32 bytes encoded + null)."""
    padded = (name.upper() + " " * 15)[:15] + chr(suffix)
    out = b""
    for ch in padded.encode("ascii", errors="replace"):
        out += bytes([((ch >> 4) & 0x0F) + 0x41, (ch & 0x0F) + 0x41])
    return out + b"\x00"


def probe_nbstat(host: str, port: int = 137, timeout: float = 3.0) -> Dict[str, object]:
    """UDP NetBIOS Node Status query (NBSTAT)."""
    result: Dict[str, object] = {
        "detected": False,
        "names": [],
        "mac": "",
        "error": "",
    }
    # NBNS header + question for '*' type NBSTAT (0x0021)
    txn = 0x1337
    header = struct.pack(">HHHHHH", txn, 0x0000, 1, 0, 0, 0)
    question = _encode_netbios_name("*", 0x00) + struct.pack(">HH", 0x0021, 0x0001)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, int(port)))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            result["error"] = "short_response"
            return result
        # Skip header (12) + question (~34) — find number of names
        # Response answer RR: after question, TYPE/CLASS/TTL/RDLEN then num_names
        # Question length = 1+32+1 + 4 = 38? encoded name is 32+1 null = 33 + 4 = 37 from offset 12
        q_end = 12 + 33 + 4  # name + type/class
        if len(data) < q_end + 12:
            result["error"] = "parse_failed"
            return result
        # RR: name pointer/name + type + class + ttl + rdlength
        # Often compression pointer 0xC00C
        pos = 12
        # skip question name
        if data[pos] == 0x20:  # length 32 encoded
            pos += 33
        else:
            pos = q_end - 4
        pos += 4  # type/class of question
        # answer name
        if pos < len(data) and data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            # skip labels
            while pos < len(data) and data[pos] != 0:
                if data[pos] & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += 1 + data[pos]
            else:
                pos += 1
        if pos + 10 > len(data):
            result["error"] = "rr_truncated"
            return result
        pos += 8  # type, class, ttl
        rdlength = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        rdata = data[pos : pos + rdlength]
        if not rdata:
            result["error"] = "empty_rdata"
            return result
        num = rdata[0]
        names: List[Dict[str, object]] = []
        off = 1
        for _ in range(num):
            if off + 18 > len(rdata):
                break
            raw_name = rdata[off : off + 15].decode("ascii", errors="ignore").strip()
            suffix = rdata[off + 15]
            flags = struct.unpack(">H", rdata[off + 16 : off + 18])[0]
            names.append(
                {
                    "name": raw_name,
                    "suffix": f"0x{suffix:02x}",
                    "type": _SUFFIX_MAP.get(suffix, "Unknown"),
                    "group": bool(flags & 0x8000),
                }
            )
            off += 18
        mac = ""
        if off + 6 <= len(rdata):
            mac = ":".join(f"{b:02x}" for b in rdata[off : off + 6])
        result["detected"] = True
        result["names"] = names
        result["mac"] = mac
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()
