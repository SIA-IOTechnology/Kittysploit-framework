#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse Registry.pol binary policy files."""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

_MAGIC = b"\x50\x52\x65\x67\x01\x00\x00\x00"
_REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def _value_to_string(reg_type: str, keyvalue: str) -> str:
    hex_str = keyvalue[2:] if keyvalue.upper().startswith("0X") else keyvalue
    try:
        if reg_type in {"REG_DWORD", "REG_QWORD"}:
            return str(int(hex_str, 16))
        if reg_type in {"REG_SZ", "REG_EXPAND_SZ"}:
            raw = bytes.fromhex(hex_str)
            return raw.decode("utf-8", errors="replace").replace("\x00", "")[::-1]
        if reg_type == "REG_MULTI_SZ":
            raw = bytes.fromhex(hex_str)
            return raw.decode("utf-8", errors="replace").replace("\x00\x00\x00", ",").replace("\x00", "")[::-1]
    except ValueError:
        pass
    return keyvalue


def parse_registry_pol(data: bytes, policy_type: str = "Machine") -> Optional[Dict[str, Any]]:
    """Return normalized registry entries from a Registry.pol blob."""
    if not data or not data.startswith(_MAGIC):
        return None

    hive = "HKEY_CURRENT_USER" if policy_type.lower() == "user" else "HKEY_LOCAL_MACHINE"
    entries: List[Dict[str, str]] = []
    body = data[len(_MAGIC):]

    while body:
        if body[:2] != b"[\x00":
            break
        body = body[2:]

        key, _, body = body.partition(b";\x00")
        value_name, _, body = body.partition(b";\x00")
        key = key.decode("utf-16-le", errors="ignore").strip("\x00")
        value_name = value_name.decode("utf-16-le", errors="ignore").strip("\x00")

        reg_type_raw = struct.unpack("<I", body[:4])[0]
        body = body[6:]
        reg_type = _REG_TYPES.get(reg_type_raw, "REG_BINARY")

        size = struct.unpack("<I", body[:4])[0]
        body = body[6:]
        raw = body[:size]
        body = body[size:]
        data_value = _value_to_string(reg_type, f"0x{int.from_bytes(raw, 'little'):08X}")

        entries.append({
            "Hive": hive,
            "Key": f"{key}\\{value_name}" if value_name else key,
            "Type": reg_type,
            "Data": data_value,
        })

        if not body or body[:2] != b"]\x00":
            break
        body = body[2:]

    if not entries:
        return None
    return {"registry.pol": entries}
