#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Boot key (SYSKEY) from Windows LSA class values or an offline SYSTEM hive.
"""

from __future__ import annotations

import re
import struct
from typing import List, Optional

LSA_CLASS_VALUE_NAMES = ("JD", "Skew1", "GBG", "Data")
_BOOTKEY_DESCRAMBLE = (0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7)

_HEX_TOKEN = re.compile(r"^[0-9A-Fa-f]{1,2}$")


def descramble_bootkey(parts: List[bytes]) -> bytes:
    """Combine four 4-byte LSA fragments into the 16-byte boot key."""
    if len(parts) < 4:
        raise ValueError("need four LSA class value blobs")
    raw = bytearray(16)
    for i in range(16):
        part_idx = i // 4
        byte_idx = i % 4
        chunk = parts[part_idx]
        if byte_idx >= len(chunk):
            raise ValueError("LSA value too short for boot key")
        raw[_BOOTKEY_DESCRAMBLE[i]] = chunk[byte_idx]
    return bytes(raw)


def parse_reg_query_binary(output: str, value_name: str) -> Optional[bytes]:
    """Parse ``reg query`` output for a REG_BINARY value (multi-line hex)."""
    if not output:
        return None
    want = value_name.strip().lower()
    lines = output.splitlines()
    collecting = False
    hex_parts: List[str] = []

    def flush() -> Optional[bytes]:
        if not hex_parts:
            return None
        try:
            return bytes.fromhex("".join(hex_parts))
        except ValueError:
            return None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if collecting:
                return flush()
            continue

        if "REG_" in stripped and not collecting:
            tokens = stripped.split()
            if len(tokens) < 2:
                continue
            name = tokens[0].lower()
            reg_type = tokens[1].upper()
            if name != want:
                continue
            if reg_type != "REG_BINARY":
                return None
            collecting = True
            for tok in tokens[2:]:
                if _HEX_TOKEN.match(tok):
                    hex_parts.append(tok.zfill(2) if len(tok) == 1 else tok)
            continue

        if collecting:
            if "REG_" in stripped and not stripped.lower().startswith(want):
                return flush()
            for tok in stripped.replace("\\", " ").split():
                if _HEX_TOKEN.match(tok):
                    hex_parts.append(tok.zfill(2) if len(tok) == 1 else tok)
                elif tok and not tok.startswith("\\"):
                    return flush()

    return flush() if collecting else None


def bootkey_from_lsa_parts(parts: List[bytes]) -> bytes:
    return descramble_bootkey(parts)


def bootkey_from_system_hive(hive: bytes) -> bytes:
    """Extract boot key from a saved ``HKLM\\SYSTEM`` hive file."""
    try:
        from impacket.examples.secretsdump import LocalOperations

        import tempfile
        import os

        fd, path = tempfile.mkstemp(suffix=".save")
        os.close(fd)
        try:
            with open(path, "wb") as f:
                f.write(hive)
            return LocalOperations(path).getBootKey()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    except ImportError:
        pass

    parser = _HiveParser(hive)
    current = parser.get_dword(r"Select", "Current")
    if current is None:
        current = 1
    base = rf"ControlSet{current:03d}\Control\Lsa"
    parts: List[bytes] = []
    for name in LSA_CLASS_VALUE_NAMES:
        data = parser.get_value_data(base, name)
        if not data or len(data) < 4:
            raise ValueError(f"missing LSA value {name} in SYSTEM hive")
        parts.append(data[:4])
    return descramble_bootkey(parts)


class _HiveParser:
    """Minimal offline registry hive reader (SYSTEM boot key only)."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 0x1000 or data[:4] != b"regf":
            raise ValueError("not a registry hive")
        self._data = data
        self._base = 0x1000
        root_off = struct.unpack_from("<I", data, 0x20)[0]
        self._root = self._base + root_off

    def get_dword(self, key_path: str, value_name: str) -> Optional[int]:
        raw = self.get_value_data(key_path, value_name)
        if raw is None or len(raw) < 4:
            return None
        return struct.unpack("<I", raw[:4])[0]

    def get_value_data(self, key_path: str, value_name: str) -> Optional[bytes]:
        key_off = self._open_key_path(key_path)
        if key_off is None:
            return None
        nk = self._read_nk(key_off)
        for vk_off in self._value_list(nk):
            vk = self._read_vk(vk_off)
            if vk["name"].lower() == value_name.lower():
                return vk["data"]
        return None

    def _open_key_path(self, path: str) -> Optional[int]:
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        off = self._root
        for part in parts:
            child = self._find_subkey(off, part)
            if child is None:
                return None
            off = child
        return off

    def _find_subkey(self, nk_off: int, name: str) -> Optional[int]:
        nk = self._read_nk(nk_off)
        for sub_off in self._subkey_list(nk):
            sub = self._read_nk(sub_off)
            if sub["name"].lower() == name.lower():
                return sub_off
        return None

    def _read_nk(self, offset: int) -> dict:
        d = self._data
        if offset + 0x50 > len(d):
            raise ValueError("nk out of range")
        name_len = struct.unpack_from("<H", d, offset + 0x48)[0]
        name = d[offset + 0x4C : offset + 0x4C + name_len].decode("latin-1", errors="replace")
        return {
            "name": name,
            "subkeys_count": struct.unpack_from("<I", d, offset + 0x14)[0],
            "subkeys_list": struct.unpack_from("<I", d, offset + 0x1C)[0],
            "values_count": struct.unpack_from("<I", d, offset + 0x18)[0],
            "values_list": struct.unpack_from("<I", d, offset + 0x2C)[0],
        }

    def _subkey_list(self, nk: dict) -> List[int]:
        if nk["subkeys_count"] == 0:
            return []
        lf_off = self._base + nk["subkeys_list"]
        sig = self._data[lf_off : lf_off + 2]
        if sig in (b"lf", b"lh", b"ri"):
            return self._list_entries(lf_off)
        return []

    def _value_list(self, nk: dict) -> List[int]:
        if nk["values_count"] == 0:
            return []
        return self._list_entries(self._base + nk["values_list"])

    def _list_entries(self, list_off: int) -> List[int]:
        d = self._data
        sig = d[list_off : list_off + 2]
        if sig == b"ri":
            count = struct.unpack_from("<H", d, list_off + 2)[0]
            out: List[int] = []
            for i in range(count):
                lf = struct.unpack_from("<I", d, list_off + 4 + i * 4)[0]
                out.extend(self._list_entries(self._base + lf))
            return out
        if sig not in (b"lf", b"lh"):
            return []
        count = struct.unpack_from("<H", d, list_off + 2)[0]
        out = []
        for i in range(count):
            ent = list_off + 8 + i * 8
            off = struct.unpack_from("<I", d, ent + 4)[0]
            out.append(self._base + off)
        return out

    def _read_vk(self, offset: int) -> dict:
        d = self._data
        name_len = struct.unpack_from("<H", d, offset + 0x2)[0]
        data_len = struct.unpack_from("<I", d, offset + 0x4)[0]
        data_off = struct.unpack_from("<I", d, offset + 0x8)[0]
        if name_len > 0:
            name = d[offset + 0x14 : offset + 0x14 + name_len].decode("latin-1", errors="replace")
        else:
            name = d[offset + 0x14 : offset + 0x14 + 4].decode("latin-1", errors="replace")

        if data_len >= 0x80000000:
            data_len &= 0x7FFFFFFF

        if data_len <= 4:
            raw = struct.pack("<I", data_off)[:data_len]
        else:
            start = self._base + data_off
            raw = d[start : start + data_len]
        return {"name": name, "data": raw}
