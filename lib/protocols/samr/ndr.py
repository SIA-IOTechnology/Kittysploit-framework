# -*- coding: utf-8 -*-
"""Helpers NDR minimaux pour MS-SAMR (sans dépendance Impacket)."""

from __future__ import annotations

import struct
import uuid
from typing import List, Optional, Tuple


def align4(offset: int) -> int:
    return (offset + 3) & ~3


def pack_uuid(uuid_str: str, version: int = 1) -> bytes:
    """UUID interface RPC (little-endian) + version majeure."""
    return uuid.UUID(uuid_str).bytes_le + struct.pack("<I", version)


SAMR_INTERFACE_UUID = pack_uuid("12345778-1234-ABCD-EF00-0123456789AC", 1)
NDR_TRANSFER_SYNTAX = pack_uuid("8a885d04-1ceb-11c9-9fe8-08002b104860", 2)


def pack_unique_wstring(value: Optional[str], referent: int = 1) -> bytes:
    """Pointeur unique vers une chaîne UTF-16LE conformante (ou NULL)."""
    if not value:
        return struct.pack("<I", 0)
    encoded = value.encode("utf-16le") + b"\x00\x00"
    char_count = len(encoded) // 2
    body = struct.pack("<IIII", char_count, char_count, 0, char_count) + encoded
    pad = b"\x00" * ((align4(len(body)) - len(body)) % 4)
    return struct.pack("<I", referent & 0xFFFFFFFF) + body + pad


def pack_ulong(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def pack_handle(handle: bytes) -> bytes:
    if len(handle) != 20:
        raise ValueError("SAMPR_HANDLE must be 20 bytes")
    return handle


def unpack_context_handle(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    handle = data[offset : offset + 20]
    return handle, offset + 20


def unpack_ndr_return(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """NTSTATUS + nouvel offset après alignement."""
    status = struct.unpack_from("<I", data, offset)[0]
    return status, offset + 4


def unpack_unique_wstring(data: bytes, offset: int = 0) -> Tuple[str, int]:
    if offset + 4 > len(data):
        return "", offset
    referent = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if referent == 0:
        return "", offset
    if offset + 12 > len(data):
        return "", offset
    _max_count, _offset, actual_count = struct.unpack_from("<III", data, offset)
    offset += 12
    byte_len = actual_count * 2
    raw = data[offset : offset + byte_len]
    offset = align4(offset + byte_len)
    return raw.decode("utf-16le", errors="ignore").rstrip("\x00"), offset


def unpack_sid(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    if offset + 4 > len(data):
        return b"", offset
    referent = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if referent == 0:
        return b"", offset
    revision = data[offset]
    subauth_count = data[offset + 1]
    length = 8 + subauth_count * 4
    sid = data[offset : offset + length]
    return sid, align4(offset + length)


def sid_bytes_to_str(sid: bytes) -> str:
    if len(sid) < 8:
        return ""
    revision = sid[0]
    subauth_count = sid[1]
    authority = int.from_bytes(sid[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    for i in range(subauth_count):
        start = 8 + i * 4
        parts.append(str(struct.unpack_from("<I", sid, start)[0]))
    return "-".join(parts)


def unpack_user_all_information(data: bytes, offset: int = 0) -> Tuple[dict, int]:
    """
    Décode SAMPR_USER_ALL_INFORMATION (classe 21) — champs utiles à la chasse honeytoken.
    Layout NDR partiel basé sur [MS-SAMR] 2.2.21.11.
    """
    fields: dict = {}
    if offset + 4 > len(data):
        return fields, offset

    # LastLogon (OLD_LARGE_INTEGER) — offset fixe dans le stub plat après en-têtes NDR
    # On parse de façon défensive en cherchant les champs clés via le déroulé NDR complet.
    start = offset
    try:
        # LastLogonTime, LastLogoutTime, PasswordLastSet, AccountExpires (4x 8 bytes)
        last_logon = struct.unpack_from("<Q", data, start)[0]
        start += 8
        start += 8  # last logout
        pwd_last_set = struct.unpack_from("<Q", data, start)[0]
        start += 8
        start += 8  # account expires

        fields["last_logon"] = last_logon
        fields["password_last_set"] = pwd_last_set

        # PasswordCanChange, PasswordMustChange
        start += 16

        # PasswordLastSet déjà lu ; sauter vers compteurs après bloc unicode strings
        # Repositionnement : strings NDR (UserName, FullName, HomeDirectory, ...)
        name, start = unpack_unique_wstring(data, start)
        fields["user_name"] = name
        _full, start = unpack_unique_wstring(data, start)
        _home, start = unpack_unique_wstring(data, start)
        _dir, start = unpack_unique_wstring(data, start)
        script, start = unpack_unique_wstring(data, start)
        profile, start = unpack_unique_wstring(data, start)
        admin_comment, start = unpack_unique_wstring(data, start)
        fields["admin_comment"] = admin_comment
        work, start = unpack_unique_wstring(data, start)
        fields["description"] = work

        if start + 20 <= len(data):
            # UserId, PrimaryGroupId, UserAccountControl, …
            start += 4  # user id
            start += 4  # primary group
            if start + 4 <= len(data):
                fields["user_account_control"] = struct.unpack_from("<I", data, start)[0]
                start += 4
        if start + 8 <= len(data):
            fields["logon_count"] = struct.unpack_from("<H", data, start)[0]
    except (struct.error, IndexError):
        pass

    return fields, align4(start)
