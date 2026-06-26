# -*- coding: utf-8 -*-
"""
Énumération NetUserEnum native Windows (netapi32) — sans Impacket ni bind LDAP.

Utilise le même canal que les outils d'inventaire (SAMR/NetAPI sur 445) et expose
lastLogon / logonCount pour l'oracle honeytoken.
"""

from __future__ import annotations

import sys
from typing import List

from lib.protocols.samr.types import SamAccountRecord

if sys.platform != "win32":
    WIN32_NETAPI_AVAILABLE = False
else:
    WIN32_NETAPI_AVAILABLE = True

FILTER_NORMAL_ACCOUNT = 0x0002
FILTER_WORKSTATION_TRUST_ACCOUNT = 0x00000010
FILTER_SERVER_TRUST_ACCOUNT = 0x00000020
MAX_PREFERRED_LENGTH = 0xFFFFFFFF
NERR_Success = 0


def _enumerate_filter(server: str, filt: int) -> List[SamAccountRecord]:
    import ctypes
    from ctypes import wintypes

    netapi32 = ctypes.WinDLL("netapi32")

    class USER_INFO_11(ctypes.Structure):
        _fields_ = [
            ("usri11_name", wintypes.LPWSTR),
            ("usri11_password", wintypes.LPWSTR),
            ("usri11_password_age", wintypes.DWORD),
            ("usri11_priv", wintypes.DWORD),
            ("usri11_home_dir", wintypes.LPWSTR),
            ("usri11_comment", wintypes.LPWSTR),
            ("usri11_flags", wintypes.DWORD),
            ("usri11_auth_flags", wintypes.DWORD),
            ("usri11_full_name", wintypes.LPWSTR),
            ("usri11_usr_comment", wintypes.LPWSTR),
            ("usri11_parms", wintypes.LPWSTR),
            ("usri11_last_logon", wintypes.DWORD),
            ("usri11_last_logout", wintypes.DWORD),
            ("usri11_bad_pw_count", wintypes.DWORD),
            ("usri11_num_logons", wintypes.DWORD),
            ("usri11_logon_server", wintypes.LPWSTR),
            ("usri11_country_code", wintypes.DWORD),
            ("usri11_code_page", wintypes.DWORD),
        ]

    bufptr = ctypes.c_void_p()
    entriesread = wintypes.DWORD(0)
    totalentries = wintypes.DWORD(0)
    resume = wintypes.DWORD(0)
    records: List[SamAccountRecord] = []

    while True:
        status = netapi32.NetUserEnum(
            server,
            11,
            filt,
            ctypes.byref(bufptr),
            MAX_PREFERRED_LENGTH,
            ctypes.byref(entriesread),
            ctypes.byref(totalentries),
            ctypes.byref(resume),
        )
        if status not in (NERR_Success, 234):  # ERROR_MORE_DATA
            break
        try:
            if entriesread.value:
                entries_array = (USER_INFO_11 * entriesread.value).from_address(bufptr.value)
                for i in range(entriesread.value):
                    entry = entries_array[i]
                    name = entry.usri11_name or ""
                    if not name:
                        continue
                    records.append(
                        SamAccountRecord(
                            name=name,
                            last_logon=int(entry.usri11_last_logon or 0),
                            logon_count=int(entry.usri11_num_logons or 0),
                            description=str(entry.usri11_comment or ""),
                            admin_comment=str(entry.usri11_usr_comment or ""),
                            source="netapi",
                        )
                    )
        finally:
            if bufptr:
                netapi32.NetApiBufferFree(bufptr)
                bufptr = ctypes.c_void_p()
        if status != 234:
            break
    return records


def enumerate_accounts_win32(
    server: str,
    *,
    include_users: bool = True,
    include_computers: bool = True,
) -> List[SamAccountRecord]:
    """Énumère les comptes via NetUserEnum (Windows uniquement)."""
    if not WIN32_NETAPI_AVAILABLE:
        raise OSError("NetUserEnum is only available on Windows")

    target = f"\\\\{server}" if server and not server.startswith("\\\\") else server
    records: List[SamAccountRecord] = []
    if include_users:
        records.extend(_enumerate_filter(target, FILTER_NORMAL_ACCOUNT))
    if include_computers:
        machine_filter = FILTER_WORKSTATION_TRUST_ACCOUNT | FILTER_SERVER_TRUST_ACCOUNT
        records.extend(_enumerate_filter(target, machine_filter))
    return records
