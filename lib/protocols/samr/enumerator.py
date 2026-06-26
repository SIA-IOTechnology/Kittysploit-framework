# -*- coding: utf-8 -*-
"""Façade d'énumération SAM (SAMR ou NetAPI selon la plateforme)."""

from __future__ import annotations

import sys
from typing import List, Optional

from lib.protocols.samr.samr_client import SamrClient
from lib.protocols.samr.types import SamAccountRecord
from lib.protocols.samr.win32_netapi import WIN32_NETAPI_AVAILABLE, enumerate_accounts_win32


class SamEnumerationError(Exception):
    pass


class SamEnumerator:
    """
    Énumère les comptes AD via SAM (port 445) sans LDAP ni Impacket.

    - Windows : NetUserEnum (netapi32) en priorité, repli SAMR pysmb
    - Linux/macOS : SAMR MS-RPC via pysmb + stack DCE/RPC KittySploit
    """

    def __init__(
        self,
        host: str,
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        remote_name: str = "",
        timeout: int = 15,
        prefer_samr: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.remote_name = remote_name or host
        self.timeout = timeout
        self.prefer_samr = prefer_samr

    def enumerate(
        self,
        *,
        include_users: bool = True,
        include_computers: bool = True,
        max_accounts: int = 5000,
    ) -> List[SamAccountRecord]:
        errors: List[str] = []

        if WIN32_NETAPI_AVAILABLE and not self.prefer_samr:
            try:
                rows = enumerate_accounts_win32(
                    self.host,
                    include_users=include_users,
                    include_computers=include_computers,
                )
                if rows:
                    return self._filter_rows(rows, include_users, include_computers, max_accounts)
            except Exception as exc:
                errors.append(f"netapi32: {exc}")

        try:
            client = SamrClient(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                domain=self.domain,
                remote_name=self.remote_name,
                timeout=self.timeout,
            )
            with client:
                rows = client.enumerate_accounts(max_accounts=max_accounts)
            return self._filter_rows(rows, include_users, include_computers, max_accounts)
        except Exception as exc:
            errors.append(f"samr: {exc}")

        hint = (
            "Install pysmb (`pip install pysmb`) for cross-platform SAMR enumeration."
            if sys.platform != "win32"
            else "Verify DC reachability, credentials, and SMB (445/tcp)."
        )
        raise SamEnumerationError(f"SAM enumeration failed ({'; '.join(errors)}). {hint}")

    @staticmethod
    def _filter_rows(
        rows: List[SamAccountRecord],
        include_users: bool,
        include_computers: bool,
        max_accounts: int,
    ) -> List[SamAccountRecord]:
        filtered: List[SamAccountRecord] = []
        for row in rows:
            if row.is_computer and not include_computers:
                continue
            if not row.is_computer and not include_users:
                continue
            filtered.append(row)
            if len(filtered) >= max_accounts:
                break
        return filtered
