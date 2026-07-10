# -*- coding: utf-8 -*-
"""Opérations MS-SAMR (énumération lastLogon via port 445)."""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from lib.protocols.samr.dcerpc import DceRpcClient, DceRpcError
from lib.protocols.samr.ndr import (
    SAMR_INTERFACE_UUID,
    align4,
    pack_handle,
    pack_unique_wstring,
    pack_ulong,
    sid_bytes_to_str,
    unpack_context_handle,
    unpack_ndr_return,
    unpack_sid,
    unpack_unique_wstring,
    unpack_user_all_information,
)
from lib.protocols.samr.smb_transport import SmbPipeTransport
from lib.protocols.samr.types import SamAccountRecord, SamAliasRecord, SamGroupMembership

# [MS-SAMR] opnums
SAMR_CONNECT2 = 57
SAMR_CLOSE_HANDLE = 1
SAMR_ENUMERATE_DOMAINS_IN_SAM_SERVER = 6
SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER = 12
SAMR_OPEN_DOMAIN = 7
SAMR_ENUMERATE_USERS_IN_DOMAIN = 13
SAMR_ENUMERATE_ALIASES_IN_DOMAIN = 15
SAMR_LOOKUP_IDS_IN_DOMAIN = 18
SAMR_OPEN_USER = 34
SAMR_QUERY_INFORMATION_USER = 36
SAMR_OPEN_ALIAS = 27
SAMR_GET_MEMBERS_IN_ALIAS = 33

DOMAIN_LOOKUP_MAX = 0x00000008
DOMAIN_ALL_ACCESS = 0x000F07FF
ALIAS_READ = 0x00000004
USER_READ_GENERAL = 0x00000010
MAXIMUM_ALLOWED = 0x02000000
USER_ALL_INFORMATION = 21

STATUS_MORE_ENTRIES = 0x00000105
STATUS_SUCCESS = 0


class SamrClient:
    """Client SAMR minimal : énumère comptes + lastLogon sans LDAP."""

    def __init__(
        self,
        host: str,
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        remote_name: str = "",
        timeout: int = 15,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._domain = domain
        self._remote_name = remote_name
        self._timeout = timeout
        self._dce: Optional[DceRpcClient] = None
        self._transport: Optional[SmbPipeTransport] = None

    def connect(self) -> None:
        self._transport = SmbPipeTransport(
            host=self._host,
            port=self._port,
            username=self._username,
            password=self._password,
            domain=self._domain,
            remote_name=self._remote_name,
            timeout=self._timeout,
        )
        self._dce = DceRpcClient(self._transport)
        self._dce.connect()
        self._dce.bind(SAMR_INTERFACE_UUID)

    def close(self) -> None:
        if self._dce:
            try:
                self._dce.close()
            except Exception:
                pass
        self._dce = None
        self._transport = None

    def __enter__(self) -> "SamrClient":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def enumerate_accounts(self, max_accounts: int = 5000) -> List[SamAccountRecord]:
        server_handle = self._samr_connect()
        try:
            domain_name = self._pick_domain_name(server_handle)
            domain_sid = self._lookup_domain(server_handle, domain_name)
            domain_handle = self._open_domain(server_handle, domain_sid)
            try:
                return self._enumerate_users(domain_handle, max_accounts=max_accounts)
            finally:
                self._close_handle(domain_handle)
        finally:
            self._close_handle(server_handle)

    def enumerate_aliases(self, max_aliases: int = 512) -> List[SamAliasRecord]:
        server_handle = self._samr_connect()
        try:
            domain_name = self._pick_domain_name(server_handle)
            domain_sid = self._lookup_domain(server_handle, domain_name)
            domain_handle = self._open_domain(server_handle, domain_sid)
            try:
                return self._enumerate_aliases(domain_handle, domain_sid, max_aliases=max_aliases)
            finally:
                self._close_handle(domain_handle)
        finally:
            self._close_handle(server_handle)

    def enumerate_group_membership(
        self,
        *,
        alias_name: str = "",
        max_aliases: int = 64,
        max_members: int = 512,
    ) -> List[SamGroupMembership]:
        aliases = self.enumerate_aliases(max_aliases=max_aliases)
        if alias_name:
            needle = alias_name.strip().lower()
            aliases = [item for item in aliases if item.name.lower() == needle]
        memberships: List[SamGroupMembership] = []
        server_handle = self._samr_connect()
        try:
            domain_name = self._pick_domain_name(server_handle)
            domain_sid = self._lookup_domain(server_handle, domain_name)
            domain_handle = self._open_domain(server_handle, domain_sid)
            try:
                for alias in aliases[:max_aliases]:
                    members = self._get_alias_members(
                        domain_handle,
                        domain_sid,
                        alias.rid,
                        max_members=max_members,
                    )
                    memberships.append(
                        SamGroupMembership(
                            group_name=alias.name,
                            group_rid=alias.rid,
                            members=members,
                        )
                    )
            finally:
                self._close_handle(domain_handle)
        finally:
            self._close_handle(server_handle)
        return memberships

    def _samr_connect(self) -> bytes:
        assert self._dce is not None
        stub = pack_unique_wstring(None) + pack_ulong(MAXIMUM_ALLOWED)
        resp = self._dce.request(SAMR_CONNECT2, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            raise DceRpcError(f"SamrConnect2 failed: 0x{status:08x}")
        handle, _ = unpack_context_handle(resp, offset)
        return handle

    def _pick_domain_name(self, server_handle: bytes) -> str:
        assert self._dce is not None
        names = []
        context = 0
        while True:
            stub = (
                pack_handle(server_handle)
                + pack_ulong(context)
                + pack_ulong(0xFFFF)
            )
            resp = self._dce.request(SAMR_ENUMERATE_DOMAINS_IN_SAM_SERVER, stub)
            status, offset = unpack_ndr_return(resp, 0)
            if status not in (STATUS_SUCCESS, STATUS_MORE_ENTRIES):
                break
            # EnumerationContext out
            context = struct.unpack_from("<I", resp, offset)[0]
            offset += 4
            # buffer pointer
            if struct.unpack_from("<I", resp, offset)[0] == 0:
                break
            offset += 4
            if offset + 12 > len(resp):
                break
            _max_count, _offset, entry_count = struct.unpack_from("<III", resp, offset)
            offset += 12
            for _ in range(entry_count):
                name, offset = unpack_unique_wstring(resp, offset)
                _sid, offset = unpack_sid(resp, offset)
                if name:
                    names.append(name)
            if status != STATUS_MORE_ENTRIES:
                break
        if not names:
            raise DceRpcError("No SAM domains returned")
        # Compte domaine (pas Builtin/Account)
        for candidate in names:
            if candidate.lower() not in ("builtin", "account"):
                return candidate
        return names[0]

    def _lookup_domain(self, server_handle: bytes, domain_name: str) -> bytes:
        assert self._dce is not None
        stub = pack_handle(server_handle) + pack_unique_wstring(domain_name)
        resp = self._dce.request(SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            raise DceRpcError(f"SamrLookupDomain failed: 0x{status:08x}")
        if struct.unpack_from("<I", resp, offset)[0] == 0:
            raise DceRpcError("SamrLookupDomain returned null SID")
        offset += 4
        sid, _ = unpack_sid(resp, offset)
        if not sid:
            raise DceRpcError("Empty domain SID")
        return sid

    def _open_domain(self, server_handle: bytes, domain_sid: bytes) -> bytes:
        assert self._dce is not None
        stub = (
            pack_handle(server_handle)
            + pack_ulong(DOMAIN_ALL_ACCESS)
            + struct.pack("<I", 1)  # sid referent
            + domain_sid
            + b"\x00" * ((align4(len(domain_sid)) - len(domain_sid)) % 4)
        )
        resp = self._dce.request(SAMR_OPEN_DOMAIN, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            raise DceRpcError(f"SamrOpenDomain failed: 0x{status:08x}")
        handle, _ = unpack_context_handle(resp, offset)
        return handle

    def _enumerate_users(
        self,
        domain_handle: bytes,
        max_accounts: int = 5000,
    ) -> List[SamAccountRecord]:
        assert self._dce is not None
        records: List[SamAccountRecord] = []
        context = 0
        while len(records) < max_accounts:
            stub = (
                pack_handle(domain_handle)
                + pack_ulong(context)
                + pack_ulong(0)  # UserAccountControl filter
                + pack_ulong(0xFFFF)
            )
            resp = self._dce.request(SAMR_ENUMERATE_USERS_IN_DOMAIN, stub)
            status, offset = unpack_ndr_return(resp)
            if status not in (STATUS_SUCCESS, STATUS_MORE_ENTRIES):
                break
            context = struct.unpack_from("<I", resp, offset)[0]
            offset += 4
            if struct.unpack_from("<I", resp, offset)[0] == 0:
                break
            offset += 4
            if offset + 12 > len(resp):
                break
            _max_count, _off, entry_count = struct.unpack_from("<III", resp, offset)
            offset += 12
            entries: List[Tuple[str, int]] = []
            for _ in range(entry_count):
                if offset + 8 > len(resp):
                    break
                rel_id = struct.unpack_from("<I", resp, offset)[0]
                offset += 4
                name, offset = unpack_unique_wstring(resp, offset)
                entries.append((name, rel_id))
            for name, rid in entries:
                if len(records) >= max_accounts:
                    break
                detail = self._query_user(domain_handle, rid)
                records.append(
                    SamAccountRecord(
                        name=detail.get("user_name") or name,
                        last_logon=int(detail.get("last_logon") or 0),
                        logon_count=int(detail.get("logon_count") or 0),
                        password_last_set=int(detail.get("password_last_set") or 0),
                        description=str(detail.get("description") or ""),
                        admin_comment=str(detail.get("admin_comment") or ""),
                        rid=rid,
                        user_account_control=int(detail.get("user_account_control") or 0),
                        source="samr",
                    )
                )
            if status != STATUS_MORE_ENTRIES:
                break
        return records

    def _query_user(self, domain_handle: bytes, rid: int) -> dict:
        assert self._dce is not None
        user_handle = self._open_user(domain_handle, rid)
        try:
            stub = (
                pack_handle(user_handle)
                + pack_ulong(USER_ALL_INFORMATION)
            )
            resp = self._dce.request(SAMR_QUERY_INFORMATION_USER, stub)
            status, offset = unpack_ndr_return(resp)
            if status != STATUS_SUCCESS:
                return {}
            if struct.unpack_from("<I", resp, offset)[0] == 0:
                return {}
            offset += 4
            info, _ = unpack_user_all_information(resp, offset)
            return info
        finally:
            self._close_handle(user_handle)

    def _open_user(self, domain_handle: bytes, rid: int) -> bytes:
        assert self._dce is not None
        stub = pack_handle(domain_handle) + pack_ulong(USER_READ_GENERAL) + pack_ulong(rid)
        resp = self._dce.request(SAMR_OPEN_USER, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            raise DceRpcError(f"SamrOpenUser failed for RID {rid}: 0x{status:08x}")
        handle, _ = unpack_context_handle(resp, offset)
        return handle

    def _close_handle(self, handle: bytes) -> None:
        if not self._dce or not handle:
            return
        try:
            self._dce.request(SAMR_CLOSE_HANDLE, pack_handle(handle))
        except Exception:
            pass

    def _enumerate_aliases(
        self,
        domain_handle: bytes,
        domain_sid: bytes,
        max_aliases: int = 512,
    ) -> List[SamAliasRecord]:
        assert self._dce is not None
        aliases: List[SamAliasRecord] = []
        context = 0
        while len(aliases) < max_aliases:
            stub = (
                pack_handle(domain_handle)
                + pack_ulong(context)
                + pack_ulong(0xFFFF)
            )
            resp = self._dce.request(SAMR_ENUMERATE_ALIASES_IN_DOMAIN, stub)
            status, offset = unpack_ndr_return(resp)
            if status not in (STATUS_SUCCESS, STATUS_MORE_ENTRIES):
                break
            context = struct.unpack_from("<I", resp, offset)[0]
            offset += 4
            if struct.unpack_from("<I", resp, offset)[0] == 0:
                break
            offset += 4
            if offset + 12 > len(resp):
                break
            _max_count, _off, entry_count = struct.unpack_from("<III", resp, offset)
            offset += 12
            for _ in range(entry_count):
                if offset + 8 > len(resp):
                    break
                rel_id = struct.unpack_from("<I", resp, offset)[0]
                offset += 4
                name, offset = unpack_unique_wstring(resp, offset)
                if name:
                    aliases.append(SamAliasRecord(name=name, rid=rel_id, domain_sid=domain_sid))
                if len(aliases) >= max_aliases:
                    break
            if status != STATUS_MORE_ENTRIES:
                break
        return aliases

    def _open_alias(self, domain_handle: bytes, alias_rid: int) -> bytes:
        assert self._dce is not None
        stub = pack_handle(domain_handle) + pack_ulong(ALIAS_READ) + pack_ulong(alias_rid)
        resp = self._dce.request(SAMR_OPEN_ALIAS, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            raise DceRpcError(f"SamrOpenAlias failed for RID {alias_rid}: 0x{status:08x}")
        handle, _ = unpack_context_handle(resp, offset)
        return handle

    def _get_alias_members(
        self,
        domain_handle: bytes,
        domain_sid: bytes,
        alias_rid: int,
        max_members: int = 512,
    ) -> List[str]:
        assert self._dce is not None
        alias_handle = self._open_alias(domain_handle, alias_rid)
        try:
            resp = self._dce.request(SAMR_GET_MEMBERS_IN_ALIAS, pack_handle(alias_handle))
            status, offset = unpack_ndr_return(resp)
            if status != STATUS_SUCCESS:
                return []
            if struct.unpack_from("<I", resp, offset)[0] == 0:
                return []
            offset += 4
            if offset + 4 > len(resp):
                return []
            count = struct.unpack_from("<I", resp, offset)[0]
            offset += 4
            members: List[str] = []
            relative_ids: List[int] = []
            domain_prefix = sid_bytes_to_str(domain_sid)
            for _ in range(min(count, max_members)):
                sid_bytes, offset = unpack_sid(resp, offset)
                if not sid_bytes:
                    continue
                sid_text = sid_bytes_to_str(sid_bytes)
                if sid_text.startswith(domain_prefix + "-"):
                    relative_ids.append(int(sid_text.rsplit("-", 1)[-1]))
                else:
                    members.append(sid_text)
            if relative_ids:
                members.extend(self._lookup_relative_ids(domain_handle, relative_ids))
            return members
        finally:
            self._close_handle(alias_handle)

    def _lookup_relative_ids(self, domain_handle: bytes, relative_ids: List[int]) -> List[str]:
        assert self._dce is not None
        if not relative_ids:
            return []
        stub = pack_handle(domain_handle) + pack_ulong(len(relative_ids))
        for rel_id in relative_ids:
            stub += pack_ulong(rel_id)
        resp = self._dce.request(SAMR_LOOKUP_IDS_IN_DOMAIN, stub)
        status, offset = unpack_ndr_return(resp)
        if status != STATUS_SUCCESS:
            return [str(rid) for rid in relative_ids]
        if struct.unpack_from("<I", resp, offset)[0] == 0:
            return [str(rid) for rid in relative_ids]
        offset += 4
        names: List[str] = []
        for _ in relative_ids:
            name, offset = unpack_unique_wstring(resp, offset)
            names.append(name or "?")
        return names
