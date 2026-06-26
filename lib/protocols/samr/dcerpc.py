# -*- coding: utf-8 -*-
"""Client DCE/RPC v5 minimal pour MS-SAMR sur named pipe SMB."""

from __future__ import annotations

import struct
from typing import Optional

from lib.protocols.samr.ndr import NDR_TRANSFER_SYNTAX, pack_uuid

MSRPC_REQUEST = 0x00
MSRPC_BIND = 0x0B
MSRPC_BINDACK = 0x0C
MSRPC_RESPONSE = 0x02

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


class DceRpcError(Exception):
    pass


class DceRpcClient:
    """DCE/RPC v5 sans auth PDU (session SMB déjà authentifiée)."""

    def __init__(self, transport) -> None:
        self._transport = transport
        self._call_id = 1
        self._ctx_id = 0
        self._max_xmit = 4280

    def connect(self) -> None:
        self._transport.connect()

    def close(self) -> None:
        self._transport.disconnect()

    def bind(self, interface_uuid: bytes, ctx_id: int = 0) -> None:
        self._ctx_id = ctx_id
        bind_body = self._build_bind(interface_uuid)
        packet = self._build_header(MSRPC_BIND, bind_body)
        self._transport.send(packet)
        response = self._recv_pdu()
        pdu_type = response[2]
        if pdu_type not in (MSRPC_BINDACK,):
            raise DceRpcError(f"RPC bind failed (PDU type 0x{pdu_type:02x})")
        if len(response) >= 26:
            self._max_xmit = struct.unpack_from("<H", response, 24)[0] or self._max_xmit

    def request(self, opnum: int, stub: bytes) -> bytes:
        alloc_hint = len(stub)
        header = struct.pack(
            "<BBBBIHHIHH",
            5,
            0,
            MSRPC_REQUEST,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            0x00000010,
            24 + len(stub),
            0,
            self._call_id,
            alloc_hint,
            self._ctx_id,
            opnum,
        )
        self._call_id += 1
        self._transport.send(header + stub)
        return self._recv_stub()

    def _build_bind(self, interface_uuid: bytes) -> bytes:
        ctx_item = (
            struct.pack("<HBB", self._ctx_id, 1, 0)
            + interface_uuid[:20].ljust(20, b"\x00")
            + NDR_TRANSFER_SYNTAX[:20].ljust(20, b"\x00")
        )
        return (
            struct.pack("<HHIBBH", self._max_xmit, self._max_xmit, 0, 1, 0, 0)
            + ctx_item
        )

    def _build_header(self, pdu_type: int, body: bytes) -> bytes:
        frag_len = 16 + len(body)
        return struct.pack(
            "<BBBBIHHI",
            5,
            0,
            pdu_type,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            0x00000010,
            frag_len,
            0,
            self._call_id,
        ) + body

    def _recv_pdu(self) -> bytes:
        data = self._transport.recv()
        if len(data) < 16:
            raise DceRpcError("RPC response too short")
        frag_len = struct.unpack_from("<H", data, 8)[0]
        while len(data) < frag_len:
            data += self._transport.recv()
        return data

    def _recv_stub(self) -> bytes:
        data = self._recv_pdu()
        if data[2] == 0x03:  # fault
            if len(data) >= 28:
                status = struct.unpack_from("<I", data, 24)[0]
                raise DceRpcError(f"RPC fault status 0x{status:08x}")
            raise DceRpcError("RPC fault")
        # MSRPC response header is 24 bytes
        auth_len = struct.unpack_from("<H", data, 10)[0]
        stub_end = len(data) - auth_len
        if auth_len:
            stub_end -= 8
        return data[24:stub_end]
