# -*- coding: utf-8 -*-
"""Sondes SMB bas niveau : SMBv1, signing, null session (sans authentification)."""

import socket
import struct
from typing import Tuple, Optional

# Dialectes SMB2
_SMB2_DIALECT_MAP = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# SMBv1 Negotiate (NetBIOS + SMB)
_SMB1_NEGOTIATE_PKT = (
    b"\x00\x00\x00\x2f"
    b"\xff\x53\x4d\x42"  # SMB
    b"\x72"  # Negotiate
    b"\x00\x00\x00\x00"
    b"\x18\x01\x28"
    b"\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\xff\xff\xfe\xff\x00\x00\x00\x00"
    b"\x00"
    b"\x0c\x00"
    b"\x02NT LM 0.12\x00"
)


def _smb_recv(sock: socket.socket, length: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < length:
        try:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf


def _is_conn_reset(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "10054" in msg or "forcibly closed" in msg or "connection reset" in msg or "econnreset" in msg


def smb1_negotiate(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Retourne True si le serveur répond à un SMBv1 Negotiate."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_SMB1_NEGOTIATE_PKT)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                return False
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 256), timeout)
            if len(body) < 9:
                return False
            return (
                body[0:4] == b"\xff\x53\x4d\x42"
                and body[4] == 0x72
                and struct.unpack_from("<I", body, 5)[0] == 0
            )
    except Exception:
        return False


def _build_smb2_negotiate() -> bytes:
    dialects = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
    preauth_data = struct.pack("<HHH", 1, 0, 0x0001)
    neg_ctx = struct.pack("<HHI", 0x0001, len(preauth_data), 0) + preauth_data
    dialects_end = 64 + 36 + len(dialect_bytes)
    pad_len = (8 - dialects_end % 8) % 8
    neg_ctx_offset = dialects_end + pad_len
    body = (
        struct.pack("<H", 36)
        + struct.pack("<H", len(dialects))
        + struct.pack("<H", 0x0001)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0x0000007F)
        + b"\x00" * 16
        + struct.pack("<I", neg_ctx_offset)
        + struct.pack("<H", 1)
        + struct.pack("<H", 0)
        + dialect_bytes
        + b"\x00" * pad_len
        + neg_ctx
    )
    smb2_hdr = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x1f\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )
    payload = smb2_hdr + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def check_smb_signing(
    host: str, port: int = 445, timeout: float = 3.0
) -> Tuple[str, Optional[str]]:
    """
    Retourne (signing_status, smb_version).
    signing_status: "required" | "enabled_not_required" | "disabled" | "smb2_disabled" | "unreachable" | "error"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_build_smb2_negotiate())
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                return "smb2_disabled", None
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 512), timeout)
            if len(body) < 68 or body[0:4] != b"\xfeSMB":
                return "smb2_disabled", None
            nt_status = struct.unpack_from("<I", body, 8)[0]
            if nt_status != 0:
                return "error", None
            sec_mode = struct.unpack_from("<H", body, 66)[0]
            dialect_code = struct.unpack_from("<H", body, 68)[0] if len(body) >= 70 else None
            ver = _SMB2_DIALECT_MAP.get(dialect_code) if dialect_code is not None else None
            if sec_mode & 0x02:
                return "required", ver
            if sec_mode & 0x01:
                return "enabled_not_required", ver
            return "disabled", ver
    except socket.timeout:
        return "error", None
    except ConnectionRefusedError:
        return "unreachable", None
    except Exception as e:
        if _is_conn_reset(e):
            return "smb2_disabled", None
        return "error", None


# Null session (SMBv1 session setup anonymous)
_NULL_SESSION_PKT = (
    b"\x00\x00\x00\x59"
    b"\xff\x53\x4d\x42"
    b"\x73"  # Session setup
    b"\x00\x00\x00\x00"
    b"\x18"
    b"\x07\xc0"
    b"\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00"
    b"\xff\xff"
    b"\xff\xfe"
    b"\x00\x00"
    b"\x40\x00"
    b"\x0d"
    b"\xff"
    b"\x00"
    b"\x00\x00"
    b"\xff\x00"
    b"\x02\x00"
    b"\x01\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x60\x48\x06\x06"
    b"\x11\x00"
    b"\x00"
    b"\x00"
    b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
    b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
)


def check_null_session(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Retourne True si une null session (anonyme) est acceptée."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_NULL_SESSION_PKT)
            resp = _smb_recv(s, 256, timeout)
            if len(resp) >= 13 and resp[4:8] == b"\xff\x53\x4d\x42":
                return struct.unpack_from("<I", resp, 9)[0] == 0
    except Exception:
        pass
    return False
