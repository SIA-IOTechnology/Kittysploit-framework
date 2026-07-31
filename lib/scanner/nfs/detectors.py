#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFS showmount via MOUNT EXPORT (NSE nfs-showmount)."""

from __future__ import annotations

import socket
import struct
import uuid
from typing import Dict, List


def _xid() -> int:
    return uuid.uuid4().int & 0xFFFFFFFF


def _rpc_call(program: int, version: int, procedure: int, payload: bytes = b"") -> bytes:
    """Build ONC RPC CALL message (AUTH_NULL)."""
    xid = _xid()
    header = struct.pack(
        ">IIIIIIIIII",
        xid,
        0,  # CALL
        2,  # RPC version
        program,
        version,
        procedure,
        0,  # cred flavor NULL
        0,  # cred length
        0,  # verf flavor NULL
        0,  # verf length
    )
    return header + payload


def _recv_record(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    # TCP record marking
    hdr = sock.recv(4)
    if len(hdr) < 4:
        return b""
    length = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _parse_exports(data: bytes) -> List[Dict[str, str]]:
    """Best-effort parse of MOUNT EXPORT reply list."""
    exports: List[Dict[str, str]] = []
    # Skip RPC reply header (xid + msg_type + reply_stat + …) — look for path strings
    i = 0
    # Find rpc accept success then walk bool/list — fallback to string scrape
    paths = []
    while i + 4 <= len(data):
        strlen = struct.unpack(">I", data[i : i + 4])[0]
        if 1 <= strlen <= 256 and i + 4 + strlen <= len(data):
            raw = data[i + 4 : i + 4 + strlen]
            if all(32 <= b < 127 or b in (9,) for b in raw):
                text = raw.decode("ascii", errors="ignore")
                if text.startswith("/") or text.startswith("*"):
                    paths.append(text)
                i += 4 + strlen
                # XDR pad
                pad = (4 - (strlen % 4)) % 4
                i += pad
                continue
        i += 1
        if len(paths) >= 32:
            break
    for p in paths:
        exports.append({"path": p, "groups": "*"})
    # unique
    seen = set()
    out = []
    for e in exports:
        if e["path"] not in seen:
            seen.add(e["path"])
            out.append(e)
    return out


def _portmap_getport(
    host: str,
    program: int,
    version: int,
    protocol: int,
    port: int = 111,
    timeout: float = 3.0,
) -> int:
    """Query rpcbind/portmap for program port. protocol: 6=TCP, 17=UDP."""
    payload = struct.pack(">IIII", program, version, protocol, 0)
    call = _rpc_call(100000, 2, 3, payload)  # PMAPPROC_GETPORT
    # Try TCP first
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">I", 0x80000000 | len(call)) + call)
            data = _recv_record(sock, timeout)
            if len(data) >= 28:
                # xid(4) type(4) reply(4) verf… accept(4) port(4) — offsets vary
                # Last 4 bytes often the port
                return struct.unpack(">I", data[-4:])[0]
    except Exception:
        pass
    # UDP fallback
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(call, (host, port))
        data, _ = sock.recvfrom(256)
        sock.close()
        if len(data) >= 28:
            return struct.unpack(">I", data[-4:])[0]
    except Exception:
        pass
    return 0


def probe_nfs_showmount(
    host: str,
    portmap_port: int = 111,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """List NFS exports via MOUNT v1/v3 EXPORT (NSE nfs-showmount)."""
    result: Dict[str, object] = {
        "detected": False,
        "exports": [],
        "mount_port": 0,
        "error": "",
    }
    mount_port = _portmap_getport(host, 100005, 3, 6, portmap_port, timeout)
    if not mount_port:
        mount_port = _portmap_getport(host, 100005, 1, 6, portmap_port, timeout)
    if not mount_port:
        # Common default
        mount_port = 2049
    result["mount_port"] = mount_port

    # MOUNTPROC_EXPORT = 5 for v1/v3
    for version in (3, 1):
        call = _rpc_call(100005, version, 5, b"")
        try:
            with socket.create_connection((host, mount_port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(struct.pack(">I", 0x80000000 | len(call)) + call)
                data = _recv_record(sock, timeout)
                if not data:
                    continue
                exports = _parse_exports(data)
                if exports:
                    result["detected"] = True
                    result["exports"] = exports
                    return result
                # Even empty successful reply means mount service up
                if len(data) >= 24:
                    result["detected"] = True
                    result["exports"] = []
                    return result
        except Exception as exc:
            result["error"] = str(exc)[:200]
            continue
    if not result["detected"] and not result["error"]:
        result["error"] = "no_exports"
    return result
