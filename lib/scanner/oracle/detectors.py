#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle TNS version + SID brute (NSE oracle-tns-version / oracle-sid-brute)."""

from __future__ import annotations

import re
import socket
import struct
from typing import Dict, List


DEFAULT_SIDS = (
    "ORCL",
    "ORCLPDB1",
    "XE",
    "XEPDB1",
    "PDBORCL",
    "MSSQL",  # sometimes mis-set
    "ORA10",
    "ORA11",
    "ORA12",
    "DB11G",
    "DB12C",
    "PROD",
    "TEST",
    "DEV",
    "ASDB",
    "IASDB",
)


def _tns_connect_packet(connect_data: str) -> bytes:
    data = connect_data.encode("ascii", errors="ignore")
    # TNS Header: length, checksum, type=1 CONNECT, reserved, header checksum
    # Then connect data
    pkt_len = 8 + 50 + len(data)  # simplified — use classic NS connect format
    # Better: standard TNS connect used by nmap/msf
    # Packet type 1, reserved 0, header checksum 0
    # Followed by connect data with (DESCRIPTION=...)
    body = data
    total = 8 + len(body)
    header = struct.pack(">HHBBH", total, 0, 1, 0, 0)
    return header + body


def _recv_tns(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    hdr = sock.recv(8)
    if len(hdr) < 8:
        return hdr
    length = struct.unpack(">H", hdr[0:2])[0]
    body = hdr
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return body


def probe_oracle_tns_version(host: str, port: int = 1521, timeout: float = 5.0) -> Dict[str, object]:
    """Send TNS Connect and parse Refuse/Accept for version banner."""
    result: Dict[str, object] = {
        "detected": False,
        "version": "",
        "banner": "",
        "error": "",
    }
    connect_data = (
        "(CONNECT_DATA=(COMMAND=version))"
    )
    # Full DESCRIPTION for compatibility
    connect_data = (
        f"(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))"
        f"(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port})))"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_tns_connect_packet(connect_data))
        resp = _recv_tns(sock, timeout)
        if len(resp) < 8:
            result["error"] = "short_response"
            return result
        result["detected"] = True
        ptype = resp[4] if len(resp) > 4 else 0
        text = resp.decode("latin-1", errors="replace")
        result["banner"] = re.sub(r"[^\x20-\x7e]", " ", text)[:240].strip()
        # Version often like 192.168.1.4.0 or V8TNS
        m = re.search(r"(\d+\.\d+\.\d+\.\d+\.\d+)", text)
        if m:
            result["version"] = m.group(1)
        else:
            m2 = re.search(r"(V\d+TNS|[Ii][Ss][Qq][Ll]\*\w+)", text)
            if m2:
                result["version"] = m2.group(1)
        if ptype in (2, 4, 5, 11):  # ACCEPT / REFUSE / REDIRECT / DATA
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()


def probe_oracle_sid_brute(
    host: str,
    port: int = 1521,
    timeout: float = 3.0,
    sids: List[str] | None = None,
) -> Dict[str, object]:
    """Brute common Oracle SIDs via TNS Connect (NSE oracle-sid-brute)."""
    result: Dict[str, object] = {
        "detected": False,
        "valid_sids": [],
        "error": "",
    }
    valid: List[str] = []
    for sid in sids or list(DEFAULT_SIDS):
        if sid == "MSSQL":
            continue
        connect_data = (
            f"(DESCRIPTION=(CONNECT_DATA=(SID={sid})(CID=(PROGRAM=kittysploit)"
            f"(HOST=kittysploit)(USER=)))(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port})))"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            sock.sendall(_tns_connect_packet(connect_data))
            resp = _recv_tns(sock, timeout)
            if len(resp) < 5:
                continue
            result["detected"] = True
            ptype = resp[4]
            text = resp.decode("latin-1", errors="replace")
            # ACCEPT (2) => likely valid; REFUSE (4) with certain errors => invalid
            if ptype == 2:
                valid.append(sid)
            elif ptype == 4:
                # Refuse with "SID is not correct" vs auth errors
                if re.search(r"TNS-12505|SID not|not correct", text, re.I):
                    continue
                # Other refuse reasons (auth) may still indicate SID exists
                if re.search(r"TNS-12518|TNS-12520|OERR", text, re.I):
                    valid.append(sid)
            elif ptype == 11:  # DATA / redirect-ish
                valid.append(sid)
        except Exception:
            continue
        finally:
            sock.close()
    result["valid_sids"] = valid
    return result
