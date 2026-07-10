#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Raw S7comm CPU control for Siemens S7-300 and S7-400 PLCs."""

from __future__ import annotations

import socket
from enum import IntEnum
from typing import Optional


SETUP_COMMUNICATION_PACKET = bytes.fromhex(
    "0300001902f08032010000020000080000f0000002000201e0"
)
CPU_START_PACKET = bytes.fromhex(
    "0300002502f0803201000005000014000028000000000000fd000009505f50504f4752414d"
)
CPU_STOP_PACKET = bytes.fromhex(
    "0300002102f0803201000006000010000029000000000009505f50504f4752414d"
)
ISO_CONNECT_PREFIX = bytes.fromhex("0300001611e00000001400c1020100c20201")
ISO_CONNECT_SUFFIX = bytes.fromhex("c0010a")


class S7_300Command(IntEnum):
    START = 1
    STOP = 2


_COMMAND_PAYLOADS = {
    S7_300Command.START: CPU_START_PACKET,
    S7_300Command.STOP: CPU_STOP_PACKET,
}


def is_s7_port_open(host: str, port: int = 102, timeout: float = 1.0) -> bool:
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


def build_iso_connect_packet(slot: int) -> bytes:
    slot_value = int(slot)
    if slot_value < 0 or slot_value > 255:
        raise ValueError(f"slot must be 0-255, got {slot_value}")
    return ISO_CONNECT_PREFIX + bytes([slot_value]) + ISO_CONNECT_SUFFIX


class S7_300Client:
    """S7-300/400 PLC start/stop via classic S7comm PIP _PROGRAM requests."""

    def __init__(self, host: str, port: int = 102, slot: int = 2, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.slot = int(slot)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            return False

        try:
            sock.sendall(build_iso_connect_packet(self.slot))
            sock.recv(1024)
            sock.sendall(SETUP_COMMUNICATION_PACKET)
            sock.recv(1024)
        except OSError:
            sock.close()
            return False

        self._sock = sock
        return True

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def send_command(self, command: S7_300Command | int) -> None:
        cmd = S7_300Command(int(command))
        payload = _COMMAND_PAYLOADS.get(cmd)
        if payload is None:
            raise ValueError(f"unsupported S7-300 command: {command}")
        if not self._sock:
            raise RuntimeError("S7-300 client not connected")
        self._sock.sendall(payload)
        self._sock.recv(1024)

    def run_command(self, command: S7_300Command | int) -> None:
        if not self.connect():
            raise RuntimeError("S7comm connection failed")
        try:
            self.send_command(command)
        finally:
            self.close()
