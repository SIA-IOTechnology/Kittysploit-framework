#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active IEC 60870-5-104 client — STARTDT and general interrogation."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional


STARTDT_ACT = bytes.fromhex("680407000000")
STARTDT_CON = bytes.fromhex("68040b000000")
TESTFR_ACT = bytes.fromhex("680043000000")


@dataclass
class Iec104Result:
    host: str
    port: int
    connected: bool = False
    startdt_confirmed: bool = False
    interrogation_sent: bool = False
    responses: List[str] = field(default_factory=list)
    error: str = ""


class Iec104Client:
    def __init__(self, host: str, port: int = 2404, timeout: float = 5.0, common_address: int = 1):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.common_address = int(common_address)
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
        self._sock = sock
        return True

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _recv(self) -> bytes:
        if not self._sock:
            return b""
        try:
            return self._sock.recv(4096)
        except socket.timeout:
            return b""

    def startdt(self) -> bool:
        if not self._sock:
            return False
        self._sock.sendall(STARTDT_ACT)
        response = self._recv()
        return response.startswith(STARTDT_CON)

    def general_interrogation(self) -> bool:
        if not self._sock:
            return False
        # C_IC_NA_1 (100) activation — read-only interrogation command.
        asdu = struct.pack(
            ">BBBBBBH",
            0x64,
            0x01,
            0x06,
            0x00,
            self.common_address & 0xFF,
            (self.common_address >> 8) & 0xFF,
            0x0000,
        )
        apdu = bytes([0x68, len(asdu) + 4, 0x02, 0x00, 0x00, 0x00]) + asdu
        self._sock.sendall(apdu)
        return True

    def _recv_all(self, max_frames: int = 8) -> List[bytes]:
        frames: List[bytes] = []
        if not self._sock:
            return frames
        for _ in range(max(1, max_frames)):
            chunk = self._recv()
            if not chunk:
                break
            frames.append(chunk)
        return frames

    def single_command(self, ioa: int, value: bool, select: bool = False) -> bool:
        if not self._sock:
            return False
        # C_SC_NA_1 (45) — single command with SCO byte.
        sco = 0x01 if value else 0x00
        if select:
            sco |= 0x80
        asdu = struct.pack(
            ">BBBBBBBB",
            0x2D,
            0x01,
            0x06,
            0x00,
            self.common_address & 0xFF,
            (self.common_address >> 8) & 0xFF,
            ioa & 0xFF,
            (ioa >> 8) & 0xFF,
        ) + bytes([(ioa >> 16) & 0xFF, sco])
        apdu = bytes([0x68, len(asdu) + 4, 0x02, 0x00, 0x00, 0x00]) + asdu
        self._sock.sendall(apdu)
        response = self._recv()
        return bool(response)

    def interrogation_dump(self, max_frames: int = 16) -> Iec104Result:
        result = Iec104Result(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            result.startdt_confirmed = self.startdt()
            if not result.startdt_confirmed:
                result.error = "STARTDT not confirmed"
                return result
            result.interrogation_sent = self.general_interrogation()
            for frame in self._recv_all(max_frames):
                result.responses.append(frame.hex())
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()

    def interrogate(self) -> Iec104Result:
        result = Iec104Result(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            result.startdt_confirmed = self.startdt()
            if not result.startdt_confirmed:
                result.error = "STARTDT not confirmed"
                return result
            result.interrogation_sent = self.general_interrogation()
            response = self._recv()
            if response:
                result.responses.append(response.hex())
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()


def interrogate_iec104(
    host: str,
    port: int = 2404,
    timeout: float = 5.0,
    common_address: int = 1,
) -> Iec104Result:
    client = Iec104Client(host, port, timeout, common_address)
    return client.interrogate()


def dump_iec104_interrogation(
    host: str,
    port: int = 2404,
    timeout: float = 5.0,
    common_address: int = 1,
    max_frames: int = 16,
) -> Iec104Result:
    client = Iec104Client(host, port, timeout, common_address)
    return client.interrogation_dump(max_frames)
