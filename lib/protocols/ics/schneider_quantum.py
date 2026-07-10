#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Schneider Quantum 140 series Modbus extension (FC 0x5A) PLC control."""

from __future__ import annotations

import socket
from enum import IntEnum
from typing import Optional


GET_SESSION_PAYLOAD = bytes.fromhex(
    "013800000018005a0010337700000f57494e2d5039504b48485643495538"
)
START_FRAME_PREFIX = "015300000006005a"
STOP_FRAME_PREFIX = "015800000006005a"
START_FRAME_SUFFIX = "40ff00"
STOP_FRAME_SUFFIX = "41ff00"


class QuantumCommand(IntEnum):
    START = 1
    STOP = 2


class SchneiderQuantumClient:
    """Modbus/TCP client for Schneider Quantum proprietary launcher commands."""

    def __init__(self, host: str, port: int = 502, timeout: float = 3.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._session_hex: str = ""

    @property
    def session_hex(self) -> str:
        return self._session_hex

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
        self._session_hex = ""

    def get_session(self) -> bool:
        if not self._sock:
            return False
        self._sock.sendall(GET_SESSION_PAYLOAD)
        response = self._sock.recv(1024)
        if not response:
            return False
        self._session_hex = response[:-1].hex()
        return bool(self._session_hex)

    def send_command(self, command: QuantumCommand | int) -> bool:
        cmd = QuantumCommand(int(command))
        if not self._sock or not self._session_hex:
            return False
        if cmd == QuantumCommand.START:
            frame = START_FRAME_PREFIX + self._session_hex + START_FRAME_SUFFIX
        elif cmd == QuantumCommand.STOP:
            frame = STOP_FRAME_PREFIX + self._session_hex + STOP_FRAME_SUFFIX
        else:
            raise ValueError(f"unsupported Quantum command: {command}")
        self._sock.sendall(bytes.fromhex(frame))
        return True

    def start_plc(self) -> bool:
        return self.send_command(QuantumCommand.START)

    def stop_plc(self) -> bool:
        return self.send_command(QuantumCommand.STOP)

    def run(self, command: QuantumCommand | int) -> bool:
        if not self.connect():
            return False
        try:
            if not self.get_session():
                return False
            return self.send_command(command)
        finally:
            self.close()
