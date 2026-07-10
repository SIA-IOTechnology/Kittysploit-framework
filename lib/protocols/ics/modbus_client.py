#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active Modbus TCP client for safe ICS reconnaissance."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ModbusProbeResult:
    host: str
    port: int
    unit_id: int
    function_code: int
    success: bool
    values: List[int] = field(default_factory=list)
    error_code: Optional[int] = None
    raw_error: str = ""


class ModbusTCPClient:
    def __init__(self, host: str, port: int = 502, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._transaction_id = 0

    @property
    def connected(self) -> bool:
        return self._sock is not None

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

    def _next_transaction_id(self) -> int:
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF
        if self._transaction_id == 0:
            self._transaction_id = 1
        return self._transaction_id

    def _send_receive(self, pdu: bytes, unit_id: int) -> bytes:
        if not self._sock:
            raise RuntimeError("Not connected")
        trans_id = self._next_transaction_id()
        header = struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit_id & 0xFF)
        self._sock.sendall(header + pdu)
        response = self._recv_all()
        if len(response) < 9:
            raise RuntimeError("Modbus response too short")
        return response

    def _recv_all(self) -> bytes:
        if not self._sock:
            return b""
        chunks: List[bytes] = []
        self._sock.settimeout(self.timeout)
        while True:
            try:
                part = self._sock.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
            if len(part) < 4096:
                break
        return b"".join(chunks)

    def read_holding_registers(self, unit_id: int, address: int, count: int = 1) -> ModbusProbeResult:
        return self._read_registers(unit_id, 0x03, address, count)

    def read_input_registers(self, unit_id: int, address: int, count: int = 1) -> ModbusProbeResult:
        return self._read_registers(unit_id, 0x04, address, count)

    def _read_registers(self, unit_id: int, function_code: int, address: int, count: int) -> ModbusProbeResult:
        pdu = struct.pack(">BHH", function_code, address & 0xFFFF, count & 0xFFFF)
        try:
            response = self._send_receive(pdu, unit_id)
        except Exception as exc:
            return ModbusProbeResult(
                host=self.host,
                port=self.port,
                unit_id=unit_id,
                function_code=function_code,
                success=False,
                raw_error=str(exc),
            )

        resp_fc = response[7]
        if resp_fc & 0x80:
            return ModbusProbeResult(
                host=self.host,
                port=self.port,
                unit_id=unit_id,
                function_code=function_code,
                success=False,
                error_code=response[8] if len(response) > 8 else None,
            )

        byte_count = response[8]
        values: List[int] = []
        data = response[9 : 9 + byte_count]
        for offset in range(0, len(data), 2):
            if offset + 1 < len(data):
                values.append(int.from_bytes(data[offset : offset + 2], "big"))
        return ModbusProbeResult(
            host=self.host,
            port=self.port,
            unit_id=unit_id,
            function_code=function_code,
            success=True,
            values=values,
        )

    def write_single_register(self, unit_id: int, address: int, value: int) -> ModbusProbeResult:
        pdu = struct.pack(">BHH", 0x06, address & 0xFFFF, value & 0xFFFF)
        try:
            response = self._send_receive(pdu, unit_id)
        except Exception as exc:
            return ModbusProbeResult(
                host=self.host,
                port=self.port,
                unit_id=unit_id,
                function_code=0x06,
                success=False,
                raw_error=str(exc),
            )

        resp_fc = response[7]
        if resp_fc & 0x80:
            return ModbusProbeResult(
                host=self.host,
                port=self.port,
                unit_id=unit_id,
                function_code=0x06,
                success=False,
                error_code=response[8] if len(response) > 8 else None,
            )
        return ModbusProbeResult(
            host=self.host,
            port=self.port,
            unit_id=unit_id,
            function_code=0x06,
            success=True,
            values=[value],
        )

    def scan_unit_ids(
        self,
        start: int = 1,
        end: int = 247,
        function_code: int = 0x03,
        address: int = 0,
        count: int = 1,
    ) -> List[ModbusProbeResult]:
        results: List[ModbusProbeResult] = []
        for unit_id in range(max(0, start), min(end, 255) + 1):
            if function_code == 0x04:
                result = self.read_input_registers(unit_id, address, count)
            else:
                result = self.read_holding_registers(unit_id, address, count)
            if result.success:
                results.append(result)
        return results


    def read_coils(self, unit_id: int, address: int, count: int = 1) -> ModbusProbeResult:
        pdu = struct.pack(">BHH", 0x01, address & 0xFFFF, count & 0xFFFF)
        return self._read_bits(unit_id, 0x01, pdu, count)

    def read_discrete_inputs(self, unit_id: int, address: int, count: int = 1) -> ModbusProbeResult:
        pdu = struct.pack(">BHH", 0x02, address & 0xFFFF, count & 0xFFFF)
        return self._read_bits(unit_id, 0x02, pdu, count)

    def _read_bits(self, unit_id: int, function_code: int, pdu: bytes, count: int) -> ModbusProbeResult:
        try:
            response = self._send_receive(pdu, unit_id)
        except Exception as exc:
            return ModbusProbeResult(
                host=self.host, port=self.port, unit_id=unit_id,
                function_code=function_code, success=False, raw_error=str(exc),
            )
        resp_fc = response[7]
        if resp_fc & 0x80:
            return ModbusProbeResult(
                host=self.host, port=self.port, unit_id=unit_id,
                function_code=function_code, success=False,
                error_code=response[8] if len(response) > 8 else None,
            )
        byte_count = response[8]
        bits = []
        data = response[9 : 9 + byte_count]
        for bit_index in range(count):
            byte = data[bit_index // 8] if bit_index // 8 < len(data) else 0
            bits.append(1 if byte & (1 << (bit_index % 8)) else 0)
        return ModbusProbeResult(
            host=self.host, port=self.port, unit_id=unit_id,
            function_code=function_code, success=True, values=bits,
        )

    def write_single_coil(self, unit_id: int, address: int, value: bool) -> ModbusProbeResult:
        coil_value = 0xFF00 if value else 0x0000
        pdu = struct.pack(">BHH", 0x05, address & 0xFFFF, coil_value)
        try:
            response = self._send_receive(pdu, unit_id)
        except Exception as exc:
            return ModbusProbeResult(
                host=self.host, port=self.port, unit_id=unit_id,
                function_code=0x05, success=False, raw_error=str(exc),
            )
        resp_fc = response[7]
        if resp_fc & 0x80:
            return ModbusProbeResult(
                host=self.host, port=self.port, unit_id=unit_id,
                function_code=0x05, success=False,
                error_code=response[8] if len(response) > 8 else None,
            )
        return ModbusProbeResult(
            host=self.host, port=self.port, unit_id=unit_id,
            function_code=0x05, success=True, values=[1 if value else 0],
        )

    def map_registers(
        self,
        unit_id: int,
        start: int,
        count: int,
        register_type: str = "holding",
    ) -> Dict[str, object]:
        register_type = (register_type or "holding").lower()
        readers = {
            "holding": self.read_holding_registers,
            "input": self.read_input_registers,
            "coil": self.read_coils,
            "discrete": self.read_discrete_inputs,
        }
        reader = readers.get(register_type, self.read_holding_registers)
        result = reader(unit_id, start, count)
        return {
            "unit_id": unit_id,
            "start": start,
            "count": count,
            "type": register_type,
            "success": result.success,
            "values": result.values,
            "error_code": result.error_code,
            "raw_error": result.raw_error,
        }


def identify_modbus_device(
    host: str,
    port: int = 502,
    timeout: float = 5.0,
    unit_start: int = 1,
    unit_end: int = 32,
) -> Dict[str, object]:
    client = ModbusTCPClient(host, port, timeout)
    if not client.connect():
        return {"reachable": False, "host": host, "port": port, "units": []}

    try:
        units = client.scan_unit_ids(unit_start, unit_end)
        return {
            "reachable": True,
            "host": host,
            "port": port,
            "units": [
                {
                    "unit_id": item.unit_id,
                    "registers": item.values[:8],
                    "function_code": item.function_code,
                }
                for item in units
            ],
        }
    finally:
        client.close()


def test_modbus_write_enabled(
    host: str,
    port: int = 502,
    timeout: float = 5.0,
    unit_id: int = 1,
    address: int = 0,
    test_value: int = 0x00A5,
) -> Dict[str, object]:
    client = ModbusTCPClient(host, port, timeout)
    if not client.connect():
        return {"reachable": False, "write_enabled": False, "reason": "connection failed"}

    try:
        read_before = client.read_holding_registers(unit_id, address, 1)
        original = read_before.values[0] if read_before.success and read_before.values else None
        write_result = client.write_single_register(unit_id, address, test_value)
        if not write_result.success:
            return {
                "reachable": True,
                "write_enabled": False,
                "unit_id": unit_id,
                "address": address,
                "reason": f"write rejected (exception {write_result.error_code})",
            }

        read_after = client.read_holding_registers(unit_id, address, 1)
        changed = read_after.success and read_after.values and read_after.values[0] == test_value

        if changed and original is not None and original != test_value:
            client.write_single_register(unit_id, address, original)

        return {
            "reachable": True,
            "write_enabled": bool(changed),
            "unit_id": unit_id,
            "address": address,
            "test_value": test_value,
            "restored": original is not None and original != test_value,
            "reason": "write accepted and verified" if changed else "write not verified",
        }
    finally:
        client.close()
