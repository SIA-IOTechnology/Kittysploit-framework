#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active DoIP (ISO 13400) client with UDS-over-DoIP helpers."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from lib.protocols.doip.constants import (
    DOIP_ACTIVATION_DEFAULT,
    DOIP_DEFAULT_PORT,
    DOIP_DIAGNOSTIC_MESSAGE,
    DOIP_DIAGNOSTIC_MESSAGE_ACK,
    DOIP_DIAGNOSTIC_MESSAGE_NACK,
    DOIP_FUNCTIONAL_ADDRESS,
    DOIP_HEADER_SIZE,
    DOIP_INVERSE_PROTOCOL_VERSION,
    DOIP_PROTOCOL_VERSION,
    DOIP_ROUTING_ACTIVATION_REQUEST,
    DOIP_ROUTING_ACTIVATION_RESPONSE,
    DOIP_ROUTING_ALREADY_ACTIVE,
    DOIP_ROUTING_RESPONSE_NAMES,
    DOIP_ROUTING_SUCCESS,
    DOIP_TESTER_ADDRESS_DEFAULT,
    DOIP_VEHICLE_ANNOUNCEMENT,
    DOIP_VEHICLE_ID_REQUEST,
    UDS_DID_VIN,
    UDS_DTC_REPORT_BY_STATUS_MASK,
    UDS_NEGATIVE_RESPONSE,
    UDS_NRC_NAMES,
    UDS_READ_DATA_BY_IDENTIFIER,
    UDS_READ_DTC_INFORMATION,
    UDS_TESTER_PRESENT,
)


@dataclass
class DoIPMessage:
    payload_type: int
    payload: bytes
    protocol_version: int = DOIP_PROTOCOL_VERSION


@dataclass
class DoIPUdsResult:
    success: bool
    request: bytes = b""
    response: bytes = b""
    service: int = 0
    nrc: Optional[int] = None
    nrc_name: str = ""
    data: bytes = b""
    raw_error: str = ""
    source_address: int = 0
    target_address: int = 0


@dataclass
class DoIPVehicleInfo:
    vin: str = ""
    logical_address: int = 0
    eid: bytes = b""
    gid: bytes = b""
    further_action: int = 0
    vin_sync: int = 0
    raw: bytes = b""


@dataclass
class DoIPEcuProbe:
    address: int
    responsive: bool
    response: bytes = b""
    nrc: Optional[int] = None
    error: str = ""


@dataclass
class DoIPDtcRecord:
    code: str
    raw: int
    status: int
    status_hex: str = ""


class DoIPClient:
    """TCP DoIP client: routing activation + diagnostic (UDS) exchange."""

    def __init__(
        self,
        host: str,
        port: int = DOIP_DEFAULT_PORT,
        timeout: float = 5.0,
        source_address: int = DOIP_TESTER_ADDRESS_DEFAULT,
        target_address: int = 0x0000,
        activation_type: int = DOIP_ACTIVATION_DEFAULT,
        protocol_version: int = DOIP_PROTOCOL_VERSION,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.source_address = int(source_address) & 0xFFFF
        self.target_address = int(target_address) & 0xFFFF
        self.activation_type = int(activation_type) & 0xFF
        self.protocol_version = int(protocol_version) & 0xFF
        self.inverse_protocol_version = (~self.protocol_version) & 0xFF
        self.entity_address: Optional[int] = None
        self.routing_active = False
        self._sock: Optional[socket.socket] = None
        self._rx_buffer = bytearray()

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self, activate: bool = True) -> bool:
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            return False
        self._sock = sock
        self._rx_buffer.clear()
        if activate:
            ok, _ = self.routing_activation()
            return ok
        return True

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self.routing_active = False
        self._rx_buffer.clear()

    def _build_header(self, payload_type: int, payload_length: int) -> bytes:
        return struct.pack(
            ">BBHI",
            self.protocol_version,
            self.inverse_protocol_version,
            payload_type & 0xFFFF,
            payload_length & 0xFFFFFFFF,
        )

    def _send_message(self, payload_type: int, payload: bytes = b"") -> None:
        if not self._sock:
            raise RuntimeError("Not connected")
        frame = self._build_header(payload_type, len(payload)) + payload
        self._sock.sendall(frame)

    def _recv_exact(self, size: int) -> bytes:
        if not self._sock:
            raise RuntimeError("Not connected")
        while len(self._rx_buffer) < size:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("DoIP connection closed")
            self._rx_buffer.extend(chunk)
        data = bytes(self._rx_buffer[:size])
        del self._rx_buffer[:size]
        return data

    def _recv_message(self, expect_types: Optional[Tuple[int, ...]] = None) -> DoIPMessage:
        pending_deadline = self.timeout
        self._sock.settimeout(pending_deadline)  # type: ignore[union-attr]
        while True:
            header = self._recv_exact(DOIP_HEADER_SIZE)
            version, inv, payload_type, length = struct.unpack(">BBHI", header)
            if inv != ((~version) & 0xFF):
                raise RuntimeError(f"Invalid DoIP inverse protocol version: {inv:#04x}")
            payload = self._recv_exact(length) if length else b""
            msg = DoIPMessage(payload_type=payload_type, payload=payload, protocol_version=version)
            if expect_types is None or payload_type in expect_types:
                return msg
            # Skip unexpected frames (ACK/alive) and keep waiting for expected type

    def routing_activation(self) -> Tuple[bool, Dict]:
        """Send Routing Activation Request and parse response."""
        payload = struct.pack(
            ">HBI",
            self.source_address,
            self.activation_type,
            0,  # reserved ISO
        )
        try:
            self._send_message(DOIP_ROUTING_ACTIVATION_REQUEST, payload)
            msg = self._recv_message((DOIP_ROUTING_ACTIVATION_RESPONSE,))
        except Exception as exc:
            return False, {"error": str(exc)}

        if len(msg.payload) < 5:
            return False, {"error": "routing activation response too short", "raw": msg.payload.hex()}

        tester_addr, entity_addr, code = struct.unpack(">HHB", msg.payload[:5])
        self.entity_address = entity_addr
        if self.target_address == 0 and entity_addr:
            self.target_address = entity_addr
        ok = code in (DOIP_ROUTING_SUCCESS, DOIP_ROUTING_ALREADY_ACTIVE)
        self.routing_active = ok
        return ok, {
            "tester_address": tester_addr,
            "entity_address": entity_addr,
            "response_code": code,
            "response_name": DOIP_ROUTING_RESPONSE_NAMES.get(code, f"unknown ({code:#04x})"),
            "raw": msg.payload.hex(),
        }

    def send_diagnostic(
        self,
        user_data: bytes,
        target_address: Optional[int] = None,
        source_address: Optional[int] = None,
        wait_ack: bool = True,
    ) -> DoIPUdsResult:
        """Send a UDS PDU inside a DoIP diagnostic message and wait for the response."""
        src = int(source_address if source_address is not None else self.source_address) & 0xFFFF
        dst = int(target_address if target_address is not None else self.target_address) & 0xFFFF
        if not user_data:
            return DoIPUdsResult(success=False, raw_error="empty UDS payload", source_address=src, target_address=dst)

        payload = struct.pack(">HH", src, dst) + bytes(user_data)
        try:
            self._send_message(DOIP_DIAGNOSTIC_MESSAGE, payload)
            if wait_ack:
                # Optional ACK/NACK may arrive before the diagnostic response
                msg = self._recv_message(
                    (
                        DOIP_DIAGNOSTIC_MESSAGE,
                        DOIP_DIAGNOSTIC_MESSAGE_ACK,
                        DOIP_DIAGNOSTIC_MESSAGE_NACK,
                    )
                )
                if msg.payload_type == DOIP_DIAGNOSTIC_MESSAGE_NACK:
                    nack = msg.payload[4] if len(msg.payload) > 4 else None
                    return DoIPUdsResult(
                        success=False,
                        request=bytes(user_data),
                        raw_error=f"DoIP diagnostic NACK ({nack})",
                        source_address=src,
                        target_address=dst,
                    )
                if msg.payload_type == DOIP_DIAGNOSTIC_MESSAGE_ACK:
                    msg = self._recv_message((DOIP_DIAGNOSTIC_MESSAGE,))
            else:
                msg = self._recv_message((DOIP_DIAGNOSTIC_MESSAGE,))
        except Exception as exc:
            return DoIPUdsResult(
                success=False,
                request=bytes(user_data),
                raw_error=str(exc),
                source_address=src,
                target_address=dst,
            )

        if len(msg.payload) < 5:
            return DoIPUdsResult(
                success=False,
                request=bytes(user_data),
                raw_error="diagnostic response too short",
                response=msg.payload,
                source_address=src,
                target_address=dst,
            )

        resp_src, resp_dst = struct.unpack(">HH", msg.payload[:4])
        uds = msg.payload[4:]
        return self._parse_uds(bytes(user_data), uds, resp_src, resp_dst)

    def _parse_uds(self, request: bytes, response: bytes, src: int, dst: int) -> DoIPUdsResult:
        if not response:
            return DoIPUdsResult(success=False, request=request, raw_error="empty UDS response", source_address=src, target_address=dst)

        # Handle response pending (0x78) by waiting for the final response
        if (
            len(response) >= 3
            and response[0] == UDS_NEGATIVE_RESPONSE
            and response[2] == 0x78
        ):
            try:
                msg = self._recv_message((DOIP_DIAGNOSTIC_MESSAGE,))
                if len(msg.payload) >= 5:
                    src, dst = struct.unpack(">HH", msg.payload[:4])
                    response = msg.payload[4:]
            except Exception as exc:
                return DoIPUdsResult(
                    success=False,
                    request=request,
                    response=response,
                    service=request[0] if request else 0,
                    nrc=0x78,
                    nrc_name=UDS_NRC_NAMES.get(0x78, "responsePending"),
                    raw_error=str(exc),
                    source_address=src,
                    target_address=dst,
                )

        if response[0] == UDS_NEGATIVE_RESPONSE and len(response) >= 3:
            service = response[1]
            nrc = response[2]
            return DoIPUdsResult(
                success=False,
                request=request,
                response=response,
                service=service,
                nrc=nrc,
                nrc_name=UDS_NRC_NAMES.get(nrc, f"NRC_{nrc:#04x}"),
                source_address=src,
                target_address=dst,
            )

        service = request[0] if request else 0
        expected_pos = (service | 0x40) & 0xFF
        if response[0] != expected_pos and service:
            return DoIPUdsResult(
                success=False,
                request=request,
                response=response,
                service=service,
                raw_error=f"unexpected positive response SID {response[0]:#04x}, expected {expected_pos:#04x}",
                source_address=src,
                target_address=dst,
            )

        return DoIPUdsResult(
            success=True,
            request=request,
            response=response,
            service=service,
            data=response[1:],
            source_address=src,
            target_address=dst,
        )

    def tester_present(self, target_address: Optional[int] = None, suppress: bool = False) -> DoIPUdsResult:
        sub = 0x80 if suppress else 0x00
        return self.send_diagnostic(bytes([UDS_TESTER_PRESENT, sub]), target_address=target_address)

    def read_data_by_identifier(self, did: int, target_address: Optional[int] = None) -> DoIPUdsResult:
        did = int(did) & 0xFFFF
        req = struct.pack(">BH", UDS_READ_DATA_BY_IDENTIFIER, did)
        result = self.send_diagnostic(req, target_address=target_address)
        if result.success and len(result.response) >= 3:
            # response: 62 DID_H DID_L data...
            result.data = result.response[3:]
        return result

    def read_vin(self, target_address: Optional[int] = None) -> Tuple[Optional[str], DoIPUdsResult]:
        result = self.read_data_by_identifier(UDS_DID_VIN, target_address=target_address)
        if not result.success:
            return None, result
        vin = result.data.decode("ascii", errors="ignore").strip("\x00 ").strip()
        return vin or None, result

    def read_dtcs(
        self,
        status_mask: int = 0xFF,
        target_address: Optional[int] = None,
        sub_function: int = UDS_DTC_REPORT_BY_STATUS_MASK,
    ) -> Tuple[List[DoIPDtcRecord], DoIPUdsResult]:
        req = bytes([UDS_READ_DTC_INFORMATION, int(sub_function) & 0xFF, int(status_mask) & 0xFF])
        result = self.send_diagnostic(req, target_address=target_address)
        if not result.success:
            return [], result

        # Positive: 59 SF [statusAvailabilityMask] DTC* (3 bytes + status)
        body = result.response[1:]  # drop positive SID
        if len(body) < 1:
            return [], result
        offset = 1  # sub-function
        if sub_function in (UDS_DTC_REPORT_BY_STATUS_MASK, 0x01, 0x0A) and len(body) > 1:
            offset = 2  # skip SF + statusAvailabilityMask

        records: List[DoIPDtcRecord] = []
        chunk = body[offset:]
        for i in range(0, len(chunk) - 3, 4):
            raw = (chunk[i] << 16) | (chunk[i + 1] << 8) | chunk[i + 2]
            status = chunk[i + 3]
            records.append(
                DoIPDtcRecord(
                    code=self.format_dtc(raw),
                    raw=raw,
                    status=status,
                    status_hex=f"0x{status:02X}",
                )
            )
        return records, result

    @staticmethod
    def format_dtc(raw: int) -> str:
        """Format a 24-bit UDS DTC into SAE J2012 style (e.g. P0301)."""
        raw &= 0xFFFFFF
        b1 = (raw >> 16) & 0xFF
        b2 = (raw >> 8) & 0xFF
        b3 = raw & 0xFF
        letter = {0: "P", 1: "C", 2: "B", 3: "U"}.get((b1 >> 6) & 0x03, "P")
        digit1 = (b1 >> 4) & 0x03
        digit2 = b1 & 0x0F
        # Classic display uses first two bytes; third byte is often FTB
        base = f"{letter}{digit1}{digit2:X}{b2:02X}"
        if b3:
            return f"{base}-{b3:02X}"
        return base

    def probe_ecu(self, address: int) -> DoIPEcuProbe:
        result = self.tester_present(target_address=address)
        return DoIPEcuProbe(
            address=address & 0xFFFF,
            responsive=result.success,
            response=result.response,
            nrc=result.nrc,
            error=result.raw_error or result.nrc_name,
        )

    def discover_ecus(
        self,
        start: int = 0x0001,
        end: int = 0x00FF,
        step: int = 1,
        include_functional: bool = True,
    ) -> List[DoIPEcuProbe]:
        hits: List[DoIPEcuProbe] = []
        addresses = list(range(int(start) & 0xFFFF, (int(end) & 0xFFFF) + 1, max(1, int(step))))
        if include_functional and DOIP_FUNCTIONAL_ADDRESS not in addresses:
            addresses.append(DOIP_FUNCTIONAL_ADDRESS)
        # Also try entity address from routing activation
        if self.entity_address and self.entity_address not in addresses:
            addresses.insert(0, self.entity_address)

        for addr in addresses:
            probe = self.probe_ecu(addr)
            if probe.responsive or probe.nrc is not None:
                # NRC still proves an ECU is listening
                if probe.responsive or probe.nrc not in (None,):
                    hits.append(probe)
        return hits

    def request_vehicle_identification_udp(
        self,
        broadcast: str = "255.255.255.255",
        listen_timeout: float = 2.0,
    ) -> List[DoIPVehicleInfo]:
        """UDP vehicle identification request (optional discovery helper)."""
        payload = self._build_header(DOIP_VEHICLE_ID_REQUEST, 0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(listen_timeout)
        vehicles: List[DoIPVehicleInfo] = []
        try:
            sock.bind(("", 0))
            sock.sendto(payload, (broadcast, self.port))
            while True:
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(data) < DOIP_HEADER_SIZE:
                    continue
                _v, _i, ptype, length = struct.unpack(">BBHI", data[:DOIP_HEADER_SIZE])
                if ptype != DOIP_VEHICLE_ANNOUNCEMENT:
                    continue
                body = data[DOIP_HEADER_SIZE : DOIP_HEADER_SIZE + length]
                vehicles.append(self._parse_vehicle_announcement(body))
        finally:
            sock.close()
        return vehicles

    @staticmethod
    def _parse_vehicle_announcement(payload: bytes) -> DoIPVehicleInfo:
        info = DoIPVehicleInfo(raw=payload)
        if len(payload) < 32:
            return info
        info.vin = payload[0:17].decode("ascii", errors="ignore").strip("\x00 ")
        info.logical_address = struct.unpack(">H", payload[17:19])[0]
        info.eid = payload[19:25]
        info.gid = payload[25:31]
        info.further_action = payload[31]
        if len(payload) > 32:
            info.vin_sync = payload[32]
        return info
