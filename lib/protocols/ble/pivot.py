#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE UART / serial-over-GATT pivot helpers (Nordic NUS and common clones)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lib.protocols.ble.ble_client import BleGattClient, normalize_uuid


# Known BLE serial / UART service profiles (write = to device, notify = from device)
UART_PROFILES: Tuple[Dict[str, str], ...] = (
    {
        "name": "nordic_nus",
        "service": "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
        "rx_write": "6e400002-b5a3-f393-e0a9-e50e24dcca9e",  # central → peripheral
        "tx_notify": "6e400003-b5a3-f393-e0a9-e50e24dcca9e",  # peripheral → central
    },
    {
        "name": "nordic_nus_legacy",
        "service": "00001530-1212-efde-1523-785feabcd123",
        "rx_write": "00001532-1212-efde-1523-785feabcd123",
        "tx_notify": "00001531-1212-efde-1523-785feabcd123",
    },
    {
        # Texas Instruments SimpleLink serial
        "name": "ti_serial",
        "service": "0000fff0-0000-1000-8000-00805f9b34fb",
        "rx_write": "0000fff2-0000-1000-8000-00805f9b34fb",
        "tx_notify": "0000fff1-0000-1000-8000-00805f9b34fb",
    },
    {
        # Generic FF00-style UART used by many modules
        "name": "generic_ff00",
        "service": "0000ff00-0000-1000-8000-00805f9b34fb",
        "rx_write": "0000ff01-0000-1000-8000-00805f9b34fb",
        "tx_notify": "0000ff02-0000-1000-8000-00805f9b34fb",
    },
)


@dataclass
class BleUartEndpoint:
    name: str = ""
    service: str = ""
    write_uuid: str = ""
    notify_uuid: str = ""
    write_props: List[str] = field(default_factory=list)
    notify_props: List[str] = field(default_factory=list)


@dataclass
class BleUartProbeResult:
    found: bool = False
    endpoints: List[BleUartEndpoint] = field(default_factory=list)
    primary: Optional[BleUartEndpoint] = None
    error: str = ""


@dataclass
class BleUartExecResult:
    command: str = ""
    sent: bool = False
    response: bytes = b""
    text: str = ""
    notify_chunks: int = 0
    error: str = ""


def _uuid_match(a: str, b: str) -> bool:
    return normalize_uuid(a) == normalize_uuid(b) or str(a).lower() == str(b).lower()


def discover_uart_endpoints(client: BleGattClient) -> BleUartProbeResult:
    """Scan GATT map for known UART profiles or write+notify pairs on one service."""
    result = BleUartProbeResult()
    try:
        services = client.get_services(refresh=False) or client.get_services(refresh=True)
    except Exception as exc:
        result.error = str(exc)
        return result

    # Known profiles first
    for profile in UART_PROFILES:
        svc_uuid = profile["service"]
        write_uuid = profile["rx_write"]
        notify_uuid = profile["tx_notify"]
        write_char = client.find_characteristic(write_uuid)
        notify_char = client.find_characteristic(notify_uuid)
        if not write_char or not notify_char:
            # also accept if service exists with matching chars under different casing
            svc = next((s for s in services if _uuid_match(s.uuid, svc_uuid)), None)
            if not svc:
                continue
            write_char = write_char or next(
                (c for c in svc.characteristics if _uuid_match(c.uuid, write_uuid)), None
            )
            notify_char = notify_char or next(
                (c for c in svc.characteristics if _uuid_match(c.uuid, notify_uuid)), None
            )
        if write_char and notify_char:
            endpoint = BleUartEndpoint(
                name=profile["name"],
                service=svc_uuid,
                write_uuid=normalize_uuid(write_char.uuid) or write_char.uuid,
                notify_uuid=normalize_uuid(notify_char.uuid) or notify_char.uuid,
                write_props=list(write_char.properties),
                notify_props=list(notify_char.properties),
            )
            result.endpoints.append(endpoint)

    # Heuristic: service with one writable + one notify/indicate char
    for svc in services:
        writables = [
            c
            for c in svc.characteristics
            if any(p in ("write", "write-without-response") for p in (x.lower() for x in c.properties))
        ]
        notifiables = [
            c
            for c in svc.characteristics
            if any(p in ("notify", "indicate") for p in (x.lower() for x in c.properties))
        ]
        if not writables or not notifiables:
            continue
        # skip if already covered by known profile
        already = any(
            _uuid_match(e.write_uuid, writables[0].uuid) and _uuid_match(e.notify_uuid, notifiables[0].uuid)
            for e in result.endpoints
        )
        if already:
            continue
        # Prefer services that look serial-ish
        svc_l = svc.uuid.lower()
        if not any(tok in svc_l for tok in ("fff", "ff0", "uart", "serial", "6e40", "1530")):
            if len(svc.characteristics) > 6:
                continue
        endpoint = BleUartEndpoint(
            name="heuristic",
            service=normalize_uuid(svc.uuid) or svc.uuid,
            write_uuid=normalize_uuid(writables[0].uuid) or writables[0].uuid,
            notify_uuid=normalize_uuid(notifiables[0].uuid) or notifiables[0].uuid,
            write_props=list(writables[0].properties),
            notify_props=list(notifiables[0].properties),
        )
        result.endpoints.append(endpoint)

    # Dedupe by write+notify pair
    seen = set()
    unique: List[BleUartEndpoint] = []
    for ep in result.endpoints:
        key = (normalize_uuid(ep.write_uuid), normalize_uuid(ep.notify_uuid))
        if key in seen:
            continue
        seen.add(key)
        unique.append(ep)
    result.endpoints = unique
    result.found = bool(unique)
    if unique:
        # Prefer nordic_nus
        preferred = next((e for e in unique if e.name.startswith("nordic")), unique[0])
        result.primary = preferred
    return result


class BleUartPivot:
    """Interactive UART-over-GATT channel on a connected BleGattClient."""

    def __init__(
        self,
        client: BleGattClient,
        *,
        write_uuid: str = "",
        notify_uuid: str = "",
        mtu_chunk: int = 20,
    ):
        self.client = client
        self.write_uuid = normalize_uuid(write_uuid) or write_uuid
        self.notify_uuid = normalize_uuid(notify_uuid) or notify_uuid
        self.mtu_chunk = max(1, int(mtu_chunk or 20))
        self._notify_active = False
        self.profile_name = ""

    @classmethod
    def auto(cls, client: BleGattClient, mtu_chunk: int = 20) -> "BleUartPivot":
        probe = discover_uart_endpoints(client)
        if not probe.primary:
            raise RuntimeError(probe.error or "No BLE UART/NUS endpoint found")
        pivot = cls(
            client,
            write_uuid=probe.primary.write_uuid,
            notify_uuid=probe.primary.notify_uuid,
            mtu_chunk=mtu_chunk,
        )
        pivot.profile_name = probe.primary.name
        return pivot

    def start(self) -> None:
        if not self.write_uuid or not self.notify_uuid:
            raise RuntimeError("write_uuid and notify_uuid required")
        self.client.clear_notifications()
        self.client.start_notify(self.notify_uuid)
        self._notify_active = True

    def stop(self) -> None:
        if self._notify_active and self.notify_uuid:
            try:
                self.client.stop_notify(self.notify_uuid)
            except Exception:
                pass
        self._notify_active = False

    def send(self, data: bytes, response: Optional[bool] = None) -> bool:
        if not data:
            return True
        if not self._notify_active:
            self.start()
        # Chunk to typical ATT default (20) unless larger negotiated
        ok = True
        for i in range(0, len(data), self.mtu_chunk):
            chunk = data[i : i + self.mtu_chunk]
            if not self.client.write_characteristic(self.write_uuid, chunk, response=response):
                ok = False
        return ok

    def send_text(self, text: str, newline: bool = True) -> bool:
        payload = str(text or "")
        if newline and not payload.endswith("\n"):
            payload += "\n"
        return self.send(payload.encode("utf-8", errors="replace"))

    def recv(self, timeout: float = 2.0, idle: float = 0.35) -> bytes:
        """Collect notify payloads until idle gap or timeout."""
        if not self._notify_active:
            self.start()
        deadline = time.time() + max(0.2, float(timeout))
        buf = bytearray()
        last_data = time.time()
        while time.time() < deadline:
            events = self.client.drain_notifications()
            if events:
                for ev in events:
                    if self.notify_uuid and not _uuid_match(ev.uuid, self.notify_uuid):
                        # still accept if uuid normalization differs
                        pass
                    buf.extend(ev.data)
                last_data = time.time()
            elif buf and (time.time() - last_data) >= float(idle):
                break
            else:
                time.sleep(0.05)
        return bytes(buf)

    def exec_command(
        self,
        command: str,
        *,
        timeout: float = 3.0,
        newline: bool = True,
        clear: bool = True,
    ) -> BleUartExecResult:
        result = BleUartExecResult(command=str(command or ""))
        if not result.command.strip():
            result.error = "empty command"
            return result
        try:
            if clear:
                self.client.clear_notifications()
            if not self._notify_active:
                self.start()
            result.sent = self.send_text(result.command, newline=newline)
            if not result.sent:
                result.error = "write failed"
                return result
            raw = self.recv(timeout=timeout)
            result.response = raw
            result.text = raw.decode("utf-8", errors="replace")
            result.notify_chunks = 1 if raw else 0
            return result
        except Exception as exc:
            result.error = str(exc)
            return result

    def summary(self) -> Dict[str, str]:
        return {
            "profile": self.profile_name or "custom",
            "write_uuid": self.write_uuid,
            "notify_uuid": self.notify_uuid,
            "mtu_chunk": str(self.mtu_chunk),
            "notify_active": str(self._notify_active),
        }
