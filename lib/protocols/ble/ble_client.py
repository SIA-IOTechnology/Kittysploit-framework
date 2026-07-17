#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Synchronous BLE GATT client wrapper around bleak."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def bleak_available() -> bool:
    try:
        import bleak  # noqa: F401

        return True
    except ImportError:
        return False


def normalize_uuid(value: str) -> str:
    """Normalize short or full BLE UUIDs to canonical lowercase form."""
    text = str(value or "").strip().lower().replace("-", "")
    if not text:
        return ""
    if text.startswith("0x"):
        text = text[2:]
    if len(text) <= 8:
        # 16-bit or 32-bit UUID → Bluetooth base UUID
        text = text.zfill(8)
        return f"{text[:8]}-0000-1000-8000-00805f9b34fb"
    if len(text) == 32:
        return f"{text[0:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:32]}"
    # already dashed or custom
    raw = str(value or "").strip().lower()
    return raw


def props_list(char) -> List[str]:
    props = getattr(char, "properties", None)
    if props is None:
        return []
    if isinstance(props, (list, tuple, set)):
        return sorted(str(p) for p in props)
    # bleak CharacteristicProperties-like
    out = []
    for name in (
        "broadcast",
        "read",
        "write-without-response",
        "write",
        "notify",
        "indicate",
        "authenticated-signed-writes",
        "extended-properties",
        "reliable-write",
        "writable-auxiliaries",
    ):
        try:
            if name in props:
                out.append(name)
        except Exception:
            pass
    return out or sorted(str(p) for p in props)


@dataclass
class BleCharacteristicInfo:
    uuid: str
    handle: int = 0
    properties: List[str] = field(default_factory=list)
    description: str = ""
    descriptors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BleServiceInfo:
    uuid: str
    handle: int = 0
    description: str = ""
    characteristics: List[BleCharacteristicInfo] = field(default_factory=list)


@dataclass
class BleNotifyEvent:
    uuid: str
    data: bytes
    hex: str
    timestamp: float


class BleGattClient:
    """
    Persistent BLE GATT connection with a sync API for listeners / post modules.

    Runs an asyncio loop in a background thread so bleak can keep the link alive
    across multiple post-module calls.
    """

    def __init__(
        self,
        address: str,
        adapter: str = "",
        timeout: float = 20.0,
        name: str = "",
    ):
        self.address = str(address or "").strip()
        self.adapter = str(adapter or "").strip()
        self.timeout = float(timeout or 20)
        self.name = str(name or "")
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._client = None
        self._connected = False
        self._services_cache: List[BleServiceInfo] = []
        self._notify_events: List[BleNotifyEvent] = []
        self._notify_lock = threading.Lock()
        self._active_notifications: Dict[str, bool] = {}

    @property
    def connected(self) -> bool:
        if not self._connected or self._client is None:
            return False
        try:
            return bool(getattr(self._client, "is_connected", False))
        except Exception:
            return self._connected

    def connect(self) -> bool:
        if not bleak_available():
            raise RuntimeError("bleak is required (pip install bleak)")
        if not self.address:
            raise RuntimeError("BLE address is required")
        self._ensure_loop()
        try:
            self._run(self._connect_async())
            return self.connected
        except Exception:
            self._connected = False
            return False

    def close(self) -> None:
        try:
            if self._loop and self._client is not None:
                try:
                    self._run(self._disconnect_async(), timeout=min(10.0, self.timeout))
                except Exception:
                    pass
        finally:
            self._connected = False
            self._client = None
            self._stop_loop()

    def disconnect(self) -> None:
        self.close()

    def get_services(self, refresh: bool = False) -> List[BleServiceInfo]:
        self._require_connected()
        if self._services_cache and not refresh:
            return list(self._services_cache)
        services = self._run(self._get_services_async())
        self._services_cache = services
        return list(services)

    def find_characteristic(self, uuid: str) -> Optional[BleCharacteristicInfo]:
        target = normalize_uuid(uuid)
        for svc in self.get_services():
            for char in svc.characteristics:
                if normalize_uuid(char.uuid) == target or char.uuid.lower() == str(uuid).lower():
                    return char
        return None

    def read_characteristic(self, uuid: str) -> bytes:
        self._require_connected()
        return self._run(self._read_async(normalize_uuid(uuid) or uuid))

    def write_characteristic(
        self,
        uuid: str,
        data: bytes,
        response: Optional[bool] = None,
    ) -> bool:
        self._require_connected()
        return bool(
            self._run(
                self._write_async(normalize_uuid(uuid) or uuid, bytes(data), response=response)
            )
        )

    def start_notify(self, uuid: str) -> bool:
        self._require_connected()
        key = normalize_uuid(uuid) or uuid
        self._run(self._start_notify_async(key))
        self._active_notifications[key] = True
        return True

    def stop_notify(self, uuid: str) -> bool:
        self._require_connected()
        key = normalize_uuid(uuid) or uuid
        try:
            self._run(self._stop_notify_async(key))
        except Exception:
            pass
        self._active_notifications.pop(key, None)
        return True

    def clear_notifications(self) -> None:
        with self._notify_lock:
            self._notify_events.clear()

    def drain_notifications(self) -> List[BleNotifyEvent]:
        with self._notify_lock:
            events = list(self._notify_events)
            self._notify_events.clear()
            return events

    def capture_notifications(
        self,
        uuids: List[str],
        duration: float = 5.0,
        clear: bool = True,
    ) -> List[BleNotifyEvent]:
        """Subscribe to one or more characteristics and capture notifications for ``duration``."""
        self._require_connected()
        if clear:
            self.clear_notifications()
        started = []
        try:
            for uuid in uuids:
                key = normalize_uuid(uuid) or uuid
                self.start_notify(key)
                started.append(key)
            time.sleep(max(0.1, float(duration)))
            return self.drain_notifications()
        finally:
            for key in started:
                try:
                    self.stop_notify(key)
                except Exception:
                    pass

    def connection_summary(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "adapter": self.adapter,
            "timeout": self.timeout,
            "connected": self.connected,
            "services": len(self._services_cache),
            "active_notifications": list(self._active_notifications.keys()),
        }

    # --- internals ---

    def _require_connected(self) -> None:
        if not self.connected:
            raise RuntimeError("BLE GATT client is not connected")

    def _ensure_loop(self) -> None:
        if self._loop and self._thread and self._thread.is_alive():
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="ble-gatt-loop", daemon=True)
        self._thread.start()

    def _stop_loop(self) -> None:
        loop = self._loop
        self._loop = None
        if loop is not None:
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def _run(self, coro, timeout: Optional[float] = None):
        if not self._loop:
            raise RuntimeError("BLE event loop not running")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=timeout if timeout is not None else self.timeout + 5)
        except KeyboardInterrupt:
            fut.cancel()
            try:
                # Best-effort disconnect without blocking forever
                if self._client is not None:
                    disc = asyncio.run_coroutine_threadsafe(self._disconnect_async(), self._loop)
                    disc.result(timeout=2)
            except Exception:
                pass
            self._connected = False
            raise

    async def _connect_async(self):
        from bleak import BleakClient

        # adapter kw differs by platform/version; pass when set
        if self.adapter:
            try:
                self._client = BleakClient(self.address, adapter=self.adapter, timeout=self.timeout)
            except TypeError:
                self._client = BleakClient(self.address, timeout=self.timeout)
        else:
            self._client = BleakClient(self.address, timeout=self.timeout)

        await self._client.connect()
        self._connected = bool(getattr(self._client, "is_connected", True))
        # Warm services cache
        try:
            self._services_cache = await self._get_services_async()
        except Exception:
            self._services_cache = []
        return self._connected

    async def _disconnect_async(self):
        if self._client is not None:
            for uuid in list(self._active_notifications.keys()):
                try:
                    await self._client.stop_notify(uuid)
                except Exception:
                    pass
            self._active_notifications.clear()
            try:
                await self._client.disconnect()
            except Exception:
                pass

    async def _get_services_async(self) -> List[BleServiceInfo]:
        client = self._client
        services_obj = getattr(client, "services", None)
        if services_obj is None or (hasattr(services_obj, "__len__") and len(services_obj) == 0):
            get_services = getattr(client, "get_services", None)
            if callable(get_services):
                services_obj = await get_services()

        result: List[BleServiceInfo] = []
        iterable = services_obj
        if hasattr(services_obj, "services"):
            iterable = services_obj.services.values() if hasattr(services_obj.services, "values") else services_obj.services
        elif isinstance(services_obj, dict):
            iterable = services_obj.values()

        for svc in iterable or []:
            chars: List[BleCharacteristicInfo] = []
            for char in getattr(svc, "characteristics", []) or []:
                descriptors = []
                for desc in getattr(char, "descriptors", []) or []:
                    descriptors.append(
                        {
                            "uuid": str(getattr(desc, "uuid", "")),
                            "handle": int(getattr(desc, "handle", 0) or 0),
                        }
                    )
                chars.append(
                    BleCharacteristicInfo(
                        uuid=str(getattr(char, "uuid", "")),
                        handle=int(getattr(char, "handle", 0) or 0),
                        properties=props_list(char),
                        description=str(getattr(char, "description", "") or ""),
                        descriptors=descriptors,
                    )
                )
            result.append(
                BleServiceInfo(
                    uuid=str(getattr(svc, "uuid", "")),
                    handle=int(getattr(svc, "handle", 0) or 0),
                    description=str(getattr(svc, "description", "") or ""),
                    characteristics=chars,
                )
            )
        return result

    async def _read_async(self, uuid: str) -> bytes:
        data = await self._client.read_gatt_char(uuid)
        return bytes(data)

    async def _write_async(self, uuid: str, data: bytes, response: Optional[bool]) -> bool:
        kwargs = {}
        if response is not None:
            kwargs["response"] = bool(response)
        await self._client.write_gatt_char(uuid, data, **kwargs)
        return True

    def _on_notify(self, sender, data: bytearray):
        uuid = str(getattr(sender, "uuid", sender))
        payload = bytes(data)
        event = BleNotifyEvent(
            uuid=uuid,
            data=payload,
            hex=payload.hex(),
            timestamp=time.time(),
        )
        with self._notify_lock:
            self._notify_events.append(event)
            # Cap buffer to avoid unbounded growth
            if len(self._notify_events) > 5000:
                self._notify_events = self._notify_events[-2500:]

    async def _start_notify_async(self, uuid: str):
        await self._client.start_notify(uuid, self._on_notify)

    async def _stop_notify_async(self, uuid: str):
        await self._client.stop_notify(uuid)
