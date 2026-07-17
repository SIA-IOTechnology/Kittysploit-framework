#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE GATT session helpers for post-exploitation modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from lib.protocols.ble.ble_client import BleGattClient


class BleSessionMixin:
    """Resolve live BleGattClient instances from framework session registries."""

    def _opt_value(self, name: str):
        attr = getattr(self, name, None)
        if attr is None:
            return None
        return attr.value if hasattr(attr, "value") else attr

    def _resolve_session(self):
        if hasattr(self, "session") and self.session:
            return self.session
        session_id = self._opt_value("session_id")
        framework = getattr(self, "framework", None)
        if session_id and framework and hasattr(framework, "session_manager"):
            return framework.session_manager.get_session(str(session_id))
        return None

    def _session_id(self, session) -> str:
        return str(getattr(session, "session_id", getattr(session, "id", "")) or "")

    def _session_data(self, session) -> Dict[str, Any]:
        data = getattr(session, "data", None)
        return data if isinstance(data, dict) else {}

    def _ble_registry(self):
        framework = getattr(self, "framework", None)
        if not framework:
            return {}
        registry = getattr(framework, "_ble_session_clients", None)
        if registry is None:
            framework._ble_session_clients = {}
            registry = framework._ble_session_clients
        return registry

    def _client_from_listener(self, session) -> Optional[BleGattClient]:
        framework = getattr(self, "framework", None)
        if not framework:
            return None
        data = self._session_data(session)
        listener_id = data.get("listener_id")
        session_id = self._session_id(session)
        if not listener_id or not session_id:
            return None
        listener = getattr(framework, "active_listeners", {}).get(listener_id)
        if not listener or not hasattr(listener, "_session_connections"):
            return None
        conn = listener._session_connections.get(session_id)
        return conn if isinstance(conn, BleGattClient) else None

    def get_ble_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "address": data.get("address") or getattr(session, "host", "") or "",
                "adapter": data.get("adapter") or "",
                "timeout": float(data.get("timeout") or 20),
                "name": data.get("name") or "",
            }
        return {
            "address": str(self._opt_value("address") or self._opt_value("rhost") or ""),
            "adapter": str(self._opt_value("adapter") or ""),
            "timeout": float(self._opt_value("timeout") or 20),
            "name": str(self._opt_value("name") or ""),
        }

    def _build_ble_client(self, info: Dict[str, Any]) -> BleGattClient:
        return BleGattClient(
            address=str(info.get("address") or ""),
            adapter=str(info.get("adapter") or ""),
            timeout=float(info.get("timeout") or 20),
            name=str(info.get("name") or ""),
        )

    def get_ble_client(self) -> BleGattClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ble_registry().get(session_id)
            if isinstance(registry_client, BleGattClient) and registry_client.connected:
                return registry_client

            listener_client = self._client_from_listener(session)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_ble_connection_info()
            if info.get("address"):
                client = self._build_ble_client(info)
                if client.connect():
                    self._ble_registry()[session_id] = client
                    return client

        info = self.get_ble_connection_info()
        if info.get("address"):
            client = self._build_ble_client(info)
            if client.connect():
                return client

        raise RuntimeError("No BLE session and no device address configured.")

    def open_ble(self) -> BleGattClient:
        return self.get_ble_client()

    def close_ble_client(self, session_id: str) -> None:
        framework = getattr(self, "framework", None)
        if not framework:
            return
        registry = getattr(framework, "_ble_session_clients", None) or {}
        client = registry.pop(session_id, None)
        if client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass
