#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""UART session helpers for post-exploitation modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from lib.protocols.hardware.uart_client import UartClient


class UartSessionMixin:
    """Resolve live UartClient instances from framework session registries."""

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

    def _uart_registry(self):
        framework = getattr(self, "framework", None)
        if not framework:
            return {}
        registry = getattr(framework, "_uart_session_clients", None)
        if registry is None:
            framework._uart_session_clients = {}
            registry = framework._uart_session_clients
        return registry

    def _client_from_listener(self, session) -> Optional[UartClient]:
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
        return conn if isinstance(conn, UartClient) else None

    def get_uart_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            port = (
                data.get("device")
                or data.get("port_name")
                or data.get("serial_port")
                or getattr(session, "host", "")
                or ""
            )
            return {
                "port": str(port),
                "baudrate": int(data.get("baudrate") or data.get("baud") or getattr(session, "port", None) or 115200),
                "bytesize": int(data.get("bytesize") or 8),
                "parity": str(data.get("parity") or "N"),
                "stopbits": float(data.get("stopbits") or 1),
                "timeout": float(data.get("timeout") or 1.0),
                "xonxoff": bool(data.get("xonxoff", False)),
                "rtscts": bool(data.get("rtscts", False)),
                "dsrdtr": bool(data.get("dsrdtr", False)),
            }
        port = self._opt_value("port") or self._opt_value("device") or self._opt_value("rhost")
        return {
            "port": str(port or ""),
            "baudrate": int(self._opt_value("baudrate") or self._opt_value("baud") or 115200),
            "bytesize": int(self._opt_value("bytesize") or 8),
            "parity": str(self._opt_value("parity") or "N"),
            "stopbits": float(self._opt_value("stopbits") or 1),
            "timeout": float(self._opt_value("timeout") or 1.0),
            "xonxoff": bool(self._opt_value("xonxoff") or False),
            "rtscts": bool(self._opt_value("rtscts") or False),
            "dsrdtr": bool(self._opt_value("dsrdtr") or False),
        }

    def _build_uart_client(self, info: Dict[str, Any]) -> UartClient:
        return UartClient(
            str(info.get("port") or ""),
            int(info.get("baudrate") or 115200),
            int(info.get("bytesize") or 8),
            str(info.get("parity") or "N"),
            float(info.get("stopbits") or 1),
            float(info.get("timeout") or 1.0),
            float(info.get("write_timeout") or info.get("timeout") or 1.0),
            bool(info.get("xonxoff", False)),
            bool(info.get("rtscts", False)),
            bool(info.get("dsrdtr", False)),
        )

    def get_uart_client(self) -> UartClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._uart_registry().get(session_id)
            if isinstance(registry_client, UartClient) and registry_client.connected:
                return registry_client

            listener_client = self._client_from_listener(session)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_uart_connection_info()
            if info.get("port"):
                client = self._build_uart_client(info)
                if client.connect():
                    self._uart_registry()[session_id] = client
                    return client

        port = self._opt_value("port") or self._opt_value("device") or self._opt_value("rhost")
        if port:
            client = self._build_uart_client(self.get_uart_connection_info())
            if client.connect():
                return client

        raise RuntimeError("No UART session and no serial port configured.")

    def open_uart(self) -> UartClient:
        return self.get_uart_client()

    def close_uart_client(self, session_id: str) -> None:
        framework = getattr(self, "framework", None)
        if not framework:
            return
        registry = getattr(framework, "_uart_session_clients", None) or {}
        client = registry.pop(session_id, None)
        if client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass
