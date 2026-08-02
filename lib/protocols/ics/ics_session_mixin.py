#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ICS session helpers for post-exploitation and shell modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from lib.protocols.ics.modbus_client import ModbusTCPClient
from lib.protocols.ics.s7_client import S7Client
from lib.protocols.ics.bacnet_client import BacnetClient
from lib.protocols.ics.dnp3_client import Dnp3Client
from lib.protocols.ics.iec104_client import Iec104Client
from lib.protocols.ics.iec61850_client import Iec61850Client, IEC61850_PORT


class IcsSessionMixin:
    """Resolve live S7/Modbus clients from framework session registries."""

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

    def _ics_registry(self):
        framework = getattr(self, "framework", None)
        if not framework:
            return {}
        registry = getattr(framework, "_ics_session_clients", None)
        if registry is None:
            framework._ics_session_clients = {}
            registry = framework._ics_session_clients
        return registry

    def _client_from_listener(self, session, expected_type: type):
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
        return conn if isinstance(conn, expected_type) else None

    def close_ics_client(self, session_id: str) -> None:
        framework = getattr(self, "framework", None)
        if not framework:
            return
        registry = getattr(framework, "_ics_session_clients", None) or {}
        client = registry.pop(session_id, None)
        if client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


class S7SessionMixin(IcsSessionMixin):
    """Retrieve S7Client instances from an active S7comm session."""

    def get_s7_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or 102),
                "rack": int(data.get("rack") or 0),
                "slot": int(data.get("slot") or 1),
                "password": str(data.get("password") or ""),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or 102),
            "rack": int(self._opt_value("rack") or 0),
            "slot": int(self._opt_value("slot") or 1),
            "password": str(self._opt_value("password") or ""),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def _build_s7_client(self, info: Dict[str, Any]) -> S7Client:
        return S7Client(
            str(info.get("host") or ""),
            int(info.get("port") or 102),
            float(info.get("timeout") or 5),
            int(info.get("rack") or 0),
            int(info.get("slot") or 1),
            str(info.get("password") or ""),
        )

    def get_s7_client(self) -> S7Client:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, S7Client) and registry_client.connected:
                return registry_client

            listener_client = self._client_from_listener(session, S7Client)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_s7_connection_info()
            if info.get("host"):
                client = self._build_s7_client(info)
                if client.connect():
                    return client

        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            client = self._build_s7_client(self.get_s7_connection_info())
            if client.connect():
                return client

        raise RuntimeError("No S7comm session and no target/rhost configured.")

    def open_s7(self) -> S7Client:
        return self.get_s7_client()


class ModbusSessionMixin(IcsSessionMixin):
    """Retrieve ModbusTCPClient instances from an active Modbus session."""

    def get_modbus_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or 502),
                "unit_id": int(data.get("unit_id") or 1),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or 502),
            "unit_id": int(self._opt_value("unit_id") or 1),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def _build_modbus_client(self, info: Dict[str, Any]) -> ModbusTCPClient:
        return ModbusTCPClient(
            str(info.get("host") or ""),
            int(info.get("port") or 502),
            float(info.get("timeout") or 5),
        )

    def get_modbus_client(self) -> ModbusTCPClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, ModbusTCPClient) and registry_client.connected:
                return registry_client

            listener_client = self._client_from_listener(session, ModbusTCPClient)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_modbus_connection_info()
            if info.get("host"):
                client = self._build_modbus_client(info)
                if client.connect():
                    return client

        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            client = self._build_modbus_client(self.get_modbus_connection_info())
            if client.connect():
                return client

        raise RuntimeError("No Modbus session and no target/rhost configured.")

    def open_modbus(self) -> ModbusTCPClient:
        return self.get_modbus_client()


class BacnetSessionMixin(IcsSessionMixin):
    """Retrieve BacnetClient instances from an active BACnet session."""

    def get_bacnet_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or 47808),
                "device_id": int(data.get("device_id") or 0),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or 47808),
            "device_id": int(self._opt_value("device_id") or 0),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def get_bacnet_client(self) -> BacnetClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, BacnetClient) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, BacnetClient)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_bacnet_connection_info()
            if info.get("host"):
                client = BacnetClient(
                    str(info["host"]),
                    int(info["port"]),
                    float(info["timeout"]),
                    int(info["device_id"]),
                )
                if client.connect():
                    self._ics_registry()[session_id] = client
                    return client
        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            info = self.get_bacnet_connection_info()
            client = BacnetClient(
                str(info["host"]),
                int(info["port"]),
                float(info["timeout"]),
                int(info["device_id"]),
            )
            if client.connect():
                return client
        raise RuntimeError("No BACnet session and no target/rhost configured.")

    def open_bacnet(self) -> BacnetClient:
        return self.get_bacnet_client()


class Dnp3SessionMixin(IcsSessionMixin):
    """Retrieve Dnp3Client instances from an active DNP3 session."""

    def get_dnp3_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or 20000),
                "src": int(data.get("src") or 1024),
                "dest": int(data.get("dest") or 1),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or 20000),
            "src": int(self._opt_value("src") or 1024),
            "dest": int(self._opt_value("dest") or self._opt_value("dnp3_dest") or 1),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def get_dnp3_client(self) -> Dnp3Client:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, Dnp3Client) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, Dnp3Client)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_dnp3_connection_info()
            if info.get("host"):
                client = Dnp3Client(
                    str(info["host"]),
                    int(info["port"]),
                    float(info["timeout"]),
                    int(info["src"]),
                    int(info["dest"]),
                )
                if client.connect():
                    self._ics_registry()[session_id] = client
                    return client
        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            info = self.get_dnp3_connection_info()
            client = Dnp3Client(
                str(info["host"]),
                int(info["port"]),
                float(info["timeout"]),
                int(info["src"]),
                int(info["dest"]),
            )
            if client.connect():
                return client
        raise RuntimeError("No DNP3 session and no target/rhost configured.")

    def open_dnp3(self) -> Dnp3Client:
        return self.get_dnp3_client()


class Iec104SessionMixin(IcsSessionMixin):
    """Retrieve Iec104Client instances from an active IEC 104 session."""

    def get_iec104_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or 2404),
                "common_address": int(data.get("common_address") or 1),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or 2404),
            "common_address": int(self._opt_value("common_address") or 1),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def get_iec104_client(self) -> Iec104Client:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, Iec104Client) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, Iec104Client)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_iec104_connection_info()
            if info.get("host"):
                client = Iec104Client(
                    str(info["host"]),
                    int(info["port"]),
                    float(info["timeout"]),
                    int(info["common_address"]),
                )
                if client.connect():
                    self._ics_registry()[session_id] = client
                    return client
        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            info = self.get_iec104_connection_info()
            client = Iec104Client(
                str(info["host"]),
                int(info["port"]),
                float(info["timeout"]),
                int(info["common_address"]),
            )
            if client.connect():
                return client
        raise RuntimeError("No IEC 104 session and no target/rhost configured.")

    def open_iec104(self) -> Iec104Client:
        return self.get_iec104_client()


class Iec61850SessionMixin(IcsSessionMixin):
    """Retrieve Iec61850Client instances from an active IEC 61850 MMS session."""

    def get_iec61850_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", ""),
                "port": int(data.get("port") or IEC61850_PORT),
                "timeout": float(data.get("timeout") or 5),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or IEC61850_PORT),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def get_iec61850_client(self) -> Iec61850Client:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, Iec61850Client) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, Iec61850Client)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_iec61850_connection_info()
            if info.get("host"):
                client = Iec61850Client(str(info["host"]), int(info["port"]), float(info["timeout"]))
                if client.connect():
                    self._ics_registry()[session_id] = client
                    return client
        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            info = self.get_iec61850_connection_info()
            client = Iec61850Client(str(info["host"]), int(info["port"]), float(info["timeout"]))
            if client.connect():
                return client
        raise RuntimeError("No IEC 61850 session and no target/rhost configured.")

    def open_iec61850(self) -> Iec61850Client:
        return self.get_iec61850_client()
