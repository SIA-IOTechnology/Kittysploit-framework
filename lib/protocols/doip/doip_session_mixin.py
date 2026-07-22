#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DoIP session helpers for post-exploitation modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from lib.protocols.doip.constants import (
    DOIP_ACTIVATION_DEFAULT,
    DOIP_DEFAULT_PORT,
    DOIP_TESTER_ADDRESS_DEFAULT,
)
from lib.protocols.doip.doip_client import DoIPClient


class DoIPSessionMixin:
    """Resolve live DoIPClient instances from framework session registries."""

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

    def _doip_registry(self):
        framework = getattr(self, "framework", None)
        if not framework:
            return {}
        registry = getattr(framework, "_doip_session_clients", None)
        if registry is None:
            framework._doip_session_clients = {}
            registry = framework._doip_session_clients
        return registry

    def _client_from_listener(self, session) -> Optional[DoIPClient]:
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
        return conn if isinstance(conn, DoIPClient) else None

    def get_doip_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": data.get("host", "") or getattr(session, "host", ""),
                "port": int(data.get("port") or getattr(session, "port", None) or DOIP_DEFAULT_PORT),
                "source_address": int(data.get("source_address") or DOIP_TESTER_ADDRESS_DEFAULT),
                "target_address": int(data.get("target_address") or 0),
                "activation_type": int(data.get("activation_type") or DOIP_ACTIVATION_DEFAULT),
                "timeout": float(data.get("timeout") or 5),
                "entity_address": data.get("entity_address"),
                "routing_active": bool(data.get("routing_active", False)),
            }
        host = self._opt_value("target") or self._opt_value("rhost")
        return {
            "host": str(host or ""),
            "port": int(self._opt_value("port") or self._opt_value("rport") or DOIP_DEFAULT_PORT),
            "source_address": int(self._opt_value("source_address") or DOIP_TESTER_ADDRESS_DEFAULT),
            "target_address": int(self._opt_value("target_address") or 0),
            "activation_type": int(self._opt_value("activation_type") or DOIP_ACTIVATION_DEFAULT),
            "timeout": float(self._opt_value("timeout") or 5),
            "entity_address": None,
            "routing_active": False,
        }

    def _build_doip_client(self, info: Dict[str, Any]) -> DoIPClient:
        return DoIPClient(
            str(info.get("host") or ""),
            int(info.get("port") or DOIP_DEFAULT_PORT),
            float(info.get("timeout") or 5),
            int(info.get("source_address") or DOIP_TESTER_ADDRESS_DEFAULT),
            int(info.get("target_address") or 0),
            int(info.get("activation_type") or DOIP_ACTIVATION_DEFAULT),
        )

    def get_doip_client(self) -> DoIPClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._doip_registry().get(session_id)
            if isinstance(registry_client, DoIPClient) and registry_client.connected:
                return registry_client

            listener_client = self._client_from_listener(session)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_doip_connection_info()
            if info.get("host"):
                client = self._build_doip_client(info)
                if client.connect():
                    self._doip_registry()[session_id] = client
                    return client

        host = self._opt_value("target") or self._opt_value("rhost")
        if host:
            client = self._build_doip_client(self.get_doip_connection_info())
            if client.connect():
                return client

        raise RuntimeError("No DoIP session and no target/rhost configured.")

    def open_doip(self) -> DoIPClient:
        return self.get_doip_client()

    def resolve_target_address(self, override: Optional[int] = None) -> int:
        if override is not None and int(override) > 0:
            return int(override) & 0xFFFF
        info = self.get_doip_connection_info()
        target = int(info.get("target_address") or 0)
        if target:
            return target & 0xFFFF
        entity = info.get("entity_address")
        if entity:
            return int(entity) & 0xFFFF
        client = None
        try:
            client = self.get_doip_client()
            if client.entity_address:
                return int(client.entity_address) & 0xFFFF
            if client.target_address:
                return int(client.target_address) & 0xFFFF
        except Exception:
            pass
        return 0

    def close_doip_client(self, session_id: str) -> None:
        framework = getattr(self, "framework", None)
        if not framework:
            return
        registry = getattr(framework, "_doip_session_clients", None) or {}
        client = registry.pop(session_id, None)
        if client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass
