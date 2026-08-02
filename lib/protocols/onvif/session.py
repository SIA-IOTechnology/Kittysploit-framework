#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ONVIF session helpers — inherit ``OnvifSessionMixin`` / ``OnvifClientMixin``."""

from __future__ import annotations

from typing import Any, Dict

from lib.protocols.ics.ics_session_mixin import IcsSessionMixin
from lib.protocols.onvif.client import OnvifClient


class OnvifSessionMixin(IcsSessionMixin):
    """Resolve ``OnvifClient`` from session registry / listener / module options."""

    def _onvif_opt(self, name: str, default=None):
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            attr = attr.value
        return attr if attr is not None else default

    def get_onvif_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": str(data.get("host") or data.get("rhost") or "").strip(),
                "port": int(data.get("port") or data.get("rport") or 80),
                "username": str(data.get("username") or self._onvif_opt("username") or ""),
                "password": str(data.get("password") or self._onvif_opt("password") or ""),
                "use_https": bool(
                    data.get("ssl")
                    if data.get("ssl") is not None
                    else data.get("use_https")
                    if data.get("use_https") is not None
                    else self._onvif_opt("ssl")
                    or False
                ),
                "timeout": float(data.get("timeout") or self._onvif_opt("timeout") or 8),
                "device_path": str(
                    data.get("device_path")
                    or self._onvif_opt("device_path")
                    or "/onvif/device_service"
                ),
            }
        return {
            "host": str(self._onvif_opt("rhost") or self._onvif_opt("target") or "").strip(),
            "port": int(self._onvif_opt("rport") or self._onvif_opt("port") or 80),
            "username": str(self._onvif_opt("username") or ""),
            "password": str(self._onvif_opt("password") or ""),
            "use_https": bool(self._onvif_opt("ssl") or self._onvif_opt("use_https") or False),
            "timeout": float(self._onvif_opt("timeout") or 8),
            "device_path": str(self._onvif_opt("device_path") or "/onvif/device_service"),
        }

    def _make_onvif_client(self, info: Dict[str, Any]) -> OnvifClient:
        return OnvifClient(
            str(info["host"]),
            int(info["port"]),
            str(info.get("username") or ""),
            str(info.get("password") or ""),
            use_https=bool(info.get("use_https")),
            timeout=float(info.get("timeout") or 8),
            device_path=str(info.get("device_path") or "/onvif/device_service"),
        )

    def get_onvif_client(self, *, discover: bool = False) -> OnvifClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, OnvifClient) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, OnvifClient)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_onvif_connection_info()
            if info.get("host"):
                client = self._make_onvif_client(info)
                if not client.connect():
                    raise RuntimeError(client.last_error or "ONVIF connect failed")
                self._ics_registry()[session_id] = client
                return client

        info = self.get_onvif_connection_info()
        host = str(info.get("host") or "").strip()
        if not host:
            raise RuntimeError("ONVIF session or rhost is required")
        client = self._make_onvif_client(info)
        if discover:
            if not client.connect():
                raise RuntimeError(client.last_error or "No ONVIF device service found")
        return client

    def open_onvif(self, *, discover: bool = True) -> OnvifClient:
        return self.get_onvif_client(discover=discover)


# Backward-compatible alias used by auxiliary camera modules
OnvifClientMixin = OnvifSessionMixin
